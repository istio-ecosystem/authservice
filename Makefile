.PHONY: all docs compose docker docker-from-scratch docker-compile-env build run test coverage format clean dist

# Include versions of tools we build or fetch on-demand.
include Tools.mk

.DEFAULT_GOAL := all
TARGET        := //src/main:auth_server
BAZEL_FLAGS   ?=
IMAGE         ?= authservice:$(USER)

# Root dir returns absolute path of current directory. It has a trailing "/".
root_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Local cache directory.
CACHE_DIR ?= $(root_dir).cache

# Go tools directory holds the binaries of Go-based tools.
go_tools_dir := $(CACHE_DIR)/tools/go

# Prepackaged tools may have more than precompiled binaries, e.g. for clang,
prepackaged_tools_dir := $(CACHE_DIR)/tools/prepackaged
bazel_cache_dir       := $(CACHE_DIR)/bazel
clang_version         := $(subst github.com/llvm/llvm-project/llvmorg/clang+llvm@,,$(clang@v))

# Currently we resolve it using which. But more sophisticated approach is to use infer GOROOT.
go     := $(shell which go)
goarch := $(shell $(go) env GOARCH)
goos   := $(shell $(go) env GOOS)

export PATH            := $(prepackaged_tools_dir)/bin:$(PATH)
export LLVM_PREFIX     := $(prepackaged_tools_dir)
export RT_LIBRARY_PATH := $(prepackaged_tools_dir)/lib/clang/$(clang_version)/lib/$(goos)
export BAZELISK_HOME   := $(CACHE_DIR)/tools/bazelisk
export CGO_ENABLED     := 0

# Make 3.81 doesn't support '**' globbing: Set explicitly instead of recursion.
main_cc_sources     := $(wildcard src/*/*.cc src/*/*.h src/*/*/*.cc src/*/*/*.h)
testable_cc_sources := $(wildcard test/*/*.cc test/*/*.h test/*/*/*.cc test/*/*/*.h)
bazel_files         := $(wildcard WORKSPACE BUILD.bazel bazel/*.bzl bazel/*.BUILD src/*/BUILD src/*/*/BUILD src/*/*/*/BUILD test/*/BUILD test/*/*/BUILD test/*/*/*/BUILD)

binary_name     := auth_server
current_binary  := bazel-bin/src/main/$(binary_name)
stripped_binary := $(current_binary).stripped

all: build test docs

docs:
	# If the protodoc command is not found, you can install it with: go get -v -u go.etcd.io/protodoc
	protodoc --directories=config=message --title="Configuration Options" --output="docs/README.md"
	grep -v '(validate.required)' docs/README.md > /tmp/README.md && mv /tmp/README.md docs/README.md

compose:
	openssl req -out run/envoy/tls.crt -new -keyout run/envoy/tls.pem -newkey rsa:2048 -batch -nodes -verbose -x509 -subj "/CN=localhost" -days 365
	chmod a+rw run/envoy/tls.crt run/envoy/tls.pem
	docker-compose up --build

docker: build
	rm -rf build_release && mkdir -p build_release && cp -r bazel-bin/ build_release && docker build . -f build/Dockerfile.runner -t $(IMAGE)

docker.push: docker
  docker push $(IMAGE)

docker-from-scratch:
	docker build -f build/Dockerfile.builder -t authservice:$(USER) .

docker-compile-env:
	docker build -f build/Dockerfile.interactive-compile-environment -t authservice-build-env:$(USER) .

$(current_binary):
# Note: add --compilation_mode=dbg to the end of the next line to build a debug executable with `make docker-from-scratch`
	bazel build $(BAZEL_FLAGS) //src/main:auth_server

# Always use amd64 for bazelisk for build and test rules below, since we don't support for macOS
# arm64 (with --host_javabase=@local_jdk//:jdk) yet (especially the protoc-gen-validate project:
# "no matching toolchains found for types @io_bazel_rules_go//go:toolchain").
bazel        := GOARCH=amd64 $(go) run $(bazelisk@v) --output_user_root=$(bazel_cache_dir)
buildifier   := $(go_tools_dir)/buildifier
envsubst     := $(go_tools_dir)/envsubst
clang        := $(prepackaged_tools_dir)/bin/clang
llvm-config  := $(prepackaged_tools_dir)/bin/llvm-config
clang-format := $(prepackaged_tools_dir)/bin/clang-format

build: ## Build the main binary
	$(call bazel-build)

# This should be overridden by current tag (with stripped "v") when running `make dist` on CI.
VERSION ?= dev
# This will be overridden with available matrix modes (e.g. default, clang, clang-fips).
MODE ?= default

dist: dist/$(binary_name)_$(goos)_amd64_$(MODE)_$(VERSION).tar.gz

# Since we don't do cross-compilation (probably later via `zig cc`) we can only build artifact for
# the current `os` and `mode` pair (e.g. {os: 'macOS', mode: 'clang-fips'}).
dist/$(binary_name)_$(goos)_amd64_$(MODE)_$(VERSION).tar.gz: $(stripped_binary) ## Create build artifacts
	@$(eval DIST_DIR := $(shell mktemp -d))
	@cp -f LICENSE $(DIST_DIR)
	@mkdir -p dist $(DIST_DIR)/bin
	@cp -f $(stripped_binary) $(DIST_DIR)/bin/$(binary_name)
	@tar -C $(DIST_DIR) -cpzf $@ .

# Stripped binary is compiled using "--compilation_mode opt". "opt" means build with optimization
# enabled and with assert() calls disabled (-O2 -DNDEBUG). Debugging information will not be
# generated in opt mode unless you also pass --copt -g.
#
# Reference: https://docs.bazel.build/versions/main/user-manual.html#flag--compilation_mode.
$(stripped_binary): $(main_cc_sources) $(bazel_files)
	$(call bazel-build,--compilation_mode opt,.stripped)

run: ## Build the main target
	$(bazel) run $(BAZEL_FLAGS) $(TARGET)

TEST_FLAGS ?= --strategy=TestRunner=standalone --test_output=all
test: ## Run tests
	$(call bazel-test)

check: ## Run check script
	@$(MAKE) format
	@if [ ! -z "`git status -s`" ]; then \
		echo "The following differences will fail CI until committed:"; \
		git diff --exit-code; \
	fi

# Only run tests whose name matches a filter
# Usage examples:
#   make filter-test FILTER=*RetrieveToken*
#   make filter-test FILTER=OidcFilterTest.*
FILTER ?= *RetrieveToken*
filter-test:
	$(call bazel-test,--test_arg='--gtest_filter=$(FILTER)')

coverage:
	$(bazel) coverage $(BAZEL_FLAGS) --instrumentation_filter=//src/ //...

# We "manually" list down all bazel files using wildcard above since: https://github.com/bazelbuild/buildtools/issues/801
# and we need to ignore all bazel files in .cache directory.
format: $(clang-format) $(buildifier) ## Format source files
	@$(buildifier) --lint=fix $(bazel_files)
	@$(clang-format) -i $(main_cc_sources) $(testable_cc_sources) $(protos)

clean: ## Run bazel clean
	$(bazel) clean --expunge --async

dep-graph.dot:
	$(bazel) query $(BAZEL_FLAGS) --nohost_deps --noimplicit_deps "deps($(TARGET))" --output graph > $@

clang.bazelrc: bazel/clang.bazelrc.tmpl $(llvm-config) $(envsubst)
	@$(envsubst) < $< > $@

# Catch all rules for Go-based tools.
$(go_tools_dir)/%:
	@printf "$(ansi_format_dark)" tools "installing $($(notdir $@)@v)..."
	@GOBIN=$(go_tools_dir) go install $($(notdir $@)@v)
	@printf "$(ansi_format_bright)" tools "ok"

define bazel-build
	$(call bazel-dirs)
	$(bazel) build $(BAZEL_FLAGS) $1 $(TARGET)$2
endef

define bazel-test
	$(call bazel-dirs)
	$(bazel) test $(BAZEL_FLAGS) $(TEST_FLAGS) //test/... $1
endef

define bazel-dirs
	@mkdir -p $(BAZELISK_HOME) $(bazel_cache_dir)
endef

# Install clang from https://github.com/llvm/llvm-project. We don't support win32 yet as this script
# will fail.
clang-os                          = $(if $(findstring $(goos),darwin),apple-darwin,linux-gnu-ubuntu-20.04)
clang-download-archive-url-prefix = https://$(subst llvmorg/clang+llvm@,releases/download/llvmorg-,$($(notdir $1)@v))
$(clang):
	@mkdir -p $(dir $@)
	@curl -SL $(call clang-download-archive-url-prefix,$@)/clang+llvm-$(clang_version)-x86_64-$(call clang-os).tar.xz | \
		tar xJf - -C $(prepackaged_tools_dir) --strip-components 1
$(llvm-config): $(clang)

# Install clang-format from https://github.com/angular/clang-format. We don't support win32 yet as
# this script will fail.
clang-format-download-archive-url = https://$(subst @,/archive/refs/tags/,$($(notdir $1)@v)).tar.gz
clang-format-dir                  = $(subst github.com/angular/clang-format@v,clang-format-,$($(notdir $1)@v))
$(clang-format):
	@mkdir -p $(dir $@)
	@curl -SL $(call clang-format-download-archive-url,$@) | tar xzf - -C $(prepackaged_tools_dir)/bin \
		--strip 3 $(call clang-format-dir,$@)/bin/$(goos)_x64

# This is adopted from https://github.com/tetratelabs/func-e/blob/3df66c9593e827d67b330b7355d577f91cdcb722/Makefile#L60-L76.
# ANSI escape codes. f_ means foreground, b_ background.
# See https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_(Select_Graphic_Rendition)_parameters.
f_black            := $(shell printf "\33[30m")
b_black            := $(shell printf "\33[40m")
f_white            := $(shell printf "\33[97m")
f_gray             := $(shell printf "\33[37m")
f_dark_gray        := $(shell printf "\33[90m")
f_blue             := $(shell printf "\33[34m")
b_blue             := $(shell printf "\33[44m")
ansi_reset         := $(shell printf "\33[0m")
ansi_authservice   := $(b_black)$(f_black)$(b_blue)authservice$(ansi_reset)
ansi_format_dark   := $(f_gray)$(f_blue)%-10s$(ansi_reset) $(f_dark_gray)%s$(ansi_reset)\n
ansi_format_bright := $(f_white)$(f_blue)%-10s$(ansi_reset) $(f_black)$(b_blue)%s$(ansi_reset)\n

# This formats help statements in ANSI colors. To hide a target from help, don't comment it with a trailing '##'.
help: ## Describe how to use each target
	@printf "$(ansi_authservice)$(f_white)\n"
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "$(ansi_format_dark)", $$1, $$2}' $(MAKEFILE_LIST)
