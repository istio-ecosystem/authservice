.PHONY: all docs compose docker docker-from-scratch docker-compile-env build run test coverage format clean dist

# Include versions of tools we build or fetch on-demand.
include Tools.mk

# This should be overridden by current tag (with stripped "v") when running `make dist` on CI.
VERSION ?= $(shell git describe --tags --long --dirty --always)

# This will be overridden with available matrix modes (e.g. default, clang, clang-fips).
MODE ?= default

BAZEL_FLAGS ?=
REGISTRY    ?= ghcr.io/istio-ecosystem/authservice
IMAGE       ?= $(REGISTRY)/authservice:$(VERSION)

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
main_target     := //src/main:$(binary_name)

# Always use amd64 for bazelisk for build and test rules below, since we don't support for macOS
# arm64 (with --host_javabase=@local_jdk//:jdk) yet (especially the protoc-gen-validate project:
# "no matching toolchains found for types @io_bazel_rules_go//go:toolchain").
bazel        := GOARCH=amd64 $(go) run $(bazelisk@v) --output_user_root=$(bazel_cache_dir)
buildifier   := $(go_tools_dir)/buildifier
envsubst     := $(go_tools_dir)/envsubst
protodoc     := $(go_tools_dir)/protodoc
clang        := $(prepackaged_tools_dir)/bin/clang
llvm-config  := $(prepackaged_tools_dir)/bin/llvm-config
clang-format := $(prepackaged_tools_dir)/bin/clang-format

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

build: ## Build the main binary. To build the debug binary, run `make build-dbg`
	$(call bazel-build)

# Build with a specified compilation mode, e.g. 'build-dbg'
build-%:
	$(call bazel-build,--compilation_mode $(subst build-,,$@))

# Build the tarball of the current binary.
dist: dist/$(binary_name)_$(goos)_amd64_$(MODE)_$(VERSION).tar.gz

# Since we don't do cross-compilation yet (probably we can do it later via `zig cc`), we can only
# build artifact for the current `os` and `mode` pair (e.g. {os: 'macOS', mode: 'clang-fips'}).
dist/$(binary_name)_$(goos)_amd64_$(MODE)_$(VERSION).tar.gz: $(stripped_binary) ## Create build artifacts
	@$(eval DIST_DIR := $(shell mktemp -d))
	@cp -f LICENSE $(DIST_DIR)
	@mkdir -p dist $(DIST_DIR)/bin
	@cp -f $(stripped_binary) $(DIST_DIR)/bin/$(binary_name)
	@tar -C $(DIST_DIR) -cpzf $@ .

docs: $(protodoc) ## Build docs
	@$(protodoc) --directories=config=message --title="Configuration Options" --output="docs/README.md"
	@grep -v '(validate.required)' docs/README.md > /tmp/README.md && mv /tmp/README.md docs/README.md

image: $(stripped_binary) ## Build the docker image
	@mkdir -p build_release
	@cp -f $(stripped_binary) build_release/$(binary_name)
	@docker build . -t $(IMAGE)

push: image ## Push docker image to registry
	@docker push $(IMAGE)

$(current_binary):
	bazel build $(BAZEL_FLAGS) //src/main:auth_server

ifeq ($(goos),linux)
# Some -copt="-Wno-error=" is needed to suppress the error for gcc when compiling abseil and protobuf.
gcc_w_no_error := --copt="-Wno-error=uninitialized" --copt="-Wno-error=deprecated-declarations" --copt="-Wno-error=maybe-uninitialized"
endif

# Stripped binary is compiled using "--compilation_mode opt". "opt" means build with optimization
# enabled and with assert() calls disabled (-O2 -DNDEBUG). Debugging information will not be
# generated in opt mode unless you also pass --copt -g.
#
# Reference: https://docs.bazel.build/versions/main/user-manual.html#flag--compilation_mode.
$(stripped_binary): $(main_cc_sources) $(bazel_files)
ifeq (,$(wildcard clang.bazelrc)) # if no clang.bazelrc exists, we compile using default compiler.
	$(call bazel-build,$(gcc_w_no_error) --compilation_mode opt,.stripped)
else
	$(call bazel-build,--compilation_mode opt,.stripped)
endif

run: ## Build the main target
	$(bazel) run $(BAZEL_FLAGS) $(main_target)

TEST_FLAGS ?= --strategy=TestRunner=standalone --test_output=all
test: ## Run tests
	$(call bazel-test)

# This only executes tests whose name matches a filter
# Usage examples:
#   make testfilter FILTER=*RetrieveToken*
#   make testfilter FILTER=OidcFilterTest.*
FILTER ?= *RetrieveToken*
testfilter: ## Run tests with a specified FILTER
	$(call bazel-test,--test_arg='--gtest_filter=$(FILTER)')

check: ## Run check script
	@$(MAKE) format
	@if [ ! -z "`git status -s`" ]; then \
		echo "The following differences will fail CI until committed:"; \
		git diff --exit-code; \
	fi

coverage: ## Run bazel coverage
	$(bazel) coverage $(BAZEL_FLAGS) --instrumentation_filter=//src/ //...

# We "manually" list down all bazel files using wildcard above since: https://github.com/bazelbuild/buildtools/issues/801
# and we need to ignore all bazel files in .cache directory.
format: $(clang-format) $(buildifier) ## Format source files
	@$(buildifier) --lint=fix $(bazel_files)
	@$(clang-format) -i $(main_cc_sources) $(testable_cc_sources) $(protos)

clean: ## Run bazel clean
	$(bazel) clean --expunge --async

# This generates dependencies graph of the main target.
dep-graph.dot:
	$(bazel) query $(BAZEL_FLAGS) --nohost_deps --noimplicit_deps "deps($(main_target))" --output graph > $@

# This renders configuration template to build main binary using clang as the compiler.
clang.bazelrc: bazel/clang.bazelrc.tmpl $(llvm-config) $(envsubst)
	@$(envsubst) < $< > $@

# This builds the stripped binary, and checks if the binary is statically linked.
requirestatic: $(stripped_binary)
	@test/exe/require_static.sh $(stripped_binary)

# Catch all rules for Go-based tools.
$(go_tools_dir)/%:
	@printf "$(ansi_format_dark)" tools "installing $($(notdir $@)@v)..."
	@GOBIN=$(go_tools_dir) go install $($(notdir $@)@v)
	@printf "$(ansi_format_bright)" tools "ok"

# Run bazel build to build the main target.
define bazel-build
	$(call bazel-dirs)
	$(bazel) build $(BAZEL_FLAGS) $1 $(main_target)$2
endef

# Run bazel test.
define bazel-test
	$(call bazel-dirs)
	$(bazel) test $(BAZEL_FLAGS) $(TEST_FLAGS) //test/... $1
endef

# This makes sure the required directories are created.
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
