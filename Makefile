.PHONY: all docs compose docker docker-from-scratch docker-compile-env build run test coverage format clean

# Include versions of tools we build or fetch on-demand.
include Tools.mk

.DEFAULT_GOAL:=all
SRCS=$(shell find . -name '*.cc')
HDRS=$(shell find . -name '*.h')
TARGET:=//src/main:auth_server
BAZEL_FLAGS:=$(BAZEL_FLAGS)
IMAGE?=authservice:$(USER)

# Root dir returns absolute path of current directory. It has a trailing "/".
root_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Local cache directory.
CACHE_DIR ?= $(root_dir).cache

# Prepackaged tools may have more than precompiled binaries, e.g. for clang,
prepackaged_tools_dir := $(CACHE_DIR)/tools/prepackaged
clang_version         := $(subst github.com/llvm/llvm-project/llvmorg/clang+llvm@,,$(clang@v))

# Currently we resolve it using which. But more sophisticated approach is to use infer GOROOT.
go     := $(shell which go)
goarch := $(shell $(go) env GOARCH)
goos   := $(shell $(go) env GOOS)

export PATH            := $(prepackaged_tools_dir)/bin:$(PATH)
export LLVM_PREFIX     := $(prepackaged_tools_dir)
export RT_LIBRARY_PATH := $(prepackaged_tools_dir)/lib/clang/$(clang_version)/lib/$(goos)
export CGO_ENABLED     := 0

# Make 3.81 doesn't support '**' globbing: Set explicitly instead of recursion.
main_cc_sources     := $(wildcard src/*/*.cc src/*/*.h src/*/*/*.cc src/*/*/*.h)
testable_cc_sources := $(wildcard test/*/*.cc test/*/*.h test/*/*/*.cc test/*/*/*.h)

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

bazel-bin/src/main/auth_server:
    # Note: add --compilation_mode=dbg to the end of the next line to build a debug executable with `make docker-from-scratch`
	bazel build $(BAZEL_FLAGS) //src/main:auth_server

# Always use amd64 for bazelisk for build and test rules below, since we don't support for macOS
# arm64 (with --host_javabase=@local_jdk//:jdk) yet (especially the protoc-gen-validate project:
# "no matching toolchains found for types @io_bazel_rules_go//go:toolchain").
bazel        := GOARCH=amd64 $(go) run $(bazelisk@v)
clang        := $(prepackaged_tools_dir)/bin/clang
llvm-config  := $(prepackaged_tools_dir)/bin/llvm-config
clang-format := $(prepackaged_tools_dir)/bin/clang-format

build:
	$(bazel) build $(BAZEL_FLAGS) //src/...

run:
	$(bazel) run $(BAZEL_FLAGS) $(TARGET)

TEST_FLAGS ?= --strategy=TestRunner=standalone --test_output=all
test:
	$(bazel) test $(BAZEL_FLAGS) $(TEST_FLAGS) //test/...

check:
	@$(MAKE) format
	@if [ ! -z "`git status -s`" ]; then \
		echo "The following differences will fail CI until committed:"; \
		git diff --exit-code; \
	fi

# Only run tests whose name matches a filter
# Usage examples:
#   make filter-test FILTER=*RetrieveToken*
#   make filter-test FILTER=OidcFilterTest.*
filter-test:
	$(bazel) test $(BAZEL_FLAGS) $(TEST_FLAGS) //test/... --test_arg='--gtest_filter=$(FILTER)'

coverage:
	$(bazel) coverage $(BAZEL_FLAGS) --instrumentation_filter=//src/ //...

format:
	@go run $(buildifier@v) --lint=fix -r .
	@$(clang-format) -i $(main_cc_sources) $(testable_cc_sources) $(protos)

clean:
	$(bazel) clean --expunge --async

dep-graph.dot:
	$(bazel) query $(BAZEL_FLAGS) --nohost_deps --noimplicit_deps "deps($(TARGET))" --output graph > $@

clang.bazelrc: bazel/clang.bazelrc.tmpl $(llvm-config)
	@$(go) run $(envsubst@v) < $< > $@

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
