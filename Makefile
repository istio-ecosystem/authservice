.PHONY: all docs compose docker docker-from-scratch docker-compile-env build run test coverage format clean

# Include versions of tools we build or fetch on-demand.
include Tools.mk

.DEFAULT_GOAL:=all
SRCS=$(shell find . -name '*.cc')
HDRS=$(shell find . -name '*.h')
TARGET:=//src/main:auth_server
BAZEL_FLAGS:=$(BAZEL_FLAGS)
IMAGE?=authservice:$(USER)

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
bazel := GOARCH=amd64 go run $(bazelisk@v)

build:
	$(bazel) build $(BAZEL_FLAGS) //src/...

run:
	$(bazel) run $(BAZEL_FLAGS) $(TARGET)

TEST_FLAGS ?= --strategy=TestRunner=standalone --test_output=all
test:
	$(bazel) test $(BAZEL_FLAGS) $(TEST_FLAGS) //test/...

# Only run tests whose name matches a filter
# Usage examples:
#   make filter-test FILTER=*RetrieveToken*
#   make filter-test FILTER=OidcFilterTest.*
filter-test:
	$(bazel) test $(BAZEL_FLAGS) $(TEST_FLAGS) //test/... --test_arg='--gtest_filter=$(FILTER)'

coverage:
	$(bazel) coverage $(BAZEL_FLAGS) --instrumentation_filter=//src/ //...

buildifier@v := github.com/bazelbuild/buildtools/buildifier@4.2.5
format:
	@go run $(buildifier@v) --lint=fix -r .
	clang-format -i $(SRCS) $(HDRS)

clean:
	$(bazel) clean --expunge --async

dep-graph.dot:
	$(bazel) query $(BAZEL_FLAGS) --nohost_deps --noimplicit_deps "deps($(TARGET))" --output graph > $@
