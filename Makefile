.PHONY: all docs compose docker docker-from-scratch docker-compile-env build run test coverage format clean
.DEFAULT_GOAL:=all
SRCS=$(shell find . -name '*.cc')
HDRS=$(shell find . -name '*.h')
TARGET:=//src/main:auth_server
BAZEL_FLAGS:=--incompatible_depset_is_not_iterable=false --verbose_failures

all: build test docs

docs:
	# If the protodoc command is not found, you can install it with: go get -v -u go.etcd.io/protodoc
	protodoc --directories=config=message --title="Configuration Options" --output="docs/README.md"
	grep -v '(validate.required)' docs/README.md > /tmp/README.md && mv /tmp/README.md docs/README.md

compose:
	openssl req -out run/envoy/tls.crt -new -keyout run/envoy/tls.pem -newkey rsa:2048 -batch -nodes -verbose -x509 -subj "/CN=localhost" -days 365
	docker-compose up --build

docker: build
	rm -rf build_release && mkdir -p build_release && cp -r bazel-bin/ build_release && docker build -f build/Dockerfile.runner -t authservice:$(USER) .

docker-from-scratch:
	docker build -f build/Dockerfile.builder -t authservice:$(USER) .

docker-compile-env:
	docker build -f build/Dockerfile.interactive-compile-environment -t authservice-build-env:$(USER) .

bazel-bin/src/main/auth_server:
    # Note: add --compilation_mode=dbg to the end of the next line to build a debug executable with `make docker-from-scratch`
	bazel build $(BAZEL_FLAGS) //src/main:auth_server

build:
	bazel build $(BAZEL_FLAGS) //src/...

run:
	bazel run $(BAZEL_FLAGS) $(TARGET)

test:
	bazel test $(BAZEL_FLAGS) --strategy=TestRunner=standalone --test_output=all --cache_test_results=no //test/...

# Only run tests whose name matches a filter
# Usage examples:
#   make filter-test FILTER=*RetrieveToken*
#   make filter-test FILTER=OidcFilterTest.*
filter-test:
	bazel test $(BAZEL_FLAGS) --strategy=TestRunner=standalone --test_output=all --cache_test_results=no //test/... --test_arg='--gtest_filter=$(FILTER)'

coverage:
	bazel coverage $(BAZEL_FLAGS) --instrumentation_filter=//src/ //...

format:
	clang-format -i -style=Google -sort-includes $(SRCS) $(HDRS)

clean:
	bazel clean --expunge --async

dep-graph.dot:
	bazel query $(BAZEL_FLAGS) --nohost_deps --noimplicit_deps "deps($(TARGET))" --output graph > $@
