.PHONY: all compose docker docker-from-scratch docker-compile-env build run test coverage format clean
.DEFAULT_GOAL:=all
SRCS=$(shell find . -name '*.cc')
HDRS=$(shell find . -name '*.h')
TARGET:=//src/main:auth-server
BAZEL_FLAGS:=--incompatible_depset_is_not_iterable=false --verbose_failures

all: build test

compose: docker
	openssl req -out run/envoy/tls.crt -new -keyout run/envoy/tls.pem -newkey rsa:2048 -batch -nodes -verbose -x509 -subj "/CN=localhost" -days 365
	docker-compose up

docker:
	rm -rf build_release && mkdir -p build_release && cp -r bazel-bin/ build_release && docker build -f build/Dockerfile.builder -t authservice:$(USER) .

docker-from-scratch:
	docker build -f build/Dockerfile.builder -t authservice:$(USER) .

docker-compile-env:
	docker build -f build/Dockerfile.interactive-compile-environment -t authservice-build-env:$(USER) .

bazel-bin/src/main/auth-server:
	bazel build $(BAZEL_FLAGS) //src/main:auth-server

build:
	bazel build $(BAZEL_FLAGS) //src/...

run:
	bazel run $(TARGET)

test:
	bazel test $(BAZEL_FLAGS) --strategy=TestRunner=standalone --test_output=all //test/...

coverage:
	bazel coverage --instrumentation_filter=//src/ //...

format:
	clang-format -i -style=Google -sort-includes $(SRCS) $(HDRS)

clean:
	bazel clean --expunge

dep-graph.dot:
	bazel query --nohost_deps --noimplicit_deps "deps($(TARGET))" --output graph > $@
