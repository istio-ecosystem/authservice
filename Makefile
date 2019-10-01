.PHONY: all docker build run test coverage format clean
.DEFAULT_GOAL:=all
SRCS=$(shell find . -name '*.cc')
HDRS=$(shell find . -name '*.h')
TARGET:=//src/main:auth-server
BAZEL_FLAGS:=--incompatible_depset_is_not_iterable=false --verbose_failures

all: build test

docker:
	docker build -f build/Dockerfile.builder -t authservice:$(USER) .

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
