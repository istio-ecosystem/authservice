# Copyright 2024 Tetrate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BUF ?= github.com/bufbuild/buf/cmd/buf@v1.17.0

default: build

PROTO_SOURCES := $(shell find . -name '*.proto')

.PHONY: build
build: $(PROTO_SOURCES) ## Generate the Go code from the protobuf definitions
	@echo "Generating Go code from protobuf definitions"
	@go run $(BUF) mod update
	@go run $(BUF) build
	@go run $(BUF) generate
	@go mod tidy

.PHONY: lint
lint:  ## Lint the protobuf definitions
	@echo "Linting protobuf definitions"
	@go run $(BUF) lint

.PHONY: clean
clean:  ## Clean all generated code
	@echo "Cleaning generated code"
	@rm -rf gen
