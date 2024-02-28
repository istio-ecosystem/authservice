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

ROOT      := $(shell git rev-parse --show-toplevel)
GO_MODULE := $(shell sed -ne 's/^module //gp' $(ROOT)/go.mod)

-include $(ROOT)/.makerc  # Pick up any local overrides.

GOLANGCI_LINT ?= github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2
GOSIMPORTS    ?= github.com/rinchsan/gosimports/cmd/gosimports@v0.3.8
LICENSER      ?= github.com/liamawhite/licenser@v0.6.1-0.20210729145742-be6c77bf6a1f
KIND          ?= sigs.k8s.io/kind@v0.18.0
ENVTEST    ?= sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

NAME    ?= authservice
TARGETS ?= linux-amd64 linux-arm64 #darwin-amd64 darwin-arm64

DOCKER_HUB            ?= gcr.io/tetrate-internal-containers
DOCKER_TAG            ?= $(shell git rev-parse HEAD)
DOCKER_TARGETS        ?= linux-amd64 linux-arm64
DOCKER_BUILDER_NAME   ?= $(NAME)-builder

export ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
export ARCH := amd64
endif
