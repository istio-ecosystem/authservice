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
NAME      ?= authservice

-include $(ROOT)/.makerc  # Pick up any local overrides.

GOLANGCI_LINT ?= github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
GOSIMPORTS    ?= github.com/rinchsan/gosimports/cmd/gosimports@v0.3.8
SWEYES        ?= github.com/apache/skywalking-eyes/cmd/license-eye@v0.6.0
KIND          ?= sigs.k8s.io/kind@v0.18.0
ENVTEST       ?= sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

TARGETS      ?= linux-amd64 linux-arm64 #darwin-amd64 darwin-arm64
FIPS_TARGETS := $(filter linux-%,$(TARGETS))

# DOCKER_HUB is exported so that it can be referenced in e2e docker compose files
export DOCKER_HUB     ?= $(GO_MODULE:github.com/%=ghcr.io/%)
DOCKER_TARGETS        ?= linux-amd64 linux-arm64
DOCKER_BUILDER_NAME   ?= $(NAME)-builder

REVISION := $(shell git rev-parse HEAD)
ifneq ($(strip $(VERSION)),)
# Remove the suffix as we want N.N.N instead of vN.N.N
DOCKER_TAG ?= $(strip $(VERSION:v%=%))
else
DOCKER_TAG ?= $(REVISION)
endif

# Docker metadata
DOCKER_METADATA := \
	org.opencontainers.image.title=$(NAME) \
	org.opencontainers.image.description="Move OIDC token acquisition out of your app code and into the Istio mesh" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.source=https://$(GO_MODULE) \
	org.opencontainers.image.version=$(DOCKER_TAG) \
	org.opencontainers.image.revision=$(REVISION)

# In non-Linux systems, use Docker to build FIPS-compliant binaries.
OS := $(shell uname)
ifeq ($(OS),Darwin)
BUILD_FIPS_IN_DOCKER ?= true
endif

export ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
export ARCH := amd64
endif
