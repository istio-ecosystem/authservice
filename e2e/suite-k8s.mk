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

# This file contains the common e2e targets and variables for e2e suites that use
# Kubernetes to spin up the environment.
# When adding a suite, create a new directory under e2e/ and add a Makefile that
# includes this file.

ROOT := $(shell git rev-parse --show-toplevel)

include $(ROOT)/env.mk

E2E_TEST_OPTS    ?= -count=1
E2E_CLUSTER_NAME ?= authservice
E2E_KIND_CONFIG  := cluster/kind-config.yaml
E2E_KUBECONFIG   := cluster/kubeconfig
E2E_IMAGE		 ?= $(DOCKER_HUB)/$(NAME):latest-$(ARCH)


.PHONY: e2e
e2e: e2e-pre
	@$(MAKE) e2e-test e2e-post

.PHONY: e2e-test
e2e-test:
	@go test $(E2E_TEST_OPTS) ./... || ( $(MAKE) e2e-post-error; exit 1 )

# Creates the kind cluster and generates the kubeconfig. If the kubeconfig already exists, from
# previous test runs, the kind cluster is not recreated to allow repeated runs of the e2e tests
# against the same environment
e2e-pre:: $(E2E_KUBECONFIG)
	@$(MAKE) kind-load

.PHONY: e2e-post
e2e-post::  ## Destroy the kind cluster and the generated kubeconfig file
ifeq ($(E2E_PRESERVE_LOGS),true)
	@$(MAKE) capture-logs
endif
	@go run $(KIND) delete cluster -n $(E2E_CLUSTER_NAME)
	@rm -f $(E2E_KUBECONFIG)

.PHONY: e2e-post-error
e2e-post-error: capture-logs

.PHONY: capture-logs
capture-logs:
	@kind export logs --name $(E2E_CLUSTER_NAME) ./logs

# If the kubeconfig file does not exist, create a new cluster and export the kubeconfig file to the
# configured file
$(E2E_KUBECONFIG): $(E2E_KIND_CONFIG)
	@go run $(KIND) create cluster -n $(E2E_CLUSTER_NAME) --kubeconfig $(@) --config $(E2E_KIND_CONFIG)

# Load the e2e images in the kind cluster. Note images are tagged in the `kind-local` registry
# to use it as a placeholder in e2e kubernetes manifests regardless of the configured $(DOCKER_HUB). This
# also helps state that the images needs to be kind-loaded.
.PHONY: kind-load
kind-load:  ## Load the end-to-end test images in the local Kind cluster
	@docker tag $(E2E_IMAGE) kind-local/$(NAME):e2e
	@go run $(KIND) load docker-image kind-local/$(NAME):e2e -n $(E2E_CLUSTER_NAME)

.PHONY: kind-create
kind-create: e2e-pre

.PHONY: kind-destroy
kind-destroy: e2e-post

.PHONY: clean
clean::
	@rm -rf ./logs
