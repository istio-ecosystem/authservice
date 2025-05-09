# Copyright 2025 Tetrate
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
# Docker compose to spin up the environment.
# When adding a suite, create a new directory under e2e/ and add a Makefile that
# includes this file.

ROOT := $(shell git rev-parse --show-toplevel)

include $(ROOT)/env.mk # Load common variables
-include $(ROOT)/.makerc  # Pick up any local overrides.

# Force run of the e2e tests by default
E2E_TEST_OPTS ?= -count=1


.PHONY: e2e
e2e: e2e-pre
	@$(MAKE) e2e-test e2e-post

.PHONY: e2e-test
e2e-test:
	@go test $(E2E_TEST_OPTS) ./... || ( $(MAKE) e2e-post-error; exit 1 )

.PHONY: e2e-pre
e2e-pre::
	@docker compose up --detach --wait --force-recreate --remove-orphans || ($(MAKE) e2e-post-error; exit 1)

.PHONY: e2e-post
e2e-post::
ifeq ($(E2E_PRESERVE_LOGS),true)
	@$(MAKE) capture-logs
endif
	@docker compose down --remove-orphans

.PHONY: e2e-post-error
e2e-post-error: capture-logs

.PHONY: capture-logs
capture-logs:
	@mkdir -p ./logs
	@docker compose logs > logs/docker-compose-logs.log

.PHONY: clean
clean::
	@rm -rf ./logs
