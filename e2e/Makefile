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

SUITES_DOCKER := mock redis keycloak
SUITES_K8S    := istio
SUITES        := $(SUITES_DOCKER) $(SUITES_K8S)

.PHONY: e2e
e2e: $(SUITES:%=e2e/%)  ## Run all e2e tests

.PHONY: e2e/docker
e2e/docker: $(SUITES_DOCKER:%=e2e/%)

.PHONY: e2e/k8s
e2e/k8s: $(SUITES_K8S:%=e2e/%)

e2e/%:
	@$(MAKE) -C $(@F) $(@D)

.PHONY: clean
clean: $(SUITES:%=clean/%)

clean/%:
	@$(MAKE) -C $(@F) $(@D)
