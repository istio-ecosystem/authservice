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

include ../suite-certs.mk
include ../suite-k8s.mk

.PHONY: gen-certs
gen-certs: clean-certs ca/ca.authservice.internal certificate/http-echo.authservice.internal
	@chmod -R a+r $(CERTS_DIR)

.PHONY: clean
clean:: clean-certs

.PHONY: e2e-pre
e2e-pre:: gen-certs
	@kubectl --kubeconfig $(E2E_KUBECONFIG) create namespace istio-system
	@kubectl --kubeconfig $(E2E_KUBECONFIG) -n istio-system create secret tls http-echo-certs \
		--cert=certs/http-echo.authservice.internal.crt \
		--key=certs/http-echo.authservice.internal.key
