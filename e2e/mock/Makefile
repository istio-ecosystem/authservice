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


.PHONY: e2e
e2e: e2e-pre
	@go test $(E2E_TEST_OPTS) ./... || ( $(MAKE) e2e-test-post-error; exit 1 )
	@$(MAKE) e2e-test-post

.PHONY: e2e-pre
e2e-pre:
	@docker compose up --detach --wait --force-recreate --remove-orphans || ($(MAKE) e2e-test-post-error; exit 1)

.PHONY: e2e-test-post
e2e-test-post:
	@docker compose down

.PHONY: e2e-test-post-error
e2e-test-post-error: capture-logs

.PHONY: capture-logs
capture-logs:
	@mkdir -p ./logs
	@docker compose logs > logs/docker-compose-logs.log

.PHONY: clean
clean:
	@rm -rf ./logs
