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

PKG	   	   ?= ./cmd
BUILD_OPTS ?=
TEST_OPTS  ?=
TEST_PKGS  ?= $(shell go list ./... | grep -v /e2e)
OUTDIR     ?= bin

include env.mk    # Load common variables


##@ Build targets

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS:%=$(OUTDIR)/$(NAME)-%)  ## Build all the binaries

.PHONY: static
static: $(TARGETS:%=$(OUTDIR)/$(NAME)-static-%)  ## Build all the static binaries

.PHONY: fips
fips: $(FIPS_TARGETS:%=$(OUTDIR)/$(NAME)-fips-%)  ## Build all the FIPS static binaries

$(OUTDIR)/$(NAME)-%: GOOS=$(word 1,$(subst -, ,$(subst $(NAME)-,,$(@F))))
$(OUTDIR)/$(NAME)-%: GOARCH=$(word 2,$(subst -, ,$(subst $(NAME)-,,$(@F))))
$(OUTDIR)/$(NAME)-%:
	@echo "Build $(@F)"
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_OPTS) -o $@ $(PKG)

$(OUTDIR)/$(NAME)-static-%: GOOS=$(word 1,$(subst -, ,$(subst $(NAME)-static-,,$(@F))))
$(OUTDIR)/$(NAME)-static-%: GOARCH=$(word 2,$(subst -, ,$(subst $(NAME)-static-,,$(@F))))
$(OUTDIR)/$(NAME)-static-%:
	@echo "Build $(@F)"
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_OPTS) \
		-ldflags '-s -w -extldflags "-static"' -tags "netgo" \
		-o $@ $(PKG)

$(OUTDIR)/$(NAME)-fips-%: GOOS=$(word 1,$(subst -, ,$(subst $(NAME)-fips-,,$(@F))))
$(OUTDIR)/$(NAME)-fips-%: GOARCH=$(word 2,$(subst -, ,$(subst $(NAME)-fips-,,$(@F))))
$(OUTDIR)/$(NAME)-fips-%:
ifneq ($(BUILD_FIPS_IN_DOCKER),true)
	@echo "Build $(@F)"
	@GOEXPERIMENT=boringcrypto CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(BUILD_OPTS) \
		-ldflags '-linkmode=external -s -w -extldflags "-static"' -tags "netgo" \
		-o $@ $(PKG)
	@echo "Verifying FIPS symbols are present"
	@strings $@ | grep -q _Cfunc__goboringcrypto_ || (echo "FIPS symbols not found" && exit 1)
else
# Run the FIPS build in a Linux container if the host OS is not Linux
	@$(ROOT)/run-in-docker.sh $(GOOS)/$(GOARCH) make $@
endif

.PHONY: clean
clean: clean/e2e  ## Clean the build artifacts
	@rm -rf $(OUTDIR)

.PHONY: clean/coverage
clean/coverage:  ## Clean the coverage report
	@rm -rf $(OUTDIR)/coverage

.PHONY: clean/all
clean/all: clean config/clean   ## Clean everything
	@rm -rf $(OUTDIR)

.PHONY: clean/e2e
clean/e2e:  ## Clean the e2e test artifacts
	@$(MAKE) -C $(@F) $(@D)


##@ Config Proto targets

.PHONY: config/build
config/build:  ## Build the API
	@$(MAKE) -C $(@D) $(@F)

.PHONY: config/clean
config/clean:  ## Clean the Config Proto generated code
	@$(MAKE) -C $(@D) $(@F)

.PHONY: config/lint
config/lint:  ## Lint the Config Proto generated code
	@$(MAKE) -C $(@D) $(@F)


##@ Test targets

.PHONY: test
test:  ## Run all the tests
	@KUBEBUILDER_ASSETS="$(shell go run $(ENVTEST) use -p path)" \
		go test $(TEST_OPTS) $(TEST_PKGS)

COVERAGE_OPTS ?=
.PHONY: coverage
coverage: ## Creates coverage report for all projects
	@echo "Running test coverage"
	@mkdir -p $(OUTDIR)/$@
	@KUBEBUILDER_ASSETS="$(shell go run $(ENVTEST) use -p path)" \
		go test $(COVERAGE_OPTS) \
			-timeout 30s \
			-coverprofile $(OUTDIR)/$@/coverage.out \
			-covermode atomic \
			$(TEST_PKGS)
	@go tool cover -html="$(OUTDIR)/$@/coverage.out" -o "$(OUTDIR)/$@/coverage.html"

.PHONY: e2e
e2e:  ## Runt he e2e tests
	@$(MAKE) -C e2e e2e

e2e/%: force-e2e
	@$(MAKE) -C e2e $(@)

.PHONY: force-e2e
force-e2e:

##@ Docker targets

.PHONY: docker-pre
docker-pre:
	@docker buildx inspect $(DOCKER_BUILDER_NAME) || \
		docker buildx create --name $(DOCKER_BUILDER_NAME) \
			--driver docker-container --driver-opt network=host \
			--buildkitd-flags '--allow-insecure-entitlement network.host' --use

comma     := ,
space     := $(empty) $(empty)
PLATFORMS := $(subst -,/,$(subst $(space),$(comma),$(DOCKER_TARGETS)))
INSECURE_REGISTRY_ARG := --output=type=registry,registry.insecure=true

.PHONY: docker
docker: docker-pre $(DOCKER_TARGETS:%=docker/static/%)  ## Build the Docker images

.PHONY: docker-fips
docker-fips: docker-pre $(DOCKER_TARGETS:%=docker/fips/%)  ## Build the FIPS Docker images

.SECONDEXPANSION:
docker/%: PLATFORM=$(subst -,/,$(notdir $(*)))
docker/%: DOCKER_ARCH=$(notdir $(subst -,/,$(PLATFORM)))
docker/%: FLAVOR=$(subst /,,$(dir $(*)))
docker/%: TAG_SUFFIX=$(if $(subst static,,${FLAVOR}),-fips)
docker/%: $(OUTDIR)/$(NAME)-$$(FLAVOR)-$$(notdir %)
	@echo "Building Docker image $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)-$(DOCKER_ARCH)$(TAG_SUFFIX)"
	@docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--builder $(DOCKER_BUILDER_NAME) \
		--load \
		-f Dockerfile \
		--platform $(PLATFORM) \
		--build-arg REPO=https://$(GO_MODULE) \
		--build-arg FLAVOR=$(FLAVOR) \
		$(subst org.,--label org.,$(DOCKER_METADATA)) \
		-t $(DOCKER_HUB)/$(NAME):latest-$(DOCKER_ARCH)$(TAG_SUFFIX) \
		-t $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)-$(DOCKER_ARCH)$(TAG_SUFFIX) \
		.

.PHONY: docker-push
docker-push: docker-pre $(DOCKER_TARGETS:%=$(OUTDIR)/$(NAME)-static-%) docker-push/static ## Build and push the multi-arch Docker images

.PHONY: docker-push-fips
docker-push-fips: docker-pre $(DOCKER_TARGETS:%=$(OUTDIR)/$(NAME)-fips-%) docker-push/fips ## Build and push the multi-arch FIPS Docker images

docker-push/%: TAG_SUFFIX=$(if $(subst static,,$(*)),-fips)
docker-push/%:
	@echo "Pushing Docker image $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)$(TAG_SUFFIX)"
	@docker buildx build \
		$(DOCKER_BUILD_ARGS) \
		--builder $(DOCKER_BUILDER_NAME) \
		$(if $(USE_INSECURE_REGISTRY),$(INSECURE_REGISTRY_ARG),--push) \
		-f Dockerfile \
		--platform $(PLATFORMS) \
		--build-arg REPO=https://$(GO_MODULE) \
		--build-arg FLAVOR=$(@F) \
		$(subst org.,--label org.,$(DOCKER_METADATA)) \
		$(subst org.,--annotation index:org.,$(DOCKER_METADATA)) \
		-t $(DOCKER_HUB)/$(NAME):$(DOCKER_TAG)$(TAG_SUFFIX) \
		.

##@ Other targets

.PHONY: generate
generate: config/build  ## Run code generation targets

LINT_OPTS ?= --timeout 5m
GOLANGCI_LINT_CONFIG ?= .golangci.yml
.PHONY: lint
lint: $(GOLANGCI_LINT_CONFIG) config/lint  ## Lint checks for all Go code
	@echo "Linting Go code"
	@go run $(GOLANGCI_LINT) run $(LINT_OPTS) --build-tags "$(TEST_TAGS)" --config $(GOLANGCI_LINT_CONFIG)

.PHONY: format
format: go.mod  ## Format all Go code
	@echo "Formatting code"
	@go run $(LICENSER) apply -r "Tetrate"
	@go run $(GOSIMPORTS) -local $(GO_MODULE) -w .
	@gofmt -w .

.PHONY: check
check:  ## CI blocks merge until this passes. If this fails, run "make check" locally and commit the difference.
	@echo "Running CI checks"
	@$(MAKE) clean/all generate
	@$(MAKE) format
	@if [ ! -z "`git status -s`" ]; then \
		echo "The following differences will fail CI until committed:"; \
		git diff; \
		exit 1; \
	fi

.PHONY: dist
dist:  ## Package the release binaries
	@mkdir -p $(OUTDIR)/dist
	@cd $(OUTDIR) && for f in $(NAME)-*; do \
		tar cvzf dist/$$f.tar.gz $$f; \
	done

.PHONY: help
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
			/^[.a-zA-Z0-9\/_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } \
			/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
