IMAGE_REGISTRY ?= quay.io/oraz
IMAGE_NAME ?= vigil
VERSION ?= 0.0.2
IMG ?= $(IMAGE_REGISTRY)/$(IMAGE_NAME)

COMMIT_COUNT := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
BUILD_NUMBER := $(shell echo $$(( $(COMMIT_COUNT) / 10 )))
SHORT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

CONTAINER_TOOL ?= $(shell command -v podman 2>/dev/null || echo docker)

.PHONY: build
build: ## Build the vigil binary
	CGO_ENABLED=0 go build -o bin/vigil .

.PHONY: test
test: ## Run unit tests
	go test ./... -count=1

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt-check
fmt-check: ## Check code formatting
	@test -z "$$(gofmt -l .)" || (echo "Run 'gofmt -w .' to fix formatting"; gofmt -l .; exit 1)

.PHONY: lint
lint: vet fmt-check ## Run all linters

.PHONY: docker-build
docker-build: ## Build container image
	@mkdir -p certs && cp /etc/pki/ca-trust/source/anchors/*.pem certs/ 2>/dev/null; true
	$(CONTAINER_TOOL) build -t $(IMG):latest -f Containerfile .
	@rm -rf certs

.PHONY: docker-push
docker-push: ## Push container image with latest and milestone tags
	$(CONTAINER_TOOL) push $(IMG):latest
	@if [ $$(( $(COMMIT_COUNT) % 10 )) -eq 0 ] && [ $(COMMIT_COUNT) -gt 0 ]; then \
		echo "Build milestone: tagging v$(VERSION)-$(BUILD_NUMBER)-$(SHORT_SHA)"; \
		$(CONTAINER_TOOL) tag $(IMG):latest $(IMG):v$(VERSION)-$(BUILD_NUMBER)-$(SHORT_SHA); \
		$(CONTAINER_TOOL) push $(IMG):v$(VERSION)-$(BUILD_NUMBER)-$(SHORT_SHA); \
		./hack/changelog.sh "$(VERSION)" "$(BUILD_NUMBER)" "$(SHORT_SHA)"; \
	fi

.PHONY: changelog
changelog: ## Generate changelog for current build milestone
	@./hack/changelog.sh "$(VERSION)" "$(BUILD_NUMBER)" "$(SHORT_SHA)"

.PHONY: container-build-and-push
container-build-and-push: docker-build docker-push ## Build and push container image

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
