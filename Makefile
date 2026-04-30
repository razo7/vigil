IMAGE_REGISTRY ?= quay.io/oraz
IMAGE_NAME ?= vigil
VERSION ?= 0.0.2
IMAGE_TAG ?= latest
IMG ?= $(IMAGE_REGISTRY)/$(IMAGE_NAME)

COMMIT_COUNT := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
VERSION_BASE := $(shell git rev-list --count v$(VERSION) 2>/dev/null || echo $(COMMIT_COUNT))
COMMITS_SINCE := $(shell echo $$(( $(COMMIT_COUNT) - $(VERSION_BASE) )))
BUILD_NUMBER := $(shell echo $$(( $(COMMITS_SINCE) / 10 + 1 )))
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
	$(CONTAINER_TOOL) build -t $(IMG):$(IMAGE_TAG) -f Containerfile .

.PHONY: docker-push
docker-push: ## Push container image
	$(CONTAINER_TOOL) push $(IMG):$(IMAGE_TAG)

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
