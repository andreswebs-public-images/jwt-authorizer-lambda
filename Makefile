APP_NAME   := jwt-authorizer-lambda
BIN_DIR    := $(CURDIR)/bin
IMAGE      ?= $(APP_NAME):local

.PHONY: help build compile validate fmt fmt-check vet lint test test-race \
        tidy tidy-check image clean

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: validate compile ## Run every check, then compile

compile: | $(BIN_DIR) ## Compile the handler for the host platform
	CGO_ENABLED=0 go build -trimpath -tags lambda.norpc -o $(BIN_DIR)/app .

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

validate: fmt-check vet lint tidy-check test ## Run all checks

fmt: ## Format Go code
	gofmt -w .

fmt-check: ## Fail if any file is not formatted
	@test -z "$$(gofmt -l .)" || (echo "files not formatted:"; gofmt -l .; exit 1)

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

tidy: ## Tidy module requirements
	go mod tidy

tidy-check: ## Fail if go.mod or go.sum would change
	@cp go.mod go.mod.check && cp go.sum go.sum.check && \
	  status=0; \
	  go mod tidy || status=2; \
	  if [ $$status -eq 0 ]; then \
	    cmp -s go.mod go.mod.check || status=1; \
	    cmp -s go.sum go.sum.check || status=1; \
	  fi; \
	  mv go.mod.check go.mod && mv go.sum.check go.sum; \
	  if [ $$status -eq 1 ]; then echo "go.mod/go.sum are not tidy; run make tidy"; exit 1; fi; \
	  if [ $$status -ne 0 ]; then echo "go mod tidy failed"; exit 1; fi

test: ## Run tests
	go test ./...

test-race: ## Run tests with the race detector
	go test -race ./...

image: ## Build the container image for the host platform
	docker build --load --tag $(IMAGE) .

clean: ## Remove build artifacts
	@[ -d "$(BIN_DIR)" ] && rm -rf $(BIN_DIR) || true
