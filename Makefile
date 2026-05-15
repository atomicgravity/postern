GO ?= go
BIN_DIR := bin

# Lambda binary inside the deployment zip MUST be named "bootstrap" for the
# provided.al2023 custom runtime. ARM64 (Graviton2) is the default platform.
LAMBDA_GOOS := linux
LAMBDA_GOARCH := arm64

.PHONY: all build test vet fmt fmt-check tidy tidy-check check clean broker-lambda.zip

all: check build

build:
	$(GO) build -o $(BIN_DIR)/postern ./cmd/postern
	$(GO) build -o $(BIN_DIR)/broker ./cmd/broker
	$(GO) build -o $(BIN_DIR)/timefix-apply ./cmd/timefix-apply
	$(GO) build -o $(BIN_DIR)/timefix-set-clock ./cmd/timefix-set-clock

# broker-lambda.zip produces the deployment artifact the terraform/postern-broker
# module expects (at bin/broker-lambda.zip). Rebuild on every invocation: the
# binary embeds VCS info that changes per commit and Terraform's local-file
# hashing detects content changes for redeploy.
broker-lambda.zip:
	@mkdir -p $(BIN_DIR)
	@rm -f $(BIN_DIR)/bootstrap $(BIN_DIR)/broker-lambda.zip
	GOOS=$(LAMBDA_GOOS) GOARCH=$(LAMBDA_GOARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags='-s -w' -o $(BIN_DIR)/bootstrap ./cmd/broker-lambda
	cd $(BIN_DIR) && zip -q broker-lambda.zip bootstrap
	@rm -f $(BIN_DIR)/bootstrap

test:
	$(GO) test -race ./...
	$(GO) test -tags timefix_test_path -race ./cmd/timefix-apply/...

vet:
	$(GO) vet ./...
	$(GO) vet -tags timefix_test_path ./cmd/timefix-apply/...

fmt:
	$(GO) fmt ./...

fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; \
		echo "$$out"; \
		exit 1; \
	fi

tidy:
	$(GO) mod tidy

tidy-check:
	@cp go.mod go.mod.bak; \
	if [ -f go.sum ]; then cp go.sum go.sum.bak; fi; \
	$(GO) mod tidy; \
	rc=0; \
	if ! diff -q go.mod go.mod.bak >/dev/null 2>&1; then rc=1; fi; \
	if [ -f go.sum.bak ] && ! diff -q go.sum go.sum.bak >/dev/null 2>&1; then rc=1; fi; \
	mv go.mod.bak go.mod; \
	if [ -f go.sum.bak ]; then mv go.sum.bak go.sum; fi; \
	if [ $$rc -ne 0 ]; then echo "go.mod / go.sum out of date — run 'make tidy'"; exit 1; fi

check: fmt-check vet test tidy-check

clean:
	rm -rf $(BIN_DIR)
	$(GO) clean -testcache
