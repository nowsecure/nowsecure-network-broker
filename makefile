NAME := nowsecure-network-broker
BIN := ./bin/$(NAME)
EXE := ./cmd/broker

default: ci

ci: lint test

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN) $(EXE)

start: build
	$(BIN) start -c ./.ci/hack/config.yaml

PACKAGES := $(shell go list ./... | grep -v /integration_test)
test:
	go run gotest.tools/gotestsum@latest --format testname $(PACKAGES)

test-integration:
	go run gotest.tools/gotestsum@latest --format standard-verbose ./integration_test/...

LINTER_ARGS := "--fix"
lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Please run 'asdf install' to install it." && exit 1)
	golangci-lint run ${LINTER_ARGS} ./...

dependencies-analyze:
	which govulncheck || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

GIT_RELEASE_TAG ?= $(shell git describe --tags --always)

release-amd64:
	$(info INFO: Starting build $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(GIT_RELEASE_TAG) -s -w" -o release/$(NAME)-linux-amd64 $(EXE)

release-arm64:
	$(info INFO: Starting build $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(GIT_RELEASE_TAG) -s -w" -o release/$(NAME)-linux-arm64 $(EXE)

release: release-amd64 release-arm64

.PHONY: default ci build start test lint dependencies-analyze test-integration release-amd64 release-arm64 release