BIN := ./bin/nowsecure-network-broker

default: ci

ci: lint test

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN) ./cmd/broker

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

.PHONY: default ci build start test lint dependencies-analyze test-integration