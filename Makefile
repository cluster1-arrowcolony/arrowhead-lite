.PHONY: all build test install clean check fmt vet lint security

# Build variables
VERSION ?= 1.0.0
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD)
export PATH := $(shell go env GOPATH)/bin:$(PATH)

# Go build flags
LDFLAGS = -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)

all: build

build:
	@echo "Building arrowhead-lite..."
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o bin/arrowhead-lite ./cmd/main.go

test:
	@echo "Running tests..."
	go test -v -race ./...

install: build
	sudo cp bin/arrowhead-lite /usr/local/bin/

clean:
	rm -f bin/arrowhead-lite

dev: build
	./bin/arrowhead-lite

# Code quality and security checks
fmt:
	@echo "Checking formatting..."
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Go code is not formatted. Please run 'gofmt -s -w .'"; \
		gofmt -s -l .; \
		exit 1; \
	fi

vet:
	@echo "Running go vet..."
	go vet ./...

lint:
	@echo "Running golangci-lint..."
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	}
	$(shell go env GOPATH)/bin/golangci-lint run --timeout=5m
	@echo "Running staticcheck..."
	@command -v staticcheck >/dev/null 2>&1 || { \
		echo "Installing staticcheck..."; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	}
	$(shell go env GOPATH)/bin/staticcheck ./...

security:
	@echo "Running security checks..."
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "Installing govulncheck..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	}
	$(shell go env GOPATH)/bin/govulncheck ./...
	@command -v gosec >/dev/null 2>&1 || { \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	}
	$(shell go env GOPATH)/bin/gosec ./...

check: fmt vet lint security test
	@echo "Verifying dependencies..."
	go mod verify
	@echo "Checking if go.mod is tidy..."
	go mod tidy
	@git diff --exit-code go.mod go.sum || { \
		echo "go.mod or go.sum is not tidy. Please run 'go mod tidy'"; \
		exit 1; \
	}
	@echo "All checks passed!"

.DEFAULT_GOAL := build
