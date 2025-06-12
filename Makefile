.PHONY: all build test install clean

# Build variables
VERSION ?= 1.0.0
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD)

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

.DEFAULT_GOAL := build
