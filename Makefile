.PHONY: build test lint fmt vet clean run-scan

BINARY := bin/cerberus
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/HaK0exe/cerberus/internal/version.Version=$(VERSION) \
           -X github.com/HaK0exe/cerberus/internal/version.Commit=$(COMMIT)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/cerberus

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

lint: vet fmt

clean:
	rm -rf bin/ dist/

run-scan: build
	$(BINARY) scan file $(FILE)
