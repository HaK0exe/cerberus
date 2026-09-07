.PHONY: build install test lint fmt vet lint-full staticcheck gosec govulncheck release-check clean run-scan

BINARY := bin/cerberus
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/HaK0exe/cerberus/internal/version.Version=$(VERSION) \
           -X github.com/HaK0exe/cerberus/internal/version.Commit=$(COMMIT) \
           -X github.com/HaK0exe/cerberus/internal/version.BuildDate=$(BUILD_DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/cerberus

# Installs cerberus onto $PATH (into `go env GOBIN`, or `go env
# GOPATH`/bin if GOBIN is unset) so it runs as `cerberus` from any
# directory, like sqlmap/katana — not just as ./bin/cerberus from the
# repo root.
install:
	go install -ldflags "$(LDFLAGS)" ./cmd/cerberus
	@echo "installed to $$(go env GOBIN 2>/dev/null | grep -q . && go env GOBIN || echo $$(go env GOPATH)/bin)/cerberus"
	@echo "make sure that directory is on your PATH"

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

lint: vet fmt

# Full CI gate (see AGENTS.md): vet + fmt + staticcheck + gosec + govulncheck.
lint-full: vet fmt staticcheck gosec govulncheck

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -quiet ./...

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

release-check:
	go run github.com/goreleaser/goreleaser/v2@v2.18.1 check
	go run github.com/goreleaser/goreleaser/v2@v2.18.1 release --snapshot --clean --skip=sign,sbom,publish

clean:
	rm -rf bin/ dist/

run-scan: build
	$(BINARY) scan file $(FILE)
