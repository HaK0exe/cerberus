# syntax=docker/dockerfile:1
# The standalone MCP binary currently serves stdio. It is not an HTTP
# service and still exposes honest stubs for scan orchestration and
# remediation execution.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus-mcp ./cmd/cerberus-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cerberus-mcp /usr/local/bin/cerberus-mcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cerberus-mcp"]
