# syntax=docker/dockerfile:1
# cerberus-mcp is not implemented yet (Sprint 4) — see
# cerberus-api.Dockerfile for the rationale of building the stub now.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus-mcp ./cmd/cerberus-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cerberus-mcp /usr/local/bin/cerberus-mcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cerberus-mcp"]
