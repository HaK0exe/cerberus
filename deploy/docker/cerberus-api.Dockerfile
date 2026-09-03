# syntax=docker/dockerfile:1
# cerberus-api is not implemented yet (Sprint 4) — this Dockerfile
# builds the current stub binary so the image pipeline exists ahead of
# the implementation.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus-api ./cmd/cerberus-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cerberus-api /usr/local/bin/cerberus-api
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cerberus-api"]
