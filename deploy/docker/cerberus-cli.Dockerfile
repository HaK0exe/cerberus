# syntax=docker/dockerfile:1
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/HaK0exe/cerberus/internal/version.Version=${VERSION} -X github.com/HaK0exe/cerberus/internal/version.Commit=${COMMIT} -X github.com/HaK0exe/cerberus/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/cerberus ./cmd/cerberus

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cerberus /usr/local/bin/cerberus
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cerberus"]
CMD ["--help"]
