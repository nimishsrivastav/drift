# Build from the repo root: docker build -f deploy/fixture-registry/Dockerfile .
# Serves fixtures/npm, which compose mounts read-only at /fixtures. Standard library only, and
# outside go.work, so it builds on its own.
FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
WORKDIR /src
COPY deploy/fixture-registry ./
RUN CGO_ENABLED=0 GOWORK=off go build -trimpath -ldflags=-s -o /out/fixture-registry .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/fixture-registry /fixture-registry
ENTRYPOINT ["/fixture-registry"]
