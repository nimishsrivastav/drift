# Build from the repo root: docker build -f analyzers/meta-go/Dockerfile .
FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY gen/go gen/go
COPY analyzers/meta-go analyzers/meta-go
COPY orchestrator orchestrator
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /out/meta-go ./analyzers/meta-go

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/meta-go /meta-go
ENTRYPOINT ["/meta-go"]
