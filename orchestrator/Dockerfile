# Build from the repo root: docker build -f orchestrator/Dockerfile .
FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY gen/go gen/go
COPY analyzers/meta-go analyzers/meta-go
COPY orchestrator orchestrator
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /out/drift-server ./orchestrator/cmd/drift-server
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /out/drift ./orchestrator/cmd/drift

# Not distroless like the other services: repo resolution runs git. See docs/DECISIONS.md.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
# The same uid as the distroless services, so that analyzers can read what this image writes.
# Empty named volumes take their ownership from these directories on first use.
RUN useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && install -d -o 65532 -g 65532 -m 0750 /artifacts /var/lib/drift
COPY --from=build /out/drift-server /drift-server
COPY --from=build /out/drift /drift
COPY orchestrator/config/analyzers.yaml /etc/drift/analyzers.yaml
ENV DRIFT_ANALYZERS_CONFIG=/etc/drift/analyzers.yaml
ENV DRIFT_DATA_DIR=/artifacts
ENV DRIFT_DB=/var/lib/drift/drift.db
USER 65532:65532
ENTRYPOINT ["/drift-server"]
