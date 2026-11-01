# Build from the repo root: docker build -f crates/static-rs/Dockerfile .
FROM rust:1.99.1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY proto proto
COPY crates crates
RUN cargo build --release --locked -p static-rs

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/static-rs /static-rs
ENTRYPOINT ["/static-rs"]
