# Build from the repo root: docker build -f crates/static-rs/Dockerfile .
FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY proto proto
COPY crates crates
RUN cargo build --release --locked -p static-rs

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/static-rs /static-rs
ENTRYPOINT ["/static-rs"]
