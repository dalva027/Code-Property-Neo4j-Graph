# Standalone image for the extractor: `docker build -t codegraph-extract extractor`.
# The API image builds the same binary in its own first stage (backend/Dockerfile).
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/codegraph-extract /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/codegraph-extract /usr/local/bin/codegraph-extract
ENTRYPOINT ["codegraph-extract"]
