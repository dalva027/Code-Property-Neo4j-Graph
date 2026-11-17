# Standalone image for the extractor: `docker build -t codegraph-extract extractor`.
# The API image builds the same binary in its own first stage (backend/Dockerfile).
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# rust-analyzer is a large dependency tree: on a Docker VM with little memory, build with
# `--build-arg CARGO_BUILD_JOBS=2` so the compiler does not exhaust it.
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked ${CARGO_BUILD_JOBS:+--jobs $CARGO_BUILD_JOBS} \
    && cp target/release/codegraph-extract /usr/local/bin/

# The `code` subcommand is rust-analyzer as a library: at run time it needs cargo (for
# `cargo metadata`), rustc (sysroot and cfg discovery) and the standard library's sources, so the
# runtime image is the Rust image too. `deps` needs none of that. Dependency sources that
# `cargo metadata` downloads land in /usr/local/cargo/registry: mount a volume there to keep them.
FROM rust:1-slim-bookworm
RUN rustup component add rust-src
COPY --from=build /usr/local/bin/codegraph-extract /usr/local/bin/codegraph-extract
ENTRYPOINT ["codegraph-extract"]
