# Build context is the repository root (see docker-compose.yml), so the extractor can be compiled here.

# Stage 1: codegraph-extract, the Rust extractor (dependencies and advisories, code facts).
FROM rust:1-slim-bookworm AS extractor
WORKDIR /src
COPY extractor/Cargo.toml extractor/Cargo.lock ./
COPY extractor/src ./src
# rust-analyzer is a large dependency tree: on a Docker VM with little memory, build with
# `--build-arg CARGO_BUILD_JOBS=2` so the compiler does not exhaust it.
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked ${CARGO_BUILD_JOBS:+--jobs $CARGO_BUILD_JOBS} \
    && cp target/release/codegraph-extract /usr/local/bin/

# Stage 2: the API. Based on the Rust image because `codegraph-extract code` runs rust-analyzer,
# which needs cargo, rustc and the standard library sources at run time; Python is added on top.
FROM rust:1-slim-bookworm
RUN rustup component add rust-src \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY --from=extractor /usr/local/bin/codegraph-extract /usr/local/bin/codegraph-extract
WORKDIR /app
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install --no-cache-dir .
ENV CODEGRAPH_EXTRACTOR=/usr/local/bin/codegraph-extract \
    ADVISORY_DB_PATH=/var/lib/codegraph/advisory-db \
    CODE_FACTS_CACHE=/var/lib/codegraph/code-facts
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
