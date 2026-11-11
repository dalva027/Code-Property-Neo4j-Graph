# Build context is the repository root (see docker-compose.yml), so the extractor can be compiled here.

# Stage 1: codegraph-extract, the Rust dependency/advisory extractor.
FROM rust:1-slim-bookworm AS extractor
WORKDIR /src
COPY extractor/Cargo.toml extractor/Cargo.lock ./
COPY extractor/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/codegraph-extract /usr/local/bin/

# Stage 2: the API.
FROM python:3.12-slim
COPY --from=extractor /usr/local/bin/codegraph-extract /usr/local/bin/codegraph-extract
WORKDIR /app
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install --no-cache-dir .
ENV CODEGRAPH_EXTRACTOR=/usr/local/bin/codegraph-extract \
    ADVISORY_DB_PATH=/var/lib/codegraph/advisory-db
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
