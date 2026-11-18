"""Shared test setup.

Unit tests describe the graph the tree-sitter parser builds, so they must not change with the
machine they run on: with `CODEGRAPH_EXTRACTOR` set, `GraphBuilder` would otherwise run
rust-analyzer inside them and resolve calls they expect to stay lexical. Every test therefore runs
with code facts off, except the ones marked `extractor`: the ground-truth harness, which scores
whichever mode the environment configures, and the check that the committed fixtures match the
binary. Tests that overlay committed facts switch the setting on themselves.

`neo4j_server` and `repo` give tests a real Neo4j: a throwaway `neo4j:5` container from
testcontainers, or the instance named by CODEGRAPH_TEST_NEO4J_URI (plus _USER/_PASSWORD). Without
Docker or that variable the tests that use them are skipped.
"""
import os
from collections.abc import Iterator

import pytest

from app.config import settings
from app.db import neo4j
from app.graph.repository import GraphRepository


@pytest.fixture(autouse=True)
def _code_facts_off(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("extractor") is None:
        monkeypatch.setattr(settings, "code_facts", "off")


@pytest.fixture(scope="session")
def neo4j_server() -> Iterator[tuple[str, str, str]]:
    if uri := os.environ.get("CODEGRAPH_TEST_NEO4J_URI"):
        yield (uri, os.environ.get("CODEGRAPH_TEST_NEO4J_USER", "neo4j"),
               os.environ.get("CODEGRAPH_TEST_NEO4J_PASSWORD", "codegraph"))
        return
    try:
        try:
            from testcontainers.community.neo4j import Neo4jContainer
        except ImportError:
            from testcontainers.neo4j import Neo4jContainer
        container = Neo4jContainer("neo4j:5", password="codegraph-test")
        container.start()
    except Exception as exc:  # noqa: BLE001 - no testcontainers, no Docker daemon, no image...
        pytest.skip(f"no Neo4j for the ground-truth harness: {exc}")
    try:
        yield container.get_connection_url(), container.username, container.password
    finally:
        container.stop()


@pytest.fixture
async def repo(neo4j_server, monkeypatch: pytest.MonkeyPatch):
    uri, user, password = neo4j_server
    monkeypatch.setattr(settings, "neo4j_uri", uri)
    monkeypatch.setattr(settings, "neo4j_user", user)
    monkeypatch.setattr(settings, "neo4j_password", password)
    await neo4j.connect(retries=30, delay=1.0)
    await neo4j.apply_schema()
    yield GraphRepository()
    await neo4j.close()
