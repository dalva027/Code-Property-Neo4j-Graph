"""Ground-truth harness: scan every `repos/**/expected.json` project into a real Neo4j, run all
analyzers, and require precision and recall of 1 for every rule in scope.

Neo4j comes from testcontainers (a throwaway `neo4j:5` container). To use a running instance
instead, set CODEGRAPH_TEST_NEO4J_URI (plus CODEGRAPH_TEST_NEO4J_USER/PASSWORD); the test only
touches the projects it creates and deletes them afterwards. Without Docker or that variable the
tests are skipped. Cases that declare `"requires": ["extractor"]` also need codegraph-extract
(CODEGRAPH_EXTRACTOR, e.g. scripts/codegraph-extract-docker) and an advisory database
(ADVISORY_DB_PATH); without them they are skipped.
"""
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.analyzers import REGISTRY
from app.config import settings
from app.db import neo4j
from app.evaluate import format_report, load_expected, score
from app.graph.deps import extractor_path
from app.graph.repository import GraphRepository
from app.models.analysis import SECURITY_CATEGORIES
from app.services.analysis import analyze_project
from app.services.ingest import build_and_store

REPOS = Path(__file__).resolve().parents[2] / "repos"
CASES = sorted(p for p in REPOS.rglob("expected.json") if "target" not in p.parts)


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


def test_cases_are_discovered():
    names = {p.parent.relative_to(REPOS).as_posix() for p in CASES}
    assert {"sample", "sample-rust", "vuln-samples/deps"} <= names


@pytest.mark.parametrize("expected_file", CASES, ids=[p.parent.relative_to(REPOS).as_posix() for p in CASES])
async def test_ground_truth(expected_file: Path, repo: GraphRepository):
    expected = load_expected(expected_file)
    if "extractor" in expected.requires and extractor_path() is None:
        pytest.skip(f"{settings.codegraph_extractor} not found; set CODEGRAPH_EXTRACTOR")
    root = expected_file.parent
    project = await repo.create_project(f"ground-truth:{root.name}", root.as_posix())
    try:
        await build_and_store(project, repo)
        await repo.mark_scan_finished(project.id)
        await analyze_project(project.id, repo)
        findings = await repo.list_findings(project.id)

        # The stored round trip keeps the v2 fields.
        assert all(f.category and f.rule_version for f in findings)
        graph = await repo.get_graph(project.id)
        if any(n.language == "rust" for n in graph.nodes):
            assert any(n.kind == "external" for n in graph.nodes), "Rust scans keep external callees"
            assert any(e.kind == "CALLS" and e.props.get("count") for e in graph.edges)
    finally:
        await repo.delete_project(project.id)

    report = score(expected, findings, [a.info() for a in REGISTRY])
    # report.ok means no missed and no unexpected finding for any rule in scope, which includes
    # every security category: a sample with no expected security findings must produce none.
    assert report.ok, "\n" + format_report(report)
    assert all(cat in report.categories for cat in SECURITY_CATEGORIES if expected.scope.categories is None)
