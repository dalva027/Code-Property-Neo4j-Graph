"""Ground-truth harness: scan every `repos/**/expected.json` project into a real Neo4j, run all
analyzers, and require precision and recall of 1 for every rule in scope.

Neo4j comes from testcontainers (a throwaway `neo4j:5` container). To use a running instance
instead, set CODEGRAPH_TEST_NEO4J_URI (plus CODEGRAPH_TEST_NEO4J_USER/PASSWORD); the test only
touches the projects it creates and deletes them afterwards. Without Docker or that variable the
tests are skipped. Cases that declare `"requires": ["extractor"]` also need codegraph-extract
(CODEGRAPH_EXTRACTOR, e.g. scripts/codegraph-extract-docker) and an advisory database
(ADVISORY_DB_PATH); without them they are skipped.

The harness runs in whichever mode the environment configures: with the binary every Cargo case is
scanned through the rust-analyzer extractor, and with `CODE_FACTS=off` (or no binary) through
tree-sitter alone. The cases that do not require the extractor must score 1/1 both ways.
"""
from pathlib import Path

import pytest

from app.analyzers import REGISTRY
from app.config import settings
from app.evaluate import format_report, load_expected, score
from app.graph.deps import extractor_path
from app.graph.repository import GraphRepository
from app.models.analysis import SECURITY_CATEGORIES
from app.services.analysis import analyze_project
from app.services.ingest import build_and_store

REPOS = Path(__file__).resolve().parents[2] / "repos"
CASES = sorted(p for p in REPOS.rglob("expected.json") if "target" not in p.parts)


def test_cases_are_discovered():
    names = {p.parent.relative_to(REPOS).as_posix() for p in CASES}
    assert {"sample", "sample-rust", "vuln-samples/deps"} <= names


@pytest.mark.extractor
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
