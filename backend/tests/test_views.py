"""The endpoints behind the phase 4 views, against a real Neo4j: a finding's evidence path, slices of
source files, the SARIF export and the dependency view."""
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from app.analyzers import REGISTRY
from app.graph.deps import extractor_path
from app.graph.repository import GraphRepository
from app.main import app
from app.models.analysis import Project
from app.services.analysis import analyze_project
from app.services.ingest import build_and_store

REPOS = Path(__file__).resolve().parents[2] / "repos"

MAIN_RS = """\
fn main() {
    let v = vec![1u8, 2, 3];
    println!("{}", first(&v));
}

/// Reads the first byte.
fn first(v: &[u8]) -> u8 {
    // SAFETY: callers pass a non-empty slice.
    unsafe { *v.get_unchecked(0) }
}

fn raw(p: *const u8) -> u8 {
    unsafe { *p }
}
"""


@pytest.fixture
async def client(repo: GraphRepository) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def scanned(repo: GraphRepository, root: Path, name: str) -> Project:
    project = await repo.create_project(f"views:{name}", root.as_posix())
    await build_and_store(project, repo)
    await repo.mark_scan_finished(project.id)
    await analyze_project(project.id, repo)
    return project


@pytest.fixture
async def crate(repo: GraphRepository, tmp_path: Path) -> AsyncIterator[Project]:
    """A small crate with a documented and an undocumented unsafe block, and a source file that is
    a symlink to a file outside the project."""
    root = tmp_path / "crate"
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text('[package]\nname = "views"\nversion = "0.1.0"\nedition = "2021"\n')
    (root / "src" / "main.rs").write_text(MAIN_RS)
    outside = tmp_path / "outside.rs"
    outside.write_text("fn leaked() { /* SECRET-OUTSIDE-THE-PROJECT */ }\n")
    (root / "src" / "escape.rs").symlink_to(outside)
    project = await scanned(repo, root, "crate")
    yield project
    await repo.delete_project(project.id)


@pytest.fixture
async def unsafe_sample(repo: GraphRepository) -> AsyncIterator[Project]:
    project = await scanned(repo, REPOS / "vuln-samples" / "unsafe", "unsafe")
    yield project
    await repo.delete_project(project.id)


async def test_source_slice_with_flags(client: httpx.AsyncClient, crate: Project):
    res = await client.get(f"/api/projects/{crate.id}/source", params={"path": "src/main.rs"})
    assert res.status_code == 200
    body = res.json()
    assert body["language"] == "rust"
    assert (body["start"], body["end"], body["total_lines"]) == (1, 14, 14)
    assert body["lines"][8] == "    unsafe { *v.get_unchecked(0) }"
    kinds = {(f["kind"], f["line"]) for f in body["flags"]}
    assert ("safety", 8) in kinds                         # the SAFETY comment
    assert {("unsafe", 9), ("unsafe", 13)} <= kinds       # both unsafe blocks
    undocumented = [f for f in body["flags"] if f["kind"] == "finding" and f["rule"] == "undocumented-unsafe"]
    assert [f["line"] for f in undocumented] == [13]
    assert all(f["finding_id"] for f in undocumented)

    window = (await client.get(f"/api/projects/{crate.id}/source",
                               params={"path": "src/main.rs", "start": 12, "end": 13})).json()
    assert window["lines"] == ["fn raw(p: *const u8) -> u8 {", "    unsafe { *p }"]
    assert {f["kind"] for f in window["flags"]} == {"unsafe", "finding"}   # line 8's SAFETY note is outside

    manifest = await client.get(f"/api/projects/{crate.id}/source", params={"path": "Cargo.toml"})
    assert manifest.status_code == 200 and manifest.json()["language"] == "toml"


@pytest.mark.parametrize(("path", "status"), [
    ("../outside.rs", 400),        # climbs out of the project
    ("/etc/hosts", 400),           # absolute
    ("src/nope.rs", 404),          # not a file of the project
    ("src/escape.rs", 400),        # a scanned file whose symlink resolves outside the project
])
async def test_source_refuses_paths_outside_the_project(client: httpx.AsyncClient, crate: Project, path: str,
                                                        status: int):
    res = await client.get(f"/api/projects/{crate.id}/source", params={"path": path})
    assert res.status_code == status
    assert "SECRET-OUTSIDE-THE-PROJECT" not in res.text


async def test_source_rejects_bad_ranges(client: httpx.AsyncClient, crate: Project):
    url = f"/api/projects/{crate.id}/source"
    assert (await client.get(url, params={"path": "src/main.rs", "start": 99})).status_code == 400
    assert (await client.get(url, params={"path": "src/main.rs", "start": 5, "end": 2})).status_code == 400
    assert (await client.get("/api/projects/missing/source", params={"path": "src/main.rs"})).status_code == 404


async def test_evidence_path_from_entry_to_unsafe(client: httpx.AsyncClient, repo: GraphRepository,
                                                 unsafe_sample: Project):
    findings = await repo.list_findings(unsafe_sample.id, rule="unsafe-reachable-from-entry")
    finding = next(f for f in findings if f.message.startswith("crate.buffer.sum "))
    res = await client.get(f"/api/projects/{unsafe_sample.id}/findings/{finding.id}/evidence")
    assert res.status_code == 200
    body = res.json()
    assert body["finding"]["id"] == finding.id and body["missing"] == []
    steps = body["steps"]
    assert [s["node"]["kind"] for s in steps] == ["function", "function", "unsafe"]
    assert steps[0]["node"]["attrs"]["entry_kind"] == "main"
    assert [s["edge"]["kind"] if s["edge"] else None for s in steps] == ["CALLS", "CONTAINS", None]
    assert steps[0]["edge"]["source"] == steps[0]["node"]["id"]
    assert steps[2]["owner"]["qualified_name"] == "crate.buffer.sum"
    assert steps[2]["node"]["file"] == "src/buffer.rs" and steps[2]["node"]["line_start"] == 46

    assert (await client.get(f"/api/projects/{unsafe_sample.id}/findings/nope/evidence")).status_code == 404


async def test_sarif_export(client: httpx.AsyncClient, repo: GraphRepository, unsafe_sample: Project):
    res = await client.get(f"/api/projects/{unsafe_sample.id}/findings.sarif")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/sarif+json")
    assert 'filename="views-unsafe.sarif"' in res.headers["content-disposition"]
    log = res.json()
    assert log["version"] == "2.1.0" and len(log["runs"]) == 1
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} >= {a.rule for a in REGISTRY}
    findings = await repo.list_findings(unsafe_sample.id)
    assert len(run["results"]) == len(findings) > 0
    for result in run["results"]:
        rule = rules[result["ruleIndex"]]
        assert rule["id"] == result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert not location["artifactLocation"]["uri"].startswith("/")
        assert location["region"]["startLine"] >= 1
        for flow in result.get("codeFlows", []):
            steps = flow["threadFlows"][0]["locations"]
            assert len(steps) >= 2
            assert [s["executionOrder"] for s in steps] == list(range(1, len(steps) + 1))
            assert all(s["location"]["message"]["text"] for s in steps)
    reachable = [r for r in run["results"] if r["ruleId"] == "unsafe-reachable-from-entry"]
    assert reachable and all("codeFlows" in r for r in reachable)
    tags = next(r for r in rules if r["id"] == "dangerous-unsafe-op")["properties"]["tags"]
    assert "security" in tags and any(t.startswith("external/cwe/cwe-") for t in tags)

    # Fingerprints identify a finding across analysis runs, whose finding ids are new each time.
    before = sorted(r["partialFingerprints"]["codegraph/v1"] for r in run["results"])
    await analyze_project(unsafe_sample.id, repo)
    again = (await client.get(f"/api/projects/{unsafe_sample.id}/findings.sarif")).json()["runs"][0]["results"]
    assert sorted(r["partialFingerprints"]["codegraph/v1"] for r in again) == before

    only = (await client.get(f"/api/projects/{unsafe_sample.id}/findings.sarif",
                             params={"category": "quality"})).json()["runs"][0]["results"]
    assert all(rules[r["ruleIndex"]]["properties"]["category"] == "quality" for r in only)


async def test_dependency_view(client: httpx.AsyncClient, repo: GraphRepository):
    project = await scanned(repo, REPOS / "vuln-samples" / "deps", "deps")
    try:
        res = await client.get(f"/api/projects/{project.id}/dependencies")
        assert res.status_code == 200
        view = res.json()
        crates = {n["name"]: n for n in view["nodes"] if n["kind"] == "crate"}
        member = crates["deps-sample"]
        assert member["attrs"]["workspace_member"] is True
        assert view["crate_files"] == {member["id"]: ["src/main.rs"]}
        depends = {(e["source"], e["target"]) for e in view["edges"] if e["kind"] == "DEPENDS_ON"}
        assert (member["id"], crates["smallvec"]["id"]) in depends
        advisories = [n for n in view["nodes"] if n["kind"] == "advisory"]
        assert all("description" not in n["attrs"] for n in advisories)

        if extractor_path() is None:
            assert advisories == []          # the lockfile alone names no advisories
            return
        radius = (await client.get(f"/api/projects/{project.id}/advisories/RUSTSEC-2021-0003/blast-radius")).json()
        calls = {f["path"]: f for c in radius["crates"] for f in c["functions"]}
        insert = calls["smallvec::SmallVec::insert_many"]
        assert insert["affected"] and insert["line"] == 8 and insert["external"]
        assert insert["entry_distance"] == 1             # main -> buffer
        assert radius["advisory"]["description"]
    finally:
        await repo.delete_project(project.id)
