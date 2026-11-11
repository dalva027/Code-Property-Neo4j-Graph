"""Dependency loader: lockfile parsing, manifests and linking crates to code; no Neo4j or extractor."""
import json
import textwrap
from pathlib import Path

import pytest

from app.graph.builder import GraphBuilder
from app.graph.deps import (
    ExtractorUnavailable,
    lockfile_lines,
    parse_lockfile,
    read_manifest,
    scan_dependencies,
)
from app.models.deps import DepsFacts

REPOS = Path(__file__).resolve().parents[2] / "repos"
SAMPLE = REPOS / "vuln-samples" / "deps"
FIXTURE = Path(__file__).parent / "fixtures" / "deps-sample.facts.json"


def sample_facts(_: Path) -> DepsFacts:
    return DepsFacts.model_validate_json(FIXTURE.read_text())


def test_fixture_is_current_schema():
    data = json.loads(FIXTURE.read_text())
    assert data["schema_version"] == 1 and data["advisory_db"]["commit"]


def test_parse_lockfile_matches_extractor_crates_and_edges():
    parsed = parse_lockfile(SAMPLE / "Cargo.lock")
    extracted = sample_facts(SAMPLE)
    assert {c.key for c in parsed.crates} == {c.key for c in extracted.crates}
    assert {(d.from_, d.to) for d in parsed.deps} == {(d.from_, d.to) for d in extracted.deps}
    assert not parsed.matches and not parsed.advisories


def test_ambiguous_dependency_versions(tmp_path: Path):
    (tmp_path / "Cargo.lock").write_text(textwrap.dedent('''
        version = 3
        [[package]]
        name = "app"
        version = "0.1.0"
        dependencies = ["log 0.4.20", "log 0.3.9"]
        [[package]]
        name = "log"
        version = "0.4.20"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        [[package]]
        name = "log"
        version = "0.3.9"
        source = "sparse+https://index.crates.io/"
    '''))
    facts = parse_lockfile(tmp_path / "Cargo.lock")
    assert {(d.from_, d.to) for d in facts.deps} == {("app@0.1.0", "log@0.4.20"), ("app@0.1.0", "log@0.3.9")}
    assert {c.key: c.source for c in facts.crates} == {"app@0.1.0": "path", "log@0.4.20": "registry",
                                                        "log@0.3.9": "registry"}
    assert lockfile_lines((tmp_path / "Cargo.lock").read_text()) == {"app@0.1.0": 4, "log@0.4.20": 8,
                                                                      "log@0.3.9": 12}


def test_manifest_kinds_and_renames(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(textwrap.dedent('''
        [package]
        name = "app"
        [dependencies]
        serde = "1"
        fancy = { package = "fancy-regex", version = "0.11" }
        [dev-dependencies]
        serde = "1"
        proptest = "1"
        [target.'cfg(unix)'.build-dependencies]
        cc = "1"
    '''))
    m = read_manifest(tmp_path / "Cargo.toml", tmp_path)
    assert m is not None and m.dir == "" and m.name == "app"
    assert m.kinds == {"serde": "normal", "fancy-regex": "normal", "proptest": "dev", "cc": "build"}
    assert m.renames["fancy"] == "fancy-regex"


def test_scan_links_sample_crates_to_code():
    graph = GraphBuilder().build(SAMPLE, "p")
    deps = scan_dependencies(SAMPLE, "p", graph, extractor=sample_facts)

    crates = {c.id: c for c in deps.crates}
    member = crates["p:crate:deps-sample@0.1.0"]
    assert member.workspace_member and member.manifest_path == "Cargo.toml"
    assert crates["p:crate:smallvec@1.6.0"].lockfile == "Cargo.lock"
    assert crates["p:crate:smallvec@1.6.0"].lockfile_line == 57

    direct = {e.target: e.kind for e in deps.depends_on if e.source == member.id}
    assert direct == {f"p:crate:{c}": "normal" for c in ("atty@0.2.14", "base64@0.5.1", "smallvec@1.6.0",
                                                          "time@0.1.45")}
    assert deps.crate_files == [(member.id, "p:src/main.rs")]
    assert ("p:src/main.rs", "p:crate:smallvec@1.6.0") in deps.uses
    assert set(deps.from_crate) == {
        ("p:atty::is", "p:crate:atty@0.2.14"),
        ("p:smallvec::SmallVec::insert_many", "p:crate:smallvec@1.6.0"),
        ("p:smallvec::SmallVec::new", "p:crate:smallvec@1.6.0"),
        ("p:time::get_time", "p:crate:time@0.1.45"),
    }
    kinds = {(a.crate.split(":")[-1], a.advisory): a.kind for a in deps.affected_by}
    assert kinds[("smallvec@1.6.0", "RUSTSEC-2021-0003")] == "vulnerability"
    assert kinds[("atty@0.2.14", "RUSTSEC-2021-0145")] == "unsound"
    assert deps.advisory_db_commit and not deps.warnings


def test_missing_extractor_falls_back_to_lockfile():
    def unavailable(_: Path) -> DepsFacts:
        raise ExtractorUnavailable("codegraph-extract not found")

    graph = GraphBuilder().build(SAMPLE, "p")
    deps = scan_dependencies(SAMPLE, "p", graph, extractor=unavailable)
    assert len(deps.crates) == 12 and not deps.affected_by and not deps.advisories
    assert any("advisories skipped" in w for w in deps.warnings)


def test_manifest_without_lockfile_is_reported(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "0.1.0"\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn f() {}\n")
    deps = scan_dependencies(tmp_path, "p", GraphBuilder().build(tmp_path, "p"), extractor=sample_facts)
    assert deps.crates == [] and deps.warnings == ["Cargo.toml has no Cargo.lock; its dependencies were not analyzed"]


@pytest.mark.parametrize("version", ["0.4.20", "0.3.9"])
def test_renamed_and_duplicate_versions_link_within_member_closure(tmp_path: Path, version: str):
    # Two members depend on different versions of `log`; each member's calls link to its own version.
    for name, ver in (("a", "0.4.20"), ("b", "0.3.9")):
        (tmp_path / name / "src").mkdir(parents=True)
        (tmp_path / name / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n[dependencies]\nlog = "={ver}"\n')
        (tmp_path / name / "src" / "lib.rs").write_text("pub fn f() { log::info(); }\n")
    (tmp_path / "Cargo.lock").write_text(textwrap.dedent('''
        version = 3
        [[package]]
        name = "a"
        version = "0.1.0"
        dependencies = ["log 0.4.20"]
        [[package]]
        name = "b"
        version = "0.1.0"
        dependencies = ["log 0.3.9"]
        [[package]]
        name = "log"
        version = "0.4.20"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        [[package]]
        name = "log"
        version = "0.3.9"
        source = "registry+https://github.com/rust-lang/crates.io-index"
    '''))
    graph = GraphBuilder().build(tmp_path, "p")
    deps = scan_dependencies(tmp_path, "p", graph, extractor=lambda lf: parse_lockfile(lf))
    member = "a" if version == "0.4.20" else "b"
    assert (f"p:crate:{member}@0.1.0", f"p:{member}/src/lib.rs") in deps.crate_files
    # One External node `log::info`, linked to both versions because both members call it.
    assert ("p:log::info", f"p:crate:log@{version}") in deps.from_crate
