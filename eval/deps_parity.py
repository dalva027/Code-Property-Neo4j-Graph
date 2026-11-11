"""Phase 1 acceptance: codegraph's dependency findings against `cargo audit --json`.

For each case (a directory with a Cargo.lock, plus cargo-audit's JSON report for it) this scans the
directory into a throwaway project in the configured Neo4j, runs the analyzers, and compares:

- `vulnerable-dependency` findings with cargo-audit's vulnerabilities, as (advisory, crate, version);
- `unmaintained-or-unsound-dependency` findings with cargo-audit's unmaintained, unsound and notice
  warnings. Yanked crates need the crates.io index and are out of scope.

Both tools must use the same advisory database checkout. It also prints how the D2 triage split
each project's vulnerabilities. Run from the backend virtualenv:

    cd backend
    CODEGRAPH_EXTRACTOR=../scripts/codegraph-extract-docker ADVISORY_DB_PATH=$PWD/.advisory-db \\
      .venv/bin/python ../eval/deps_parity.py ../eval/corpus/deps/ripgrep:../eval/corpus/deps/ripgrep.audit.json ...

Exit status 0 means every case matched exactly.
"""
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.db import neo4j
from app.graph.repository import GraphRepository
from app.services.analysis import analyze_project
from app.services.ingest import build_and_store

INFORMATIONAL = ("unmaintained", "unsound", "notice")
TRIAGE = ("vulnerable-api-reachable", "vulnerable-crate-used", "vulnerable-dependency-unused")


def audit_sets(report: dict) -> tuple[set, set]:
    vulns = {(v["advisory"]["id"], v["package"]["name"], v["package"]["version"])
             for v in report["vulnerabilities"]["list"]}
    warnings = {(w["advisory"]["id"], w["package"]["name"], w["package"]["version"])
                for kind, items in (report.get("warnings") or {}).items() if kind in INFORMATIONAL
                for w in items if w.get("advisory")}
    return vulns, warnings


def crate_of(crate_id: str) -> tuple[str, str]:
    name, _, version = crate_id.split(":crate:", 1)[1].rpartition("@")
    return name, version


async def ours(root: Path, repo: GraphRepository) -> tuple[set, set, Counter, list[str]]:
    project = await repo.create_project(f"parity:{root.name}", root.resolve().as_posix())
    try:
        await build_and_store(project, repo)
        await repo.mark_scan_finished(project.id)
        await analyze_project(project.id, repo)
        findings = await repo.list_findings(project.id)
        warnings = (await repo.get_project(project.id)).warnings
    finally:
        await repo.delete_project(project.id)
    vulns, infos = set(), set()
    for f in findings:
        if f.rule == "vulnerable-dependency":
            vulns.add((f.evidence[1], *crate_of(f.evidence[0])))
        elif f.rule == "unmaintained-or-unsound-dependency":
            infos.add((f.evidence[1], *crate_of(f.evidence[0])))
    return vulns, infos, Counter(f.rule for f in findings if f.rule in TRIAGE), warnings


def compare(label: str, expected: set, actual: set) -> bool:
    missing, extra = sorted(expected - actual), sorted(actual - expected)
    status = "match" if not missing and not extra else "MISMATCH"
    print(f"  {label:28} cargo-audit {len(expected):3}  codegraph {len(actual):3}  {status}")
    for m in missing:
        print(f"    missing  {' '.join(m)}")
    for e in extra:
        print(f"    extra    {' '.join(e)}")
    return status == "match"


async def main(cases: list[str]) -> int:
    await neo4j.connect()
    await neo4j.apply_schema()
    repo = GraphRepository()
    ok = True
    try:
        for case in cases:
            directory, _, audit_file = case.partition(":")
            root = Path(directory)
            report = json.loads(Path(audit_file).read_text())
            audit_vulns, audit_infos = audit_sets(report)
            our_vulns, our_infos, triage, warnings = await ours(root, repo)
            print(f"{root.name}")
            ok &= compare("vulnerabilities (D1)", audit_vulns, our_vulns)
            ok &= compare("unmaintained/unsound (D3)", audit_infos, our_infos)
            print("  D2 triage: " + ", ".join(f"{rule} {triage.get(rule, 0)}" for rule in TRIAGE))
            for w in warnings:
                print(f"  warning: {w}")
    finally:
        await neo4j.close()
    print("OK" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
