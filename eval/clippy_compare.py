"""Phase 2 comparison: codegraph's P1, P2 and U2 findings against clippy's lints, per source line.

clippy lints map onto rules like this:

    unwrap_used, expect_used, panic, unreachable, todo, unimplemented  ->  panic-reachable-from-entry (P1)
    indexing_slicing                                                   ->  unchecked-index (P2)
    undocumented_unsafe_blocks                                         ->  undocumented-unsafe (U2)

Codegraph reports P1 and P2 once per function but keeps every site in the finding's evidence (Call
nodes), so the comparison is done per site: for each rule the script lists the lines both tools
flag, the lines only clippy flags, and the lines only codegraph flags. For P1 it also reports how
many clippy sites codegraph's reachability filter drops (sites in functions no entry point reaches,
or in test code), which is the point of the graph.

Usage, from the backend virtualenv with Neo4j reachable:

    cd backend
    .venv/bin/python ../eval/clippy_compare.py ../repos/vuln-samples/panics ../repos/vuln-samples/unsafe

The crate must compile. Set CLIPPY to the command that runs clippy in it (default: `cargo clippy`),
for example a Docker wrapper:

    CLIPPY="docker run --rm -v $PWD/..:$PWD/.. -w {dir} rust:1-slim-bookworm cargo clippy"
"""
import asyncio
import json
import os
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.db import neo4j
from app.graph.repository import GraphRepository
from app.services.analysis import analyze_project
from app.services.ingest import build_and_store

LINTS = {
    "clippy::unwrap_used": "panic-reachable-from-entry", "clippy::expect_used": "panic-reachable-from-entry",
    "clippy::panic": "panic-reachable-from-entry", "clippy::unreachable": "panic-reachable-from-entry",
    "clippy::todo": "panic-reachable-from-entry", "clippy::unimplemented": "panic-reachable-from-entry",
    "clippy::indexing_slicing": "unchecked-index",
    "clippy::undocumented_unsafe_blocks": "undocumented-unsafe",
}
SITE_NODES = {
    "panic-reachable-from-entry": "Call", "unchecked-index": "Call", "undocumented-unsafe": "Unsafe",
}


def run_clippy(crate: Path) -> dict[str, set[tuple[str, int]]]:
    """{rule: {(file, line)}} from clippy's JSON diagnostics, with every mapped lint forced on."""
    base = os.environ.get("CLIPPY", "cargo clippy").replace("{dir}", str(crate.resolve()))
    cmd = [*shlex.split(base), "--quiet", "--message-format=json", "--", *(f"-W{lint}" for lint in LINTS)]
    done = subprocess.run(cmd, cwd=crate, capture_output=True, text=True, check=False)
    if done.returncode != 0 and not done.stdout:
        raise SystemExit(f"clippy failed in {crate}:\n{done.stderr[-2000:]}")
    hits: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for line in done.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        diag = msg.get("message") or {}
        code = (diag.get("code") or {}).get("code")
        if code not in LINTS:
            continue
        for span in diag.get("spans", []):
            if span.get("is_primary"):
                hits[LINTS[code]].add((span["file_name"].replace("\\", "/"), span["line_start"]))
    return hits


async def codegraph_sites(crate: Path, repo: GraphRepository) -> tuple[dict, dict, set]:
    """({rule: {(file, line)}} flagged, {rule: {(file, line)}} filtered out, panic sites in all code)."""
    project = await repo.create_project(f"clippy:{crate.name}", crate.resolve().as_posix())
    try:
        await build_and_store(project, repo)
        await repo.mark_scan_finished(project.id)
        await analyze_project(project.id, repo)
        findings = await repo.list_findings(project.id)
        flagged: dict[str, set[tuple[str, int]]] = defaultdict(set)
        for f in findings:
            if f.rule not in SITE_NODES:
                continue
            rows = await repo.query(
                f"MATCH (n:{SITE_NODES[f.rule]} {{project_id: $pid}}) WHERE n.id IN $ids "
                "RETURN n.file AS file, n.line_start AS line", pid=project.id, ids=f.evidence)
            flagged[f.rule].update((r["file"], r["line"]) for r in rows)
        # Every panicking call site, reachable or not, so the filter's effect can be measured.
        rows = await repo.query(
            """
            MATCH (fn:Function {project_id: $pid})-[:HAS_CALL]->(c:Call {subkind: 'call'})
            WHERE c.callee_path IN ['?::unwrap', '?::expect', '?::unwrap_unchecked', 'std::panic!',
                                    'std::unreachable!', 'std::todo!', 'std::unimplemented!']
            RETURN c.file AS file, c.line_start AS line, fn.entry_distance AS distance,
                   coalesce(fn.in_test, false) AS in_test
            """, pid=project.id)
        all_panics = {(r["file"], r["line"]) for r in rows}
        unreachable = {(r["file"], r["line"]) for r in rows if r["distance"] is None or r["in_test"]}
        return flagged, {"panic-reachable-from-entry": unreachable}, all_panics
    finally:
        await repo.delete_project(project.id)


def report(name: str, rule: str, ours: set, theirs: set, dropped: set) -> None:
    both, only_clippy, only_ours = ours & theirs, theirs - ours, ours - theirs
    print(f"  {rule:28} both {len(both):3}  clippy only {len(only_clippy):3}  codegraph only {len(only_ours):3}")
    for file, line in sorted(only_clippy):
        why = "  (dropped by the reachability filter)" if (file, line) in dropped else ""
        print(f"      clippy only    {file}:{line}{why}")
    for file, line in sorted(only_ours):
        print(f"      codegraph only {file}:{line}")


async def main(crates: list[str]) -> int:
    await neo4j.connect()
    await neo4j.apply_schema()
    repo = GraphRepository()
    try:
        for arg in crates:
            crate = Path(arg)
            print(crate.name)
            clippy = run_clippy(crate)
            ours, dropped, all_panics = await codegraph_sites(crate, repo)
            for rule in SITE_NODES:
                report(crate.name, rule, ours.get(rule, set()), clippy.get(rule, set()),
                       dropped.get(rule, set()))
            removed = clippy.get("panic-reachable-from-entry", set()) & dropped.get("panic-reachable-from-entry", set())
            print(f"  reachability filter: {len(removed)} of {len(clippy.get('panic-reachable-from-entry', ()))} "
                  f"clippy panic sites are unreachable or in tests ({len(all_panics)} panic sites in the graph)")
    finally:
        await neo4j.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
