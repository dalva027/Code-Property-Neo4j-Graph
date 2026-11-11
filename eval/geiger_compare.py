"""Phase 2 comparison: codegraph's unsafe counts per crate against cargo-geiger.

cargo-geiger counts, per crate and split into used/unused by the build: unsafe free functions
(foreign fn declarations included), unsafe methods, unsafe expressions, unsafe impls and unsafe
traits. codegraph counts syntactically per file and sums per workspace member. The comparison:

    geiger functions + methods  ==  codegraph unsafe_fns + foreign_fns
    geiger item_impls           ==  codegraph unsafe_impls
    geiger item_traits          ==  codegraph unsafe_traits
    geiger exprs                     shown next to codegraph unsafe_blocks, not compared: geiger counts
                                     every expression inside unsafe code, codegraph counts blocks

Known differences: codegraph counts everything in the source tree, geiger only what the build
includes, so `#[cfg]`-excluded code and unbuilt targets show up as codegraph-only.

Usage, with a cargo-geiger JSON report produced in the crate directory:

    scripts/cargo-docker geiger --output-format Json > geiger.json       # needs the crate to build
    cd backend && .venv/bin/python ../eval/geiger_compare.py <crate dir> <geiger.json>
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.db import neo4j
from app.graph.repository import GraphRepository
from app.services.ingest import build_and_store

# (label, geiger keys summed, codegraph keys summed, compared?)
COUNTS = (
    ("functions", ("functions", "methods"), ("unsafe_fns", "foreign_fns"), True),
    ("impls", ("item_impls",), ("unsafe_impls",), True),
    ("traits", ("item_traits",), ("unsafe_traits",), True),
    ("exprs/blocks", ("exprs",), ("unsafe_blocks",), False),
)
OUR_KEYS = ("unsafe_fns", "foreign_fns", "unsafe_blocks", "unsafe_impls", "unsafe_traits")


def geiger_counts(report: dict) -> dict[str, dict[str, int]]:
    """{crate name: {geiger key: unsafe count}} summing geiger's used and unused counts."""
    out: dict[str, dict[str, int]] = {}
    for pkg in report.get("packages", []):
        name = pkg["package"]["id"]["name"]
        counts = pkg.get("unsafety", {})
        total: dict[str, int] = {}
        for key in ("functions", "methods", "exprs", "item_impls", "item_traits"):
            total[key] = sum(counts.get(part, {}).get(key, {}).get("unsafe_", 0) for part in ("used", "unused"))
        out[name] = total
    return out


async def codegraph_counts(crate: Path, repo: GraphRepository) -> dict[str, dict[str, int]]:
    project = await repo.create_project(f"geiger:{crate.name}", crate.resolve().as_posix())
    try:
        await build_and_store(project, repo)
        await repo.mark_scan_finished(project.id)
        fields = ", ".join(f"c.{k} AS {k}" for k in OUR_KEYS)
        rows = await repo.query(
            f"MATCH (c:Crate {{project_id: $pid, workspace_member: true}}) RETURN c.name AS name, {fields}",
            pid=project.id)
        if not rows:                                        # no Cargo.lock: fall back to file totals
            sums = ", ".join(f"sum(coalesce(f.{k}, 0)) AS {k}" for k in OUR_KEYS)
            rows = await repo.query(
                f"MATCH (f:File {{project_id: $pid, language: 'rust'}}) RETURN $name AS name, {sums}",
                pid=project.id, name=crate.name)
        return {r["name"]: {k: r[k] or 0 for k in OUR_KEYS} for r in rows}
    finally:
        await repo.delete_project(project.id)


async def main(crate: str, report_path: str) -> int:
    geiger = geiger_counts(json.loads(Path(report_path).read_text()))
    await neo4j.connect()
    await neo4j.apply_schema()
    try:
        ours = await codegraph_counts(Path(crate), GraphRepository())
    finally:
        await neo4j.close()
    ok = True
    print(f"{'crate':24} {'metric':13} {'geiger':>7} {'codegraph':>10}")
    for name, counts in sorted(ours.items()):
        theirs = geiger.get(name) or geiger.get(name.replace("_", "-")) or {}
        for label, g_keys, our_keys, compared in COUNTS:
            g = sum(theirs.get(k, 0) for k in g_keys) if theirs else "-"
            o = sum(counts[k] for k in our_keys)
            if not compared:
                flag = "  (not comparable)"
            elif g == o:
                flag = ""
            else:
                flag, ok = "  <- differs", False
            print(f"{name:24} {label:13} {g!s:>7} {o:>10}{flag}")
    print("OK" if ok else "DIFFERS")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    raise SystemExit(asyncio.run(main(sys.argv[1], sys.argv[2])))
