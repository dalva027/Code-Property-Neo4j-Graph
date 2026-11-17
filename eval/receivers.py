"""Phase 3 acceptance: how many called externals still have an unknown receiver (`?::name`), with
tree-sitter alone and with the rust-analyzer extractor, and how many call sites come from macro
expansions.

Builds the code graph of each crate twice in memory (no Neo4j): once with CODE_FACTS off and once
with the extractor. Nothing in the crates is built or run; the extractor runs `cargo metadata`,
which downloads dependency sources into the cargo registry.

    cd backend
    export CODEGRAPH_EXTRACTOR=$PWD/../scripts/codegraph-extract-docker
    .venv/bin/python ../eval/receivers.py ../eval/corpus/deps/fd ../eval/corpus/deps/ripgrep ../eval/corpus/deps/zola
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.config import settings
from app.graph.builder import GraphBuilder
from app.models.graph import EdgeKind, NodeKind


def measure(root: Path, mode: str) -> dict:
    settings.code_facts = mode
    builder = GraphBuilder()
    started = time.monotonic()
    graph = builder.build(root, "eval")
    externals = [n for n in graph.nodes if n.kind == NodeKind.external and not n.attrs.get("is_macro")]
    unknown = [n for n in externals if str(n.attrs.get("path", "")).startswith("?::")]
    calls = [e for e in graph.edges if e.kind == EdgeKind.calls]
    by_id = {n.id: n for n in graph.nodes}
    to_unknown = sum(int(e.props.get("count", 1)) for e in calls
                     if str(by_id[e.target].attrs.get("path", "")).startswith("?::"))
    to_external = sum(int(e.props.get("count", 1)) for e in calls
                      if by_id[e.target].kind == NodeKind.external and not by_id[e.target].attrs.get("is_macro"))
    sites = [n for n in graph.nodes if n.kind == NodeKind.call]
    stats = builder.code_facts
    return {
        "seconds": round(time.monotonic() - started, 1),
        "externals": len(externals), "unknown": len(unknown),
        "external_calls": to_external, "unknown_calls": to_unknown,
        "macro_sites": sum(1 for n in sites if n.attrs.get("in_macro")),
        "vars": sum(1 for n in graph.nodes if n.kind == NodeKind.var),
        "flows": sum(1 for e in graph.edges if e.kind in (EdgeKind.flows_to, EdgeKind.passes, EdgeKind.returns_to)),
        "analyzed": f"{stats.analyzed}/{stats.functions}" if stats else "-",
        "warnings": stats.warnings if stats else [],
    }


def share(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "-"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    print(f"{'crate':<12} {'mode':<12} {'externals':>9} {'?:: nodes':>10} {'share':>7} {'ext calls':>9} "
          f"{'?:: calls':>9} {'share':>7} {'macro sites':>11} {'vars':>7} {'flows':>7} {'fns':>10} {'s':>6}")
    worst = 0.0
    for arg in argv:
        root = Path(arg).resolve()
        for mode in ("off", "auto"):
            m = measure(root, mode)
            label = "tree-sitter" if mode == "off" else "extractor"
            print(f"{root.name:<12} {label:<12} {m['externals']:>9} {m['unknown']:>10} "
                  f"{share(m['unknown'], m['externals']):>7} {m['external_calls']:>9} {m['unknown_calls']:>9} "
                  f"{share(m['unknown_calls'], m['external_calls']):>7} {m['macro_sites']:>11} {m['vars']:>7} "
                  f"{m['flows']:>7} {m['analyzed']:>10} {m['seconds']:>6}")
            for warning in m["warnings"][:5]:
                print(f"    warning: {warning}")
            if mode == "auto" and m["externals"]:
                worst = max(worst, m["unknown"] / m["externals"])
    print(f"\nworst `?::` share of External nodes with the extractor: {100 * worst:.1f}% (acceptance: below 10%)")
    return 0 if worst < 0.10 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
