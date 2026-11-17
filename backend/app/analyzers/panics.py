"""Class P: panics and denial of service (docs/build-plan.md section 3).

P1 and P2 come from `Call` nodes (panicking calls are in the catalogue's dangerous_ops.panic
group; index operations are `ops::index`). P5 finds cycles in the call graph with Tarjan's
algorithm over the project's functions, then keeps the ones an entry point reaches and that no
depth-like parameter or comparison guards.
"""
from collections import defaultdict

from app.analyzers import flow
from app.analyzers.base import Analyzer, register
from app.analyzers.reach import Reach, load_reach
from app.graph.repository import GraphRepository
from app.models.analysis import Category, Confidence, Finding, Severity
from app.rules import load_catalogue


class _PanicRule(Analyzer):
    category = Category.panic
    languages = ("rust",)


@register
class PanicReachableFromEntry(_PanicRule):
    rule = "panic-reachable-from-entry"
    severity = Severity.warning
    cwe = ("CWE-248",)
    description = ("A function an entry point reaches calls unwrap, expect or unwrap_unchecked, or invokes panic!, "
                   "unreachable!, todo! or unimplemented!. One finding per function, listing the sites. Test code "
                   "is excluded; functions nothing reaches are not reported.")

    QUERY = """
    MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(c:Call {subkind: 'call'})
    WHERE f.entry_distance IS NOT NULL AND NOT coalesce(f.in_test, false)
    RETURN f.id AS fn, f.qualified_name AS qname, f.file AS file, f.line_start AS fn_line,
           collect({id: c.id, path: c.callee_path, line: c.line_start}) AS sites
    ORDER BY file, fn_line
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        matcher = load_catalogue().matcher()
        reach = await load_reach(repo, project_id)
        findings = []
        for r in await repo.query(self.QUERY, pid=project_id):
            sites = sorted((s for s in r["sites"]
                            if any(m.group == "panic" for m in matcher.match(s["path"], "dangerous_ops"))),
                           key=lambda s: s["line"])
            if not sites:
                continue
            by_name: dict[str, list[int]] = defaultdict(list)
            for s in sites:
                by_name[s["path"].rsplit("::", 1)[-1]].append(s["line"])
            detail = ", ".join(f"{name} at line {', '.join(map(str, lines[:5]))}" for name, lines in by_name.items())
            findings.append(self.finding(
                project_id,
                f"{r['qname']} can panic ({detail}) and is {reach.describe(r['fn'])}",
                node_id=r["fn"], file=r["file"], line=sites[0]["line"], line_end=sites[-1]["line"],
                evidence=[*reach.path_to(r["fn"]), *(s["id"] for s in sites[:20])],
            ))
        return findings


@register
class UncheckedIndex(_PanicRule):
    rule = "unchecked-index"
    severity = Severity.info
    cwe = ("CWE-129",)
    description = ("Indexing a slice, array, Vec or str with a non-literal index (`v[i]`, `s[a..b]`), which "
                   "panics when out of range. One finding per function. With resolved types, maps and other "
                   "Index implementations are left out; a warning when the index is derived from untrusted "
                   "input with no bounds check. Without types every indexing expression counts, at low confidence.")
    version = "2"

    QUERY = """
    MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(c:Call {subkind: 'index'})
    WHERE NOT coalesce(f.in_test, false) AND NOT coalesce(c.base_kind, 'unknown') IN ['map', 'other']
    WITH f, c ORDER BY c.line_start
    RETURN f.id AS fn, f.qualified_name AS qname, f.file AS file, f.line_start AS fn_line,
           f.entry_distance AS distance,
           collect({id: c.id, line: c.line_start, detail: c.detail, typed: c.base_kind IS NOT NULL}) AS sites
    ORDER BY file, fn_line
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        reach = await load_reach(repo, project_id)
        rows = await repo.query(self.QUERY, pid=project_id)
        # Phase 3: an index that comes from untrusted input, unchecked.
        state = await flow.load_flow(repo, project_id)
        tainted = await flow.taint_paths(
            repo, state, ({"id": s["id"], "vias": ["arg:0"]} for r in rows for s in r["sites"]),
            blocked_paths=state.paths_in("sanitizers", "T5"), guards=state.catalogue.guards("T5"),
        )
        findings = []
        for r in rows:
            sites = r["sites"]
            examples = ", ".join(f"[{s['detail']}] at line {s['line']}" for s in sites[:3])
            more = f" and {len(sites) - 3} more" if len(sites) > 3 else ""
            hits = [tainted[s["id"]] for s in sites if s["id"] in tainted and not tainted[s["id"]].source.trusted_caller]
            if hits:
                hit = min(hits, key=lambda h: h.hops)
                findings.append(self.finding(
                    project_id,
                    f"{r['qname']} indexes {examples}{more} with a value derived from {hit.source.describe()} "
                    f"and no bounds check; it is {reach.describe(r['fn'])}",
                    node_id=r["fn"], file=r["file"], line=sites[0]["line"], line_end=sites[-1]["line"],
                    severity=Severity.warning, confidence=Confidence.medium,
                    evidence=[*hit.path, hit.sink],
                ))
                continue
            findings.append(self.finding(
                project_id,
                f"{r['qname']} indexes with a non-literal index {examples}{more}; it is {reach.describe(r['fn'])}",
                node_id=r["fn"], file=r["file"], line=sites[0]["line"], line_end=sites[-1]["line"],
                confidence=Confidence.medium if all(s["typed"] for s in sites) else Confidence.low,
                evidence=[*reach.path_to(r["fn"]), *(s["id"] for s in sites[:20])],
            ))
        return findings


def strongly_connected(nodes: set[str], edges: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan's SCCs, iterative. Returns the components with more than one node or a self-loop."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    for root in sorted(nodes):
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, i = work[-1]
            targets = sorted(edges.get(node, ()))
            if i < len(targets):
                work[-1] = (node, i + 1)
                nxt = targets[i]
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, 0))
                elif nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    if len(component) > 1 or node in edges.get(node, ()):
                        result.append(sorted(component))
    return result


@register
class UnboundedRecursion(_PanicRule):
    rule = "unbounded-recursion"
    severity = Severity.warning
    cwe = ("CWE-674",)
    description = ("A cycle in the call graph (direct or mutual recursion) that an entry point reaches, with no "
                   "depth-like parameter or comparison in any function of the cycle. Recursive parsers and "
                   "decoders on untrusted input overflow the stack this way. One finding per cycle.")
    version = "1"

    QUERY = """
    MATCH (a:Function {project_id: $pid})-[:CALLS]->(b:Function {project_id: $pid})
    RETURN a.id AS source, b.id AS target
    """
    INFO = """
    MATCH (f:Function {project_id: $pid}) WHERE f.id IN $ids
    RETURN f.id AS id, f.qualified_name AS qname, f.file AS file, f.line_start AS line, f.line_end AS line_end,
           coalesce(f.depth_guard, false) AS guarded, coalesce(f.in_test, false) AS in_test,
           f.entry_distance AS distance
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        edges: dict[str, set[str]] = defaultdict(set)
        nodes: set[str] = set()
        for r in await repo.query(self.QUERY, pid=project_id):
            edges[r["source"]].add(r["target"])
            nodes.update((r["source"], r["target"]))
        cycles = strongly_connected(nodes, edges)
        if not cycles:
            return []
        reach: Reach = await load_reach(repo, project_id)
        members = {m for c in cycles for m in c}
        info = {r["id"]: r for r in await repo.query(self.INFO, pid=project_id, ids=sorted(members))}
        findings = []
        for cycle in cycles:
            rows = [info[m] for m in cycle if m in info]
            if not rows or any(r["in_test"] for r in rows) or any(r["guarded"] for r in rows):
                continue
            reachable = [r for r in rows if r["distance"] is not None]
            if not reachable:
                continue
            head = min(reachable, key=lambda r: (r["distance"], r["qname"]))
            names = [r["qname"] for r in sorted(rows, key=lambda r: r["qname"])]
            if len(rows) == 1:
                what = f"{head['qname']} calls itself"
            else:
                shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
                what = f"{len(rows)} functions call each other in a cycle: {shown}"
            findings.append(self.finding(
                project_id,
                f"{what} with no depth limit; {head['qname']} is {reach.describe(head['id'])}",
                node_id=head["id"], file=head["file"], line=head["line"], line_end=head["line_end"],
                confidence=Confidence.medium,
                evidence=[*reach.path_to(head["id"]), *(r["id"] for r in rows if r["id"] != head["id"])],
            ))
        return findings
