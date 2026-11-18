"""A finding's evidence (an ordered list of node ids) turned into a walkable path.

Each analyzer stores the nodes that justify a finding, in order: the entry point's call chain and
then the site, the hops of a taint flow from source to sink, or member crate to advisory. This
module resolves those ids against the graph, finds the stored edge between each step and the next,
and names each step in words, for the UI's path explorer and for SARIF code flows.
"""
from app.graph.repository import GraphRepository
from app.models.analysis import Finding
from app.models.graph import EdgeKind, GraphEdge, GraphNode, NodeKind
from app.models.views import Evidence, EvidenceStep

# When two steps are joined by several edges, the most specific one explains the hop.
_EDGE_RANK = {kind: i for i, kind in enumerate([
    EdgeKind.flows_to, EdgeKind.passes, EdgeKind.returns_to, EdgeKind.calls, EdgeKind.references,
    EdgeKind.has_call, EdgeKind.targets, EdgeKind.declares, EdgeKind.contains, EdgeKind.has_literal,
    EdgeKind.from_crate, EdgeKind.depends_on, EdgeKind.affected_by, EdgeKind.uses, EdgeKind.has_file,
    EdgeKind.implements, EdgeKind.inherits, EdgeKind.imports,
])}


def _pick(edges: list[GraphEdge]) -> dict[tuple[str, str], GraphEdge]:
    best: dict[tuple[str, str], GraphEdge] = {}
    for edge in edges:
        key = (edge.source, edge.target)
        if key not in best or _EDGE_RANK.get(edge.kind, 99) < _EDGE_RANK.get(best[key].kind, 99):
            best[key] = edge
    return best


async def load_evidence(repo: GraphRepository, project_id: str, finding: Finding) -> Evidence:
    nodes = await repo.resolve_nodes(project_id, finding.evidence)
    present = [i for i in finding.evidence if i in nodes]
    best = _pick(await repo.edges_among(project_id, present)) if len(present) > 1 else {}
    steps = []
    for i, node_id in enumerate(present):
        node, owner = nodes[node_id]
        edge = None
        if i + 1 < len(present):
            nxt = present[i + 1]
            edge = best.get((node_id, nxt)) or best.get((nxt, node_id))
        steps.append(EvidenceStep(node=node, owner=owner, edge=edge))
    return Evidence(finding=finding, steps=steps, missing=[i for i in finding.evidence if i not in nodes])


def describe(node: GraphNode, owner: GraphNode | None = None) -> str:
    """One step in words: `parameter `path` of app::serve`, `call to std::process::Command::new`."""
    of = f" of {owner.qualified_name}" if owner is not None and owner.kind == NodeKind.function else ""
    inside = f" in {owner.qualified_name}" if of else ""
    attrs = node.attrs
    match node.kind:
        case NodeKind.var:
            if node.subkind == "param":
                return f"parameter `{node.name}`{of}"
            if node.subkind == "ret":
                return f"return value{of}"
            return f"`{node.name}`{inside}"
        case NodeKind.call:
            if node.subkind in ("index", "arith"):
                what = "index operation" if node.subkind == "index" else "integer arithmetic"
                return f"{what}{inside}"
            if node.subkind == "struct":
                return f"struct literal {node.name}{inside}"
            return f"call to {attrs.get('callee_path', node.name)}{inside}"
        case NodeKind.function:
            entry = attrs.get("entry_kind")
            return f"{node.qualified_name} ({entry} entry point)" if entry else node.qualified_name
        case NodeKind.external:
            return f"{node.qualified_name} (outside the project)"
        case NodeKind.unsafe:
            return f"unsafe {node.subkind}{inside}"
        case NodeKind.literal:
            return f"string literal{inside}"
        case NodeKind.crate:
            return f"crate {node.name} {attrs.get('version', '')}".rstrip()
        case NodeKind.advisory:
            title = attrs.get("title")
            return f"{node.name}: {title}" if title else node.name
        case _:
            return node.qualified_name
