"""Entry-point reachability, read once per analysis run and shared by the rules that need paths.

Ingestion sets `entry_distance` on every function (breadth-first from the entry points over
CALLS and REFERENCES, see GraphRepository.mark_reachability). This helper reconstructs one
shortest path from an entry point to any reachable function, so a finding can carry the chain
`entry -> ... -> function` as evidence without a variable-length graph query per finding.
"""
from dataclasses import dataclass, field

from app.graph.repository import GraphRepository

QUERY = """
MATCH (f:Function {project_id: $pid}) WHERE f.entry_distance IS NOT NULL
OPTIONAL MATCH (c:Function {project_id: $pid})-[:CALLS|REFERENCES]->(f)
WHERE c.entry_distance = f.entry_distance - 1
WITH f, min(c.id) AS pred
RETURN f.id AS id, f.qualified_name AS qname, f.entry_distance AS distance, f.entry_kind AS entry_kind,
       pred, coalesce(f.in_test, false) AS in_test
"""


@dataclass
class ReachableFunction:
    id: str
    qname: str
    distance: int
    entry_kind: str | None
    pred: str | None
    in_test: bool


@dataclass
class Reach:
    functions: dict[str, ReachableFunction] = field(default_factory=dict)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self.functions

    def distance(self, node_id: str) -> int | None:
        fn = self.functions.get(node_id)
        return fn.distance if fn else None

    def path_to(self, node_id: str) -> list[str]:
        """Node ids from an entry point to `node_id`, inclusive; empty when it is not reachable."""
        chain: list[str] = []
        current: str | None = node_id
        while current is not None and current in self.functions and len(chain) <= 64:
            chain.append(current)
            current = self.functions[current].pred
        return list(reversed(chain))

    def entry_of(self, node_id: str) -> ReachableFunction | None:
        path = self.path_to(node_id)
        return self.functions[path[0]] if path else None

    def describe(self, node_id: str) -> str:
        """A predicate: `reachable from main (main) in 2 calls`, `an entry point (handler)`,
        `not reachable from an entry point`. Callers prefix it with `is`."""
        fn = self.functions.get(node_id)
        if fn is None:
            return "not reachable from an entry point"
        entry = self.entry_of(node_id)
        if fn.distance == 0 or entry is None:
            return f"an entry point ({fn.entry_kind})"
        calls = "call" if fn.distance == 1 else "calls"
        return f"reachable from {entry.qname} ({entry.entry_kind}) in {fn.distance} {calls}"


async def load_reach(repo: GraphRepository, project_id: str) -> Reach:
    rows = await repo.query(QUERY, pid=project_id)
    return Reach({r["id"]: ReachableFunction(r["id"], r["qname"], r["distance"], r["entry_kind"], r["pred"],
                                             r["in_test"]) for r in rows})
