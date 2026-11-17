"""Taint paths over the data-flow graph, shared by every rule that asks "does input reach this?".

The graph (built from the rust-analyzer extractor's facts, see app/graph/facts.py) has a `Var`
node per parameter, local and return value and a `Call` node per call site, connected by
`FLOWS_TO` (inside a function), `PASSES` (an argument to the callee's parameter) and `RETURNS_TO`
(the callee's return value to the call site). A taint finding is a path over those edges from a
source to a node that flows into a sink's sensitive argument, on which no node is blocked:

- a sanitizer call of the rule (`callee_path` in the rule's sanitizer list);
- a variable carrying one of the rule's guards (a `starts_with` check, a bounds comparison, ...);
- for rules that inject text, a value of a numeric or bool type, which cannot carry a payload.

Sources come from the catalogue: calls whose result is untrusted (`std::env::args`), parameters
declared with a web-framework extractor type, and, in a library crate, the parameters of its
`pub` functions (lower confidence: whether they are attacker-controlled depends on the caller).

The search is a breadth-first expansion from all sources at once, one Cypher statement per level
with the blocking conditions in its WHERE clause, so blocked nodes are never expanded and the
cost is linear in the flow edges. (A single `SHORTEST` path pattern per sink says the same thing
in one statement and is how a path is best explored by hand in the Neo4j browser; as a rule over a
whole project it did not finish on graphs with cycles, where the level-wise form takes
milliseconds.)
"""
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.graph.repository import GraphRepository
from app.rules import Catalogue, PathMatcher, load_catalogue

MAX_HOPS = 16
# Types that cannot carry an injected string.
TEXT_BLOCKED = ["int", "float", "bool", "unit", "never", "char"]
# For lengths, sizes and indexes only a bool or unit ends the taint.
NUMBER_BLOCKED = ["bool", "unit", "never"]
ANY_VIA = ["recv", "macro", *(f"arg:{i}" for i in range(12))]
# Source groups whose data is attacker-controlled without further assumptions.
UNTRUSTED_FILES = "files"
WEAK_GROUP = "reader"
# Parameter types that hold undecoded data: byte and text buffers.
RAW_DATA = {"slice", "array", "str", "std::string::String", "std::vec::Vec", "std::ffi::OsString", "std::ffi::OsStr",
            "std::ffi::CStr", "std::ffi::CString", "std::path::Path", "std::path::PathBuf", "std::borrow::Cow",
            "bytes::Bytes", "bytes::BytesMut", "std::io::Cursor", "pointer", "generic"}

# A call that writes through a `&mut` argument passes data on whatever it returns: `read(&mut buf)`
# returns a count, and the bytes are in `buf`.
_OK = ("NOT coalesce({n}.callee_path, '') IN $blocked_paths "
       "AND (coalesce({n}.writes_out, false) "
       "     OR NOT coalesce({n}.ty_kind, {n}.ret_kind, 'other') IN $blocked_kinds) "
       "AND none(g IN coalesce({n}.guards, []) WHERE g IN $guards)")

# The analysis is field-insensitive: a value stored in one field taints the whole struct. For the
# rules about numbers, only a number may enter a struct literal, so a tainted `name` does not make
# `price` look tainted when it is read back. (A struct that is input as a whole, a deserialized
# request body, never passes a struct literal and keeps all its fields tainted.)
_FIELD = ("(NOT $numbers OR coalesce(n.subkind, '') <> 'struct' "
          "OR coalesce(a.ty_kind, a.ret_kind, 'other') IN ['int', 'float', 'char'])")

# Which of these nodes may carry taint at all (a source can itself be guarded or sanitized).
ALLOWED = f"""
CALL () {{
  MATCH (n:Var) WHERE n.id IN $ids RETURN n
  UNION ALL
  MATCH (n:Call) WHERE n.id IN $ids RETURN n
}}
WITH n WHERE {_OK.format(n="n")}
RETURN n.id AS id
"""

# One breadth-first level: everything the frontier flows into that is not blocked.
STEP = f"""
CALL () {{
  MATCH (a:Var) WHERE a.id IN $frontier RETURN a
  UNION ALL
  MATCH (a:Call) WHERE a.id IN $frontier RETURN a
}}
MATCH (a)-[r:FLOWS_TO|PASSES|RETURNS_TO]->(n:Var|Call)
WHERE {_OK.format(n="n")} AND {_FIELD}
RETURN a.id AS source, n.id AS target, r.via AS via
"""

# The nodes that flow into a sink at one of the argument positions that matter.
ARRIVALS = """
UNWIND $sinks AS s
MATCH (sink:Call {id: s.id})
MATCH (x:Var|Call)-[l:FLOWS_TO]->(sink)
WHERE any(v IN l.vias WHERE v IN s.vias)
RETURN sink.id AS sink, x.id AS x
"""

CALL_PATHS = "MATCH (c:Call {project_id: $pid}) RETURN DISTINCT c.callee_path AS path"
PARAM_TYPES = ("MATCH (v:Var {project_id: $pid, subkind: 'param'}) WHERE v.param_type IS NOT NULL "
               "RETURN DISTINCT v.param_type AS path")
SOURCES = """
MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(c:Call)
WHERE c.callee_path IN $paths AND NOT coalesce(f.in_test, false)
RETURN c.id AS id, c.callee_path AS what, 'call' AS how, f.qualified_name AS fn, c.line_start AS line,
       'other' AS kind
UNION ALL
MATCH (f:Function {project_id: $pid})-[:DECLARES]->(v:Var {subkind: 'param'})
WHERE v.param_type IN $types AND NOT coalesce(f.in_test, false)
RETURN v.id AS id, v.param_type AS what, 'type' AS how, f.qualified_name AS fn, v.line_start AS line,
       coalesce(v.type_path, v.ty_kind, 'other') AS kind
UNION ALL
MATCH (f:Function {project_id: $pid, entry_kind: 'pub_api'})-[:DECLARES]->(v:Var {subkind: 'param'})
WHERE NOT coalesce(f.in_test, false)
RETURN v.id AS id, v.name AS what, 'pub_api' AS how, f.qualified_name AS fn, v.line_start AS line,
       coalesce(v.type_path, v.ty_kind, 'other') AS kind
"""


@dataclass(frozen=True)
class Source:
    id: str
    how: str            # "call" | "type" | "pub_api"
    what: str           # the called path, the parameter type, or the parameter name
    group: str          # catalogue group: env, stdin, network, axum, ... or "pub_api"
    function: str
    line: int | None
    kind: str = "other"  # type path of a parameter source: "slice", "str", "std::vec::Vec", "u32", ...

    @property
    def trusted_caller(self) -> bool:
        """A weak source: a library's public parameter (its fields, for `self`), tainted only if
        the calling program passes input in, or bytes from a reader of unknown kind."""
        return self.how == "pub_api" or self.group == WEAK_GROUP

    @property
    def structured(self) -> bool:
        """A public parameter of a library that is not raw data: a number, a struct, a handle.
        Rules about lengths, sizes and arithmetic do not start there. A number the caller passes
        (or a field of a value the caller built) is the caller's to validate, and otherwise every
        `pub fn area(w: u32, h: u32)` would be an overflow finding. They do start at a buffer or a
        string the library is given: a number it decodes from those is the library's to check."""
        return self.how == "pub_api" and (self.what == "self" or self.kind not in RAW_DATA)

    def describe(self) -> str:
        if self.how == "call":
            return f"{self.what} (called in {self.function})"
        if self.how == "type":
            return f"the {self.what} parameter of {self.function}"
        if self.what == "self":
            return f"the fields of `self` in the public function {self.function}"
        return f"parameter `{self.what}` of the public function {self.function}"


@dataclass(frozen=True)
class Hit:
    sink: str
    path: list[str]             # node ids, source first; the last one flows into the sink
    vias: list[str]
    source: Source

    @property
    def through_dispatch(self) -> bool:
        return "dispatch" in self.vias

    @property
    def hops(self) -> int:
        return len(self.path)


@dataclass
class Flow:
    """Per-project inputs every taint rule needs, loaded once per analysis run."""
    catalogue: Catalogue
    matcher: PathMatcher
    call_paths: list[str]
    sources: dict[str, Source]

    def paths_in(self, section: str, group: str) -> list[str]:
        """Called paths of this project that match a catalogue group."""
        return [p for p in self.call_paths if any(m.group == group for m in self.matcher.match(p, section))]


async def load_flow(repo: GraphRepository, project_id: str) -> Flow:
    key = ("flow", project_id)
    if key in repo.memo:
        return repo.memo[key]
    catalogue = load_catalogue()
    matcher = catalogue.matcher()
    call_paths = sorted(r["path"] for r in await repo.query(CALL_PATHS, pid=project_id) if r["path"])
    param_types = [r["path"] for r in await repo.query(PARAM_TYPES, pid=project_id)]

    def group_of(path: str, kind: str) -> str | None:
        for m in matcher.match(path, "sources"):
            trusted = m.group == UNTRUSTED_FILES and not settings.taint_files_are_untrusted
            if m.entry.kind == kind and not trusted:
                return m.group
        return None

    call_groups = {p: g for p in call_paths if (g := group_of(p, "call"))}
    type_groups = {p: g for p in param_types if (g := group_of(p, "type"))}
    sources: dict[str, Source] = {}
    rows = await repo.query(SOURCES, pid=project_id, paths=list(call_groups), types=list(type_groups))
    for r in rows:
        group = {"call": call_groups, "type": type_groups}.get(r["how"], {}).get(r["what"], "pub_api")
        # A parameter that is both an extractor and a public parameter is an extractor.
        if r["id"] not in sources or sources[r["id"]].how == "pub_api":
            sources[r["id"]] = Source(r["id"], r["how"], r["what"], group, r["fn"], r["line"], r["kind"])
    flow = repo.memo[key] = Flow(catalogue, matcher, call_paths, sources)
    return flow


async def _spread(repo: GraphRepository, start: list[str], params: dict[str, Any],
                  claimed: set[str]) -> dict[str, tuple[str | None, str]]:
    """Breadth-first expansion from `start` over the flow edges, one Cypher statement per level.
    Returns {node id: (predecessor id, via)} for everything reached, the start nodes included
    (predecessor None). Nodes in `claimed` belong to an earlier, stronger search and are left alone.
    """
    if not start:
        return {}
    allowed = {r["id"] for r in await repo.query(ALLOWED, ids=start, **params)}
    reached: dict[str, tuple[str | None, str]] = {n: (None, "") for n in start if n in allowed and n not in claimed}
    frontier = list(reached)
    for _ in range(MAX_HOPS):
        if not frontier:
            break
        fresh: list[str] = []
        for r in await repo.query(STEP, frontier=frontier, **params):
            target = r["target"]
            if target not in reached and target not in claimed:
                reached[target] = (r["source"], r["via"] or "")
                fresh.append(target)
        frontier = fresh
    return reached


async def taint_paths(repo: GraphRepository, flow: Flow, sinks: Iterable[dict[str, Any]], *,
                      blocked_paths: Iterable[str] = (), blocked_kinds: Iterable[str] = NUMBER_BLOCKED,
                      guards: Iterable[str] = (), numbers: bool = True) -> dict[str, Hit]:
    """The shortest unblocked path from a source into each sink; sinks without one are absent.

    `sinks` are `{"id": <Call node id>, "vias": [...]}`: the ways a value may arrive (`arg:0`,
    `recv`, `macro`) for the sink to count. `numbers` says the rule is about a numeric value (a
    length, a size, an operand), which leaves out a library's public parameters that are not raw data.

    The search runs forward from all sources at once, level by level, so its cost is linear in the
    flow edges whatever the number of sources and sinks. Real input is spread first and weak
    sources (library parameters, readers of unknown kind) only over what real input did not
    reach, so a sink reachable from both is reported with the stronger source.
    """
    sinks = list(sinks)
    usable = [s for s in flow.sources.values() if not (numbers and s.structured)]
    if not sinks or not usable:
        return {}
    arrivals: dict[str, list[str]] = {}
    for r in await repo.query(ARRIVALS, sinks=sinks):
        arrivals.setdefault(r["sink"], []).append(r["x"])
    if not arrivals:
        return {}
    params = {"blocked_paths": list(blocked_paths), "blocked_kinds": list(blocked_kinds),
              "guards": list(guards), "numbers": numbers}
    strong = await _spread(repo, [s.id for s in usable if not s.trusted_caller], params, set())
    weak = await _spread(repo, [s.id for s in usable if s.trusted_caller], params, set(strong))

    def trace(node: str, reached: dict[str, tuple[str | None, str]]) -> tuple[list[str], list[str]]:
        path, vias = [node], []
        while (step := reached[path[-1]])[0] is not None:
            vias.append(step[1])
            path.append(step[0])
        return path[::-1], vias[::-1]

    hits: dict[str, Hit] = {}
    for sink, nodes in arrivals.items():
        for reached in (strong, weak):
            traces = [trace(x, reached) for x in nodes if x in reached]
            if traces:
                path, vias = min(traces, key=lambda t: len(t[0]))
                hits[sink] = Hit(sink, path, vias, flow.sources[path[0]])
                break
    return hits
