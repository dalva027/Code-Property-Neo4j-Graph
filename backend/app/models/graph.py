from enum import Enum

from pydantic import BaseModel, Field

# Values a node attribute or edge property may hold; Neo4j stores all of these natively.
Scalar = str | bool | int | float
AttrValue = Scalar | list[str]


class NodeKind(str, Enum):
    file = "file"
    class_ = "class"
    function = "function"
    external = "external"         # something called but not defined in the project (std, crates, macros)
    crate = "crate"               # a package in Cargo.lock: a workspace member or a dependency
    advisory = "advisory"         # a RustSec advisory; global, shared by every project it affects
    # Security facts (docs/build-plan.md section 5.1), produced by the parsers
    unsafe = "unsafe"             # an `unsafe` block, fn, impl or trait span
    call = "call"                 # one call site of interest: an index/arith op or a catalogue match
    literal = "literal"           # a string literal that looks like a secret (redacted; value never stored)
    # Data flow (docs/build-plan.md section 5.4), produced by the rust-analyzer extractor
    var = "var"                   # a parameter, local or return value of a function


class EdgeKind(str, Enum):
    contains = "CONTAINS"
    imports = "IMPORTS"
    calls = "CALLS"
    inherits = "INHERITS"
    implements = "IMPLEMENTS"     # {unsafe} for `unsafe impl`
    references = "REFERENCES"     # (Function)->(Function|External) passed as a value {via, line}
    has_call = "HAS_CALL"         # (Function)->(Call)
    targets = "TARGETS"           # (Call)->(External)
    has_literal = "HAS_LITERAL"   # (Function|File)->(Literal)
    declares = "DECLARES"         # (Function)->(Var)
    flows_to = "FLOWS_TO"         # (Var|Call)->(Var|Call) inside one function {via, vias}
    passes = "PASSES"             # (Var|Call)->(Var param of the callee) {via: "arg:<i>"}
    returns_to = "RETURNS_TO"     # (Var ret of the callee)->(Call)
    # Dependency graph (app/graph/deps.py)
    depends_on = "DEPENDS_ON"     # (Crate)->(Crate) {kind}
    affected_by = "AFFECTED_BY"   # (Crate)->(Advisory) {kind, functions}
    has_file = "HAS_FILE"         # (Crate)->(File), workspace members only
    uses = "USES"                 # (File)->(Crate), named in `use` / `extern crate`
    from_crate = "FROM_CRATE"     # (External)->(Crate)


# Edges the code graph builder emits; the rest come from the dependency scan.
CODE_EDGE_KINDS = (EdgeKind.contains, EdgeKind.imports, EdgeKind.calls, EdgeKind.inherits, EdgeKind.implements,
                   EdgeKind.references, EdgeKind.has_call, EdgeKind.targets, EdgeKind.has_literal,
                   EdgeKind.declares, EdgeKind.flows_to, EdgeKind.passes, EdgeKind.returns_to)
# The edges taint paths run over.
FLOW_EDGE_KINDS = (EdgeKind.flows_to, EdgeKind.passes, EdgeKind.returns_to)


class GraphNode(BaseModel):
    id: str                       # "<project_id>:<qualified_name>"
    kind: NodeKind
    name: str
    qualified_name: str           # dotted for project symbols; the `::` path for externals
    file: str = ""                # path relative to the project root; "" for externals
    line_start: int = 0
    line_end: int = 0
    language: str = "python"
    subkind: str | None = None    # e.g. "struct", "trait", "method", "macro"; None when kind says it all
    metrics: dict[str, int | float] = Field(default_factory=dict)  # loc, complexity, methods, ...
    # Non-numeric facts (an external's `path`/`crate`/`is_macro`, later visibility, abi, ...).
    attrs: dict[str, AttrValue] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: EdgeKind
    props: dict[str, AttrValue] = Field(default_factory=dict)   # CALLS {line, count}, AFFECTED_BY {kind, functions}


class CodeGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
