from enum import Enum

from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    file = "file"
    class_ = "class"
    function = "function"


class EdgeKind(str, Enum):
    contains = "CONTAINS"
    imports = "IMPORTS"
    calls = "CALLS"
    inherits = "INHERITS"
    implements = "IMPLEMENTS"


class GraphNode(BaseModel):
    id: str                       # "<project_id>:<qualified_name>"
    kind: NodeKind
    name: str
    qualified_name: str
    file: str                     # path relative to the project root
    line_start: int = 0
    line_end: int = 0
    language: str = "python"
    subkind: str | None = None    # e.g. "struct", "trait", "method"; None when kind says it all
    metrics: dict[str, float] = Field(default_factory=dict)  # loc, complexity, methods, ...


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: EdgeKind


class CodeGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
