"""Responses behind the UI's views: a finding's evidence path, a slice of a source file, and the
dependency graph (docs/build-plan.md, phase 4)."""
from typing import Literal

from pydantic import BaseModel, Field

from app.models.analysis import Finding, Severity
from app.models.graph import GraphEdge, GraphNode


class EvidenceStep(BaseModel):
    node: GraphNode
    # The function (or file) that holds a variable, call site, unsafe span or literal; the canvas
    # shows the owner, because it only draws files and symbols.
    owner: GraphNode | None = None
    # The stored edge from this step to the next one, in either direction (`source`/`target` say
    # which). None for the last step, and where the evidence lists sites side by side (the several
    # sinks of one finding) rather than a hop.
    edge: GraphEdge | None = None


class Evidence(BaseModel):
    finding: Finding
    steps: list[EvidenceStep]
    missing: list[str] = Field(default_factory=list, description="evidence ids no longer in the graph")


class SourceFlag(BaseModel):
    line: int
    line_end: int
    kind: Literal["finding", "unsafe", "safety"]
    severity: Severity | None = None
    rule: str | None = None
    message: str | None = None
    finding_id: str | None = None
    node_id: str | None = None


class SourceSlice(BaseModel):
    path: str = Field(description="relative to the project root, posix separators")
    language: str
    start: int = Field(description="first line served, 1-based")
    end: int = Field(description="last line served, inclusive")
    total_lines: int
    lines: list[str]
    # Findings and unsafe spans that overlap the slice, and the comment lines that carry a SAFETY note.
    flags: list[SourceFlag]


class DependencyView(BaseModel):
    nodes: list[GraphNode] = Field(description="Crate nodes, and the Advisory nodes affecting them")
    edges: list[GraphEdge] = Field(description="DEPENDS_ON between crates, AFFECTED_BY to advisories")
    # Files of each workspace member, so findings in code can be counted per crate.
    crate_files: dict[str, list[str]] = Field(default_factory=dict)
