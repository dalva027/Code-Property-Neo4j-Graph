from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.models.graph import GraphEdge, GraphNode


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"


class Finding(BaseModel):
    id: str
    project_id: str
    rule: str
    severity: Severity
    message: str
    node_id: str | None = None
    file: str | None = None
    line: int | None = None


class RuleInfo(BaseModel):
    rule: str
    severity: Severity
    description: str


class Project(BaseModel):
    id: str
    name: str
    root: str
    file_count: int = 0
    symbol_count: int = 0
    created_at: datetime


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    path: str = Field(description="Directory path relative to REPOS_ROOT")


class AnalysisReport(BaseModel):
    project_id: str
    total: int
    by_severity: dict[Severity, int]
    by_rule: dict[str, int]


class NodeDetail(BaseModel):
    node: GraphNode
    incoming: list[GraphEdge]
    outgoing: list[GraphEdge]
    findings: list[Finding]
