from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.models.graph import GraphEdge, GraphNode


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class Category(str, Enum):
    """What a rule is about. Everything but `quality` is one of the five vulnerability classes."""

    quality = "quality"           # code health: cycles, complexity, dead code
    unsafe = "unsafe"             # class U: unsafe code
    panic = "panic"               # class P: panics and denial of service
    injection = "injection"       # class T: taint-based injection
    dependency = "dependency"     # class D: vulnerable and risky dependencies
    crypto = "crypto"             # class C: cryptography and secrets


SECURITY_CATEGORIES = frozenset(Category) - {Category.quality}


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Finding(BaseModel):
    id: str
    project_id: str
    rule: str
    severity: Severity
    message: str
    node_id: str | None = None
    file: str | None = None
    line: int | None = None
    line_end: int | None = None
    category: Category = Category.quality
    confidence: Confidence = Confidence.high
    cwe: list[str] = Field(default_factory=list)          # e.g. ["CWE-78"]
    # Ordered node ids that justify the finding: entry -> ... -> sink, or crate -> ... -> advisory.
    evidence: list[str] = Field(default_factory=list)
    rule_version: str | None = None


class RuleInfo(BaseModel):
    rule: str
    severity: Severity
    description: str
    category: Category
    cwe: list[str] = Field(default_factory=list)
    languages: list[str] | None = Field(None, description="None means the rule runs for every language")
    version: str


class RuleCatalogueInfo(BaseModel):
    """The registered rules plus the version of the pattern catalogue they read."""

    catalogue_version: str
    catalogue_digest: str = Field(description="sha256 over the catalogue files, for reproducible runs")
    rules: list[RuleInfo]


class ScanState(str, Enum):
    scanning = "scanning"
    ready = "ready"
    failed = "failed"


class Project(BaseModel):
    id: str
    name: str
    root: str
    file_count: int = 0
    symbol_count: int = 0
    created_at: datetime
    # Projects stored before background scans existed have none of these and read back as ready.
    status: ScanState = ScanState.ready
    error: str | None = None
    scan_started_at: datetime | None = None
    scan_finished_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)       # e.g. "Cargo.toml has no Cargo.lock"
    advisory_db_commit: str | None = None                   # RustSec database used by the last scan


class ScanStatus(BaseModel):
    project_id: str
    status: ScanState
    error: str | None = None
    scan_started_at: datetime | None = None
    scan_finished_at: datetime | None = None
    file_count: int = 0
    symbol_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    advisory_db_commit: str | None = None


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    path: str = Field(description="Directory path relative to REPOS_ROOT")


class RepoDir(BaseModel):
    """A directory under REPOS_ROOT that the UI can offer as a scan target."""

    name: str
    path: str = Field(description="Directory path relative to REPOS_ROOT, posix separators")
    source_files: int = Field(0, description="Files a registered parser can read, recursively")
    has_subdirs: bool = False
    is_git: bool = False
    project_id: str | None = Field(None, description="Set when a project already points here")
    project_name: str | None = None


class RepoListing(BaseModel):
    path: str = Field(description="The directory that was listed; empty string for REPOS_ROOT")
    dirs: list[RepoDir]


class AnalysisReport(BaseModel):
    project_id: str
    total: int
    by_severity: dict[Severity, int]
    by_rule: dict[str, int]
    by_category: dict[Category, int] = Field(default_factory=dict)
    catalogue_version: str | None = None


class NodeDetail(BaseModel):
    node: GraphNode
    incoming: list[GraphEdge]
    outgoing: list[GraphEdge]
    findings: list[Finding]
