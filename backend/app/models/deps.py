"""Dependency and advisory facts.

`DepsFacts` mirrors the JSON `codegraph-extract deps` prints (extractor/src/facts.rs). The loader in
app/graph/deps.py turns one `DepsFacts` per Cargo.lock into a `DependencyGraph`: Crate and Advisory
nodes plus the edges that tie them to each other and to the code graph.
"""
from pydantic import BaseModel, ConfigDict, Field

DEPS_SCHEMA_VERSION = 1


class CrateFact(BaseModel):
    key: str                                   # name@version
    name: str
    version: str
    source: str                                # registry | git | path | other
    source_id: str | None = None
    checksum: str | None = None


class DepFact(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from")
    to: str


class AdvisoryFact(BaseModel):
    id: str
    package: str
    title: str = ""
    description: str = ""
    date: str = ""
    aliases: list[str] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    cvss: str | None = None
    cvss_score: float | None = None
    severity: str | None = None                # none | low | medium | high | critical (CVSS)
    informational: str | None = None           # unmaintained | unsound | notice | ...
    url: str | None = None
    references: list[str] = Field(default_factory=list)
    withdrawn: str | None = None
    patched: list[str] = Field(default_factory=list)
    unaffected: list[str] = Field(default_factory=list)
    functions: dict[str, list[str]] = Field(default_factory=dict)


class MatchFact(BaseModel):
    advisory: str
    crate_key: str
    kind: str                                  # vulnerability | unmaintained | unsound | notice | yanked
    functions: list[str] = Field(default_factory=list)


class DatabaseInfo(BaseModel):
    path: str = ""
    commit: str | None = None
    commit_time: str | None = None
    advisory_count: int = 0


class DepsFacts(BaseModel):
    schema_version: int
    tool: str = ""
    lockfile: str = ""
    advisory_db: DatabaseInfo | None = None
    crates: list[CrateFact] = Field(default_factory=list)
    deps: list[DepFact] = Field(default_factory=list)
    advisories: list[AdvisoryFact] = Field(default_factory=list)
    matches: list[MatchFact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# -- what gets written to Neo4j -----------------------------------------------------------------
class CrateNode(BaseModel):
    id: str                                    # <project_id>:crate:<name>@<version>
    name: str
    version: str
    source: str
    source_id: str | None = None
    checksum: str | None = None
    workspace_member: bool = False
    manifest_path: str | None = None           # relative to the project root, members only
    lockfile: str                              # relative to the project root
    lockfile_line: int = 0                     # line of `name = "..."` in the [[package]] entry


class DependencyEdge(BaseModel):
    source: str
    target: str
    kind: str | None = None                    # normal | dev | build, known for direct deps of members


class AffectedEdge(BaseModel):
    crate: str
    advisory: str
    kind: str
    functions: list[str] = Field(default_factory=list)


class DependencyGraph(BaseModel):
    crates: list[CrateNode] = Field(default_factory=list)
    depends_on: list[DependencyEdge] = Field(default_factory=list)
    advisories: list[AdvisoryFact] = Field(default_factory=list)
    affected_by: list[AffectedEdge] = Field(default_factory=list)
    crate_files: list[tuple[str, str]] = Field(default_factory=list)     # (member crate id, file id)
    uses: list[tuple[str, str]] = Field(default_factory=list)            # (file id, crate id)
    from_crate: list[tuple[str, str]] = Field(default_factory=list)      # (external id, crate id)
    advisory_db_commit: str | None = None
    warnings: list[str] = Field(default_factory=list)


# -- API responses -------------------------------------------------------------------------------
class AdvisoryInfo(BaseModel):
    id: str
    package: str
    title: str = ""
    description: str = ""                      # markdown, as RustSec writes it
    date: str = ""
    kind: str = "vulnerability"                # vulnerability | unmaintained | unsound | notice
    severity: str | None = None
    cvss_score: float | None = None
    url: str | None = None
    aliases: list[str] = Field(default_factory=list)
    patched: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)


class CrateRef(BaseModel):
    id: str
    name: str
    version: str


class ProjectAdvisory(BaseModel):
    advisory: AdvisoryInfo
    crates: list[CrateRef]


class ReachingFunction(BaseModel):
    function: str                              # node id
    qualified_name: str
    file: str
    line: int                                  # the first call site
    path: str                                  # the called external path
    affected: bool                             # the path is one of the advisory's affected functions
    external: str = ""                         # node id of the called External
    # Every call site's line, where the graph has per-site Call nodes (always with the extractor;
    # without it only for calls the catalogue names). Empty otherwise: `line` is then the only one.
    sites: list[int] = Field(default_factory=list)
    entry_distance: int | None = None          # calls from the nearest entry point; None = unreachable


class AffectedCrateRadius(BaseModel):
    crate: CrateRef
    kind: str
    # Shortest dependency path from each workspace member that depends on the crate, member first.
    paths: list[list[CrateRef]]
    functions: list[ReachingFunction]
    importing_files: list[str]


class BlastRadius(BaseModel):
    project_id: str
    advisory: AdvisoryInfo
    crates: list[AffectedCrateRadius]
