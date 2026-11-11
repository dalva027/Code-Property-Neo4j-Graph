"""Dependency graph for Cargo projects: crates, dependency edges, advisories, and how the code uses them.

For every Cargo.lock under the project root this runs `codegraph-extract deps`, which matches the
lockfile against the RustSec database exactly as cargo-audit does. When the binary is missing or
fails, the lockfile is parsed here instead, so crates and dependency edges still exist, just without
advisories. Everything else is plain Python over files and the code graph:

- workspace members are the path crates whose Cargo.toml lives under the lockfile's directory;
- direct dependencies of members get their kind (normal, dev, build) from the member's Cargo.toml,
  including renamed dependencies (`foo = { package = "bar" }`);
- every Rust file belongs to the member whose manifest directory is its longest path prefix;
- `(File)-[:USES]->(Crate)` for crates a file names in `use` / `extern crate`, and
  `(External)-[:FROM_CRATE]->(Crate)` for called paths whose first segment names a crate, both
  resolved within the dependency closure of the file's member, so two versions of one crate stay apart.
"""
import json
import logging
import os
import shutil
import subprocess
import threading
import tomllib
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from app.config import settings
from app.graph.builder import IGNORED_DIRS
from app.models.deps import (
    DEPS_SCHEMA_VERSION,
    AffectedEdge,
    CrateFact,
    CrateNode,
    DependencyEdge,
    DependencyGraph,
    DepFact,
    DepsFacts,
)
from app.models.graph import CodeGraph, EdgeKind, NodeKind

log = logging.getLogger(__name__)

Extractor = Callable[[Path], DepsFacts]
_KIND_PRIORITY = {"normal": 0, "build": 1, "dev": 2}
_db_lock = threading.Lock()      # one extractor at a time: they share the advisory-db checkout


class ExtractorUnavailable(RuntimeError):
    """The extractor binary is not installed or could not produce facts."""


def norm(name: str) -> str:
    """Crate names use dashes in Cargo.toml and underscores in code."""
    return name.replace("-", "_")


# -- facts -----------------------------------------------------------------------------------
def extractor_path() -> str | None:
    configured = settings.codegraph_extractor
    if os.sep in configured or "/" in configured:
        return configured if Path(configured).is_file() else None
    return shutil.which(configured)


def run_extractor(lockfile: Path) -> DepsFacts:
    binary = extractor_path()
    if binary is None:
        raise ExtractorUnavailable(f"{settings.codegraph_extractor} not found")
    cmd = [binary, "deps", "--lockfile", str(lockfile), "--advisory-db", settings.advisory_db_path,
           "--max-age-hours", str(settings.advisory_db_max_age_hours)]
    if settings.advisory_db_offline:
        cmd.append("--offline")
    with _db_lock:
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.extractor_timeout_seconds,
                                  check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExtractorUnavailable(f"running {binary}: {exc}") from exc
    if done.returncode != 0:
        raise ExtractorUnavailable(f"{binary} exited {done.returncode}: {done.stderr.strip()[-500:]}")
    try:
        facts = DepsFacts.model_validate(json.loads(done.stdout))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ExtractorUnavailable(f"unreadable extractor output: {exc}") from exc
    if facts.schema_version != DEPS_SCHEMA_VERSION:
        raise ExtractorUnavailable(f"extractor schema {facts.schema_version}, expected {DEPS_SCHEMA_VERSION}")
    return facts


def parse_lockfile(lockfile: Path) -> DepsFacts:
    """Crates and dependency edges straight from Cargo.lock; no advisories."""
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    packages = data.get("package", [])
    crates: list[CrateFact] = []
    versions: dict[str, list[str]] = defaultdict(list)
    for pkg in packages:
        source = pkg.get("source")
        kind = "path" if source is None else source.split("+", 1)[0]
        kind = kind if kind in ("registry", "git", "path", "sparse") else "other"
        kind = "registry" if kind == "sparse" else kind
        crates.append(CrateFact(key=f"{pkg['name']}@{pkg['version']}", name=pkg["name"], version=pkg["version"],
                                source=kind, source_id=source, checksum=pkg.get("checksum")))
        versions[pkg["name"]].append(pkg["version"])
    deps, warnings = [], []
    for pkg in packages:
        for spec in pkg.get("dependencies", []):
            name, _, rest = spec.partition(" ")
            wanted = rest.split(" ", 1)[0] if rest else None
            candidates = versions.get(name, [])
            version = candidates[0] if len(candidates) == 1 else (wanted if wanted in candidates else None)
            if version is None:
                warnings.append(f"{pkg['name']} depends on {spec}, which is not in the lockfile")
                continue
            deps.append(DepFact(**{"from": f"{pkg['name']}@{pkg['version']}", "to": f"{name}@{version}"}))
    return DepsFacts(schema_version=DEPS_SCHEMA_VERSION, tool="codegraph lockfile parser",
                     lockfile=str(lockfile), crates=crates, deps=deps, warnings=warnings)


def lockfile_lines(text: str) -> dict[str, int]:
    """name@version -> 1-based line of the package's `name = ...` in Cargo.lock."""
    lines: dict[str, int] = {}
    name, name_line = None, 0
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line == "[[package]]":
            name = None
        elif line.startswith("name = ") and name is None:
            name, name_line = line.split("=", 1)[1].strip().strip('"'), i
        elif line.startswith("version = ") and name is not None:
            lines.setdefault(f"{name}@{line.split('=', 1)[1].strip().strip(chr(34))}", name_line)
    return lines


# -- manifests -------------------------------------------------------------------------------
@dataclass
class Manifest:
    name: str
    dir: str                                            # relative to the project root, "" for the root
    path: str
    kinds: dict[str, str] = field(default_factory=dict)       # dependency package name -> kind
    renames: dict[str, str] = field(default_factory=dict)     # name used in code -> package name


def _dep_tables(doc: dict) -> Iterable[tuple[str, dict]]:
    for table, kind in (("dependencies", "normal"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        yield kind, doc.get(table, {})
        for target in doc.get("target", {}).values():
            if isinstance(target, dict):
                yield kind, target.get(table, {})


def read_manifest(path: Path, root: Path) -> Manifest | None:
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.warning("skipping %s: %s", path, exc)
        return None
    package = doc.get("package")
    if not isinstance(package, dict) or "name" not in package:
        return None                                       # a virtual workspace manifest
    rel_dir = path.parent.relative_to(root).as_posix()
    manifest = Manifest(name=package["name"], dir="" if rel_dir == "." else rel_dir,
                        path=path.relative_to(root).as_posix())
    for kind, table in _dep_tables(doc):
        for key, spec in table.items():
            real = spec.get("package", key) if isinstance(spec, dict) else key
            current = manifest.kinds.get(real)
            if current is None or _KIND_PRIORITY[kind] < _KIND_PRIORITY[current]:
                manifest.kinds[real] = kind
            manifest.renames[norm(key)] = real
    return manifest


def _walk(root: Path, ignored: set[str], filename: str) -> list[Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignored)
        if filename in filenames:
            found.append(Path(dirpath) / filename)
    return found


def _under(path: str, directory: str) -> bool:
    return directory == "" or path == directory or path.startswith(directory + "/")


# -- assembly --------------------------------------------------------------------------------
def scan_dependencies(root: Path, project_id: str, graph: CodeGraph, extractor: Extractor | None = None,
                      ignored_dirs: set[str] | None = None) -> DependencyGraph:
    ignored = ignored_dirs or IGNORED_DIRS
    out = DependencyGraph()
    lockfiles = _walk(root, ignored, "Cargo.lock")
    manifests = [m for p in _walk(root, ignored, "Cargo.toml") if (m := read_manifest(p, root))]

    covered = {lf.parent.relative_to(root).as_posix() for lf in lockfiles}
    covered = {"" if c == "." else c for c in covered}
    for m in manifests:
        if not any(_under(m.dir, c) for c in covered):
            out.warnings.append(f"{m.path} has no Cargo.lock; its dependencies were not analyzed")
    if not lockfiles:
        return out

    run = extractor or run_extractor
    crates: dict[str, CrateNode] = {}
    edges: dict[tuple[str, str], DependencyEdge] = {}
    advisories = {}
    affected: dict[tuple[str, str], AffectedEdge] = {}
    member_manifest: dict[str, Manifest] = {}
    fallback_noted = False

    def cid(key: str) -> str:
        return f"{project_id}:crate:{key}"

    for lockfile in lockfiles:
        rel_lock = lockfile.relative_to(root).as_posix()
        lock_dir = lockfile.parent.relative_to(root).as_posix()
        lock_dir = "" if lock_dir == "." else lock_dir
        try:
            facts = run(lockfile)
        except ExtractorUnavailable as exc:
            if not fallback_noted:
                out.warnings.append(f"advisories skipped: {exc}; crates were read from Cargo.lock directly")
                fallback_noted = True
            facts = parse_lockfile(lockfile)
        out.warnings.extend(f"{rel_lock}: {w}" for w in facts.warnings)
        if facts.advisory_db and facts.advisory_db.commit and out.advisory_db_commit is None:
            out.advisory_db_commit = facts.advisory_db.commit

        lines = lockfile_lines(lockfile.read_text(encoding="utf-8"))
        local = [m for m in manifests if _under(m.dir, lock_dir)]
        for c in facts.crates:
            member = next((m for m in local if m.name == c.name), None) if c.source == "path" else None
            node = crates.setdefault(cid(c.key), CrateNode(
                id=cid(c.key), name=c.name, version=c.version, source=c.source, source_id=c.source_id,
                checksum=c.checksum, workspace_member=member is not None,
                manifest_path=member.path if member else None, lockfile=rel_lock,
                lockfile_line=lines.get(c.key, 0),
            ))
            if member is not None:
                member_manifest[node.id] = member
        for d in facts.deps:
            src, dst = cid(d.from_), cid(d.to)
            kind = None
            if (m := member_manifest.get(src)) is not None:
                kind = m.kinds.get(d.to.rsplit("@", 1)[0])
            edges.setdefault((src, dst), DependencyEdge(source=src, target=dst, kind=kind))
        for a in facts.advisories:
            advisories.setdefault(a.id, a)
        for match in facts.matches:
            key = (cid(match.crate_key), match.advisory)
            affected.setdefault(key, AffectedEdge(crate=key[0], advisory=match.advisory, kind=match.kind,
                                                  functions=match.functions))

    out.crates = list(crates.values())
    out.depends_on = list(edges.values())
    out.advisories = list(advisories.values())
    out.affected_by = list(affected.values())
    _link_code(out, graph, member_manifest)
    return out


def _link_code(out: DependencyGraph, graph: CodeGraph, member_manifest: dict[str, Manifest]) -> None:
    by_id = {c.id: c for c in out.crates}
    adjacency: dict[str, list[str]] = defaultdict(list)
    for e in out.depends_on:
        adjacency[e.source].append(e.target)

    # Which crates each member can name in code: its dependency closure, by underscored name.
    lookup: dict[str, dict[str, list[str]]] = {}
    for member_id, manifest in member_manifest.items():
        seen, queue = {member_id}, deque([member_id])
        while queue:
            for nxt in adjacency[queue.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        names: dict[str, list[str]] = defaultdict(list)
        for crate_id in seen:
            names[norm(by_id[crate_id].name)].append(crate_id)
        for alias, real in manifest.renames.items():
            if norm(real) in names and alias not in names:
                names[alias] = names[norm(real)]
        lookup[member_id] = names

    members = sorted(member_manifest.items(), key=lambda kv: len(kv[1].dir), reverse=True)

    def owner(path: str) -> str | None:
        return next((mid for mid, m in members if _under(path, m.dir)), None)

    file_owner: dict[str, str] = {}
    for node in graph.nodes:
        if node.kind == NodeKind.file and node.language == "rust" and (mid := owner(node.file)):
            file_owner[node.file] = mid
            out.crate_files.append((mid, node.id))
            for name in node.attrs.get("uses_crates", []) or []:
                for crate_id in lookup[mid].get(norm(str(name)), []):
                    out.uses.append((node.id, crate_id))

    nodes = {n.id: n for n in graph.nodes}
    links: set[tuple[str, str]] = set()
    for edge in graph.edges:
        if edge.kind != EdgeKind.calls:
            continue
        target, caller = nodes.get(edge.target), nodes.get(edge.source)
        if target is None or caller is None or target.kind != NodeKind.external:
            continue
        crate_name = target.attrs.get("crate")
        mid = file_owner.get(caller.file)
        if not crate_name or mid is None:
            continue
        for crate_id in lookup[mid].get(norm(str(crate_name)), []):
            links.add((target.id, crate_id))
    out.from_crate = sorted(links)
