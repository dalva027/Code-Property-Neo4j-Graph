"""All Cypher lives here. Nothing else in the app talks to Neo4j directly."""
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import uuid4

from app.db import neo4j
from app.models.analysis import Category, Finding, NodeDetail, Project, ScanState, Severity
from app.models.deps import (
    AdvisoryInfo,
    AffectedCrateRadius,
    BlastRadius,
    CrateRef,
    DependencyGraph,
    ProjectAdvisory,
    ReachingFunction,
)
from app.models.graph import CODE_EDGE_KINDS, CodeGraph, EdgeKind, GraphEdge, GraphNode, NodeKind

CORE_PROPS = {"id", "project_id", "kind", "name", "qualified_name", "file", "line_start", "line_end", "language",
              "subkind"}
REL_TYPES = "|".join(k.value for k in EdgeKind)
LABELS = {
    NodeKind.file: "File",
    NodeKind.class_: "Symbol:Class",
    NodeKind.function: "Symbol:Function",
    NodeKind.external: "Symbol:External",
    NodeKind.unsafe: "Unsafe",
    NodeKind.call: "Call",
    NodeKind.literal: "Literal",
}
GRAPH_LABELS = "File|Symbol|Unsafe|Call|Literal"   # what the code graph builder writes
ENTRY_KINDS = ["main", "handler", "pub_api", "ffi"]   # test functions are never reachability roots
MAX_ENTRY_DEPTH = 10
SEVERITY_RANK = {Severity.critical: 0, Severity.error: 1, Severity.warning: 2, Severity.info: 3}
BATCH = 5000          # rows per UNWIND; keeps transactions bounded on large projects

PROJECT_NODES = f"{GRAPH_LABELS}|Crate"    # labels whose nodes carry project_id

# Advisories are global, so their edges are filtered to the project's own crates.
NODE_DETAIL = f"""
CALL () {{
  MATCH (n:{PROJECT_NODES} {{id: $id, project_id: $pid}}) RETURN n
  UNION
  MATCH (n:Advisory {{id: $id}}) RETURN n
}}
WITH n LIMIT 1
CALL (n) {{
  MATCH (n)-[r:{REL_TYPES}]->(t:{PROJECT_NODES}|Advisory)
  WHERE t:Advisory OR t.project_id = $pid
  RETURN collect({{source: n.id, target: t.id, kind: type(r), props: properties(r)}}) AS outgoing }}
CALL (n) {{
  MATCH (s:{PROJECT_NODES})-[r:{REL_TYPES}]->(n)
  WHERE s.project_id = $pid
  RETURN collect({{source: s.id, target: n.id, kind: type(r), props: properties(r)}}) AS incoming }}
CALL (n) {{
  OPTIONAL MATCH (n)-[:HAS_FINDING]->(f:Finding {{project_id: $pid}})
  RETURN collect(f) AS findings }}
RETURN n, outgoing, incoming, findings
"""

T = TypeVar("T")


def _chunks(items: Sequence[T], size: int = BATCH) -> Iterator[Sequence[T]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _node_props(node: GraphNode, project_id: str) -> dict[str, Any]:
    """Flatten a GraphNode into Neo4j properties; metrics and attrs become top-level props."""
    return {
        **node.attrs, **node.metrics,
        "id": node.id, "project_id": project_id, "kind": node.kind.value, "name": node.name,
        "qualified_name": node.qualified_name, "file": node.file, "line_start": node.line_start,
        "line_end": node.line_end, "language": node.language, "subkind": node.subkind,
    }


def _node_from_props(props: dict[str, Any]) -> GraphNode:
    extra = {k: v for k, v in props.items() if k not in CORE_PROPS}
    # bool is an int subclass; flags are attrs, not metrics.
    metrics = {k: v for k, v in extra.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
    attrs = {k: v for k, v in extra.items() if k not in metrics}
    return GraphNode(
        id=props["id"], kind=props["kind"], name=props["name"], qualified_name=props["qualified_name"],
        file=props.get("file", ""), line_start=props.get("line_start", 0), line_end=props.get("line_end", 0),
        language=props.get("language", "python"), subkind=props.get("subkind"), metrics=metrics, attrs=attrs,
    )


def _edge(row: dict[str, Any]) -> GraphEdge:
    return GraphEdge(source=row["source"], target=row["target"], kind=row["kind"], props=row.get("props") or {})


def _advisory_info(props: dict[str, Any], kind: str) -> AdvisoryInfo:
    return AdvisoryInfo(
        id=props["id"], package=props.get("package", ""), title=props.get("title", ""), date=props.get("date", ""),
        kind=kind, severity=props.get("severity"), cvss_score=props.get("cvss_score"), url=props.get("url"),
        aliases=props.get("aliases") or [], patched=props.get("patched") or [],
        functions=props.get("functions") or [],
    )


class GraphRepository:
    # -- projects -------------------------------------------------------------
    async def create_project(self, name: str, root: str) -> Project:
        """Create a project in the `scanning` state; the caller starts the scan."""
        now = datetime.now(UTC)
        project = Project(id=uuid4().hex[:12], name=name, root=root, created_at=now,
                          status=ScanState.scanning, scan_started_at=now)
        await neo4j.run(
            "CREATE (p:Project {id: $id, name: $name, root: $root, created_at: $created_at, "
            "file_count: 0, symbol_count: 0, status: $status, scan_started_at: $created_at})",
            id=project.id, name=name, root=root, created_at=now.isoformat(), status=project.status.value,
        )
        return project

    async def list_projects(self) -> list[Project]:
        rows = await neo4j.run("MATCH (p:Project) RETURN p ORDER BY p.created_at DESC")
        return [Project(**row["p"]) for row in rows]

    async def get_project(self, project_id: str) -> Project | None:
        rows = await neo4j.run("MATCH (p:Project {id: $pid}) RETURN p", pid=project_id)
        return Project(**rows[0]["p"]) if rows else None

    async def delete_project(self, project_id: str) -> None:
        await self._delete_project_nodes(project_id, include_findings=True)
        await neo4j.run("MATCH (p:Project {id: $pid}) DETACH DELETE p", pid=project_id)
        await self._delete_orphan_advisories()

    async def set_scan_notes(self, project_id: str, warnings: list[str], advisory_db_commit: str | None) -> None:
        await neo4j.run(
            "MATCH (p:Project {id: $pid}) SET p.warnings = $warnings, p.advisory_db_commit = $commit",
            pid=project_id, warnings=warnings, commit=advisory_db_commit,
        )

    async def mark_scan_started(self, project_id: str) -> None:
        await neo4j.run(
            "MATCH (p:Project {id: $pid}) SET p.status = $status, p.scan_started_at = $now, "
            "p.scan_finished_at = null, p.error = null",
            pid=project_id, status=ScanState.scanning.value, now=_now(),
        )

    async def mark_scan_finished(self, project_id: str, error: str | None = None) -> None:
        status = ScanState.failed if error else ScanState.ready
        await neo4j.run(
            "MATCH (p:Project {id: $pid}) SET p.status = $status, p.scan_finished_at = $now, p.error = $error",
            pid=project_id, status=status.value, now=_now(), error=error,
        )

    async def fail_interrupted_scans(self) -> int:
        """Scans run in-process; any still marked `scanning` at startup died with the old process."""
        rows = await neo4j.run(
            "MATCH (p:Project {status: $scanning}) "
            "SET p.status = $failed, p.error = 'interrupted by an API restart; rescan the project', "
            "p.scan_finished_at = $now RETURN count(p) AS n",
            scanning=ScanState.scanning.value, failed=ScanState.failed.value, now=_now(),
        )
        return rows[0]["n"] if rows else 0

    async def project_languages(self, project_id: str) -> set[str]:
        rows = await neo4j.run(
            "MATCH (f:File {project_id: $pid}) RETURN DISTINCT f.language AS language", pid=project_id
        )
        return {r["language"] for r in rows if r["language"]}

    # -- graph ----------------------------------------------------------------
    async def _delete_project_nodes(self, project_id: str, include_findings: bool) -> None:
        labels = f"{PROJECT_NODES}|Finding" if include_findings else PROJECT_NODES
        while True:
            rows = await neo4j.run(
                f"MATCH (n:{labels} {{project_id: $pid}}) WITH n LIMIT $batch "
                "DETACH DELETE n RETURN count(*) AS deleted",
                pid=project_id, batch=BATCH,
            )
            if not rows or rows[0]["deleted"] < BATCH:
                return

    async def replace_graph(self, project_id: str, graph: CodeGraph) -> None:
        """Wipe and re-create a project's graph. Findings are cleared too, since node ids may change."""
        await self._delete_project_nodes(project_id, include_findings=True)

        for kind, label in LABELS.items():
            rows = [_node_props(n, project_id) for n in graph.nodes if n.kind == kind]
            for chunk in _chunks(rows):
                await neo4j.run(f"UNWIND $rows AS r MERGE (n:{label} {{id: r.id}}) SET n = r", rows=chunk)

        file_ids = [n.id for n in graph.nodes if n.kind == NodeKind.file]
        for chunk in _chunks(file_ids):
            await neo4j.run(
                "MATCH (p:Project {id: $pid}) UNWIND $ids AS id MATCH (f:File {id: id}) MERGE (p)-[:HAS_FILE]->(f)",
                pid=project_id, ids=chunk,
            )

        for kind in CODE_EDGE_KINDS:
            rows = [{"source": e.source, "target": e.target, "props": e.props}
                    for e in graph.edges if e.kind == kind]
            for chunk in _chunks(rows):
                await neo4j.run(
                    f"UNWIND $rows AS p "
                    f"MATCH (a:{GRAPH_LABELS} {{id: p.source}}) MATCH (b:{GRAPH_LABELS} {{id: p.target}}) "
                    f"MERGE (a)-[r:{kind.value}]->(b) SET r += p.props",
                    rows=chunk,
                )

        files = len(file_ids)
        symbols = sum(n.kind in (NodeKind.class_, NodeKind.function) for n in graph.nodes)
        await neo4j.run(
            "MATCH (p:Project {id: $pid}) SET p.file_count = $files, p.symbol_count = $symbols",
            pid=project_id, files=files, symbols=symbols,
        )

    async def mark_reachability(self, project_id: str, max_depth: int = MAX_ENTRY_DEPTH) -> int:
        """Set `entry_distance` (calls from the nearest entry point) and `reachable_from_entry` on
        every function, by breadth-first expansion over CALLS and REFERENCES. Returns how many
        functions are reachable."""
        await neo4j.run(
            "MATCH (f:Function {project_id: $pid}) SET f.reachable_from_entry = false, f.entry_distance = null",
            pid=project_id,
        )
        rows = await neo4j.run(
            "MATCH (f:Function {project_id: $pid}) WHERE f.entry_kind IN $kinds "
            "SET f.reachable_from_entry = true, f.entry_distance = 0 RETURN count(f) AS n",
            pid=project_id, kinds=ENTRY_KINDS,
        )
        total = rows[0]["n"] if rows else 0
        for depth in range(1, max_depth + 1):
            rows = await neo4j.run(
                "MATCH (a:Function {project_id: $pid, entry_distance: $prev})-[:CALLS|REFERENCES]->(b:Function) "
                "WHERE b.project_id = $pid AND b.entry_distance IS NULL "
                "SET b.reachable_from_entry = true, b.entry_distance = $depth RETURN count(DISTINCT b) AS n",
                pid=project_id, prev=depth - 1, depth=depth,
            )
            if not rows or rows[0]["n"] == 0:
                break
            total += rows[0]["n"]
        return total

    async def aggregate_crate_metrics(self, project_id: str) -> None:
        """Unsafe counts per workspace member, summed over its files (comparable with cargo-geiger)."""
        await neo4j.run(
            """
            MATCH (c:Crate {project_id: $pid, workspace_member: true})
            OPTIONAL MATCH (c)-[:HAS_FILE]->(f:File)
            WITH c, sum(coalesce(f.unsafe_blocks, 0)) AS blocks, sum(coalesce(f.unsafe_fns, 0)) AS fns,
                 sum(coalesce(f.unsafe_impls, 0)) AS impls, sum(coalesce(f.unsafe_traits, 0)) AS traits,
                 sum(coalesce(f.unsafe_lines, 0)) AS lines, sum(coalesce(f.loc, 0)) AS loc,
                 sum(coalesce(f.foreign_fns, 0)) AS foreign
            SET c.unsafe_blocks = blocks, c.unsafe_fns = fns, c.unsafe_impls = impls, c.unsafe_traits = traits,
                c.unsafe_lines = lines, c.loc = loc, c.foreign_fns = foreign,
                c.unsafe_density = CASE WHEN loc > 0 THEN round(toFloat(lines) / loc, 4) ELSE 0.0 END
            """,
            pid=project_id,
        )

    async def replace_dependencies(self, project_id: str, deps: DependencyGraph) -> None:
        """Write crates, advisories and their edges. Runs after replace_graph, which cleared the old ones."""
        crates = [{
            "id": c.id, "project_id": project_id, "kind": NodeKind.crate.value, "name": c.name,
            "qualified_name": f"{c.name}@{c.version}", "file": c.lockfile, "line_start": c.lockfile_line,
            "line_end": c.lockfile_line, "language": "rust",
            "subkind": "workspace member" if c.workspace_member else "dependency",
            "version": c.version, "source": c.source, "source_id": c.source_id, "checksum": c.checksum,
            "workspace_member": c.workspace_member, "manifest_path": c.manifest_path,
        } for c in deps.crates]
        for chunk in _chunks(crates):
            await neo4j.run(
                "UNWIND $rows AS r MERGE (c:Crate {id: r.id}) SET c = r "
                "WITH c MATCH (p:Project {id: $pid}) MERGE (p)-[:HAS_CRATE]->(c)",
                rows=chunk, pid=project_id,
            )

        advisories = [{
            "id": a.id, "kind": NodeKind.advisory.value, "name": a.id, "qualified_name": a.id, "file": "",
            "language": "rust", "subkind": a.informational or "vulnerability", "package": a.package,
            "title": a.title, "description": a.description, "date": a.date, "aliases": a.aliases,
            "categories": a.categories, "keywords": a.keywords, "cvss": a.cvss, "cvss_score": a.cvss_score,
            "severity": a.severity, "informational": a.informational, "url": a.url, "withdrawn": a.withdrawn,
            "patched": a.patched, "unaffected": a.unaffected, "functions": sorted(a.functions),
            "db_commit": deps.advisory_db_commit,
        } for a in deps.advisories]
        for chunk in _chunks(advisories):
            await neo4j.run("UNWIND $rows AS r MERGE (a:Advisory {id: r.id}) SET a = r", rows=chunk)

        edge_sets = [
            ("Crate", "Crate", EdgeKind.depends_on,
             [{"s": e.source, "t": e.target, "props": {"kind": e.kind} if e.kind else {}} for e in deps.depends_on]),
            ("Crate", "Advisory", EdgeKind.affected_by,
             [{"s": e.crate, "t": e.advisory, "props": {"kind": e.kind, "functions": e.functions}}
              for e in deps.affected_by]),
            ("Crate", "File", EdgeKind.has_file, [{"s": s, "t": t, "props": {}} for s, t in deps.crate_files]),
            ("File", "Crate", EdgeKind.uses, [{"s": s, "t": t, "props": {}} for s, t in deps.uses]),
            ("External", "Crate", EdgeKind.from_crate, [{"s": s, "t": t, "props": {}} for s, t in deps.from_crate]),
        ]
        for src_label, dst_label, kind, rows in edge_sets:
            for chunk in _chunks(rows):
                await neo4j.run(
                    f"UNWIND $rows AS r MATCH (a:{src_label} {{id: r.s}}) MATCH (b:{dst_label} {{id: r.t}}) "
                    f"MERGE (a)-[e:{kind.value}]->(b) SET e += r.props",
                    rows=chunk,
                )
        await self._delete_orphan_advisories()

    async def list_advisories(self, project_id: str) -> list[ProjectAdvisory]:
        rows = await neo4j.run(
            """
            MATCH (c:Crate {project_id: $pid})-[a:AFFECTED_BY]->(adv:Advisory)
            WITH adv, a.kind AS kind, c ORDER BY c.name, c.version
            WITH adv, kind, collect({id: c.id, name: c.name, version: c.version}) AS crates
            RETURN adv, kind, crates ORDER BY adv.id
            """,
            pid=project_id,
        )
        return [ProjectAdvisory(advisory=_advisory_info(r["adv"], r["kind"]),
                                crates=[CrateRef(**c) for c in r["crates"]]) for r in rows]

    async def blast_radius(self, project_id: str, advisory_id: str) -> BlastRadius | None:
        rows = await neo4j.run(
            """
            MATCH (adv:Advisory {id: $aid})<-[a:AFFECTED_BY]-(c:Crate {project_id: $pid})
            CALL (c) {
              OPTIONAL MATCH (m:Crate {project_id: $pid, workspace_member: true}) WHERE m <> c
              OPTIONAL MATCH p = shortestPath((m)-[:DEPENDS_ON*1..20]->(c))
              WITH p WHERE p IS NOT NULL
              WITH p ORDER BY length(p)
              RETURN collect([n IN nodes(p) | {id: n.id, name: n.name, version: n.version}]) AS paths
            }
            CALL (c, a) {
              OPTIONAL MATCH (f:Function)-[call:CALLS]->(e:External)-[:FROM_CRATE]->(c)
              WITH f, call, e WHERE f IS NOT NULL
              WITH f, call, e ORDER BY f.file, call.line
              RETURN collect({function: f.id, qualified_name: f.qualified_name, file: f.file,
                              line: coalesce(call.line, f.line_start), path: e.path,
                              affected: e.path IN coalesce(a.functions, [])}) AS functions
            }
            CALL (c) {
              OPTIONAL MATCH (file:File)-[:USES]->(c)
              WITH file WHERE file IS NOT NULL
              WITH file ORDER BY file.file
              RETURN collect(DISTINCT file.file) AS importing_files
            }
            RETURN adv, a.kind AS kind, {id: c.id, name: c.name, version: c.version} AS crate,
                   paths, functions, importing_files
            ORDER BY c.name, c.version
            """,
            pid=project_id, aid=advisory_id,
        )
        if not rows:
            return None
        return BlastRadius(
            project_id=project_id, advisory=_advisory_info(rows[0]["adv"], rows[0]["kind"]),
            crates=[AffectedCrateRadius(
                crate=CrateRef(**r["crate"]), kind=r["kind"],
                paths=[[CrateRef(**n) for n in path] for path in r["paths"]],
                functions=[ReachingFunction(**f) for f in r["functions"]],
                importing_files=r["importing_files"],
            ) for r in rows],
        )

    async def _delete_orphan_advisories(self) -> None:
        await neo4j.run("MATCH (a:Advisory) WHERE NOT EXISTS { ()-[:AFFECTED_BY]->(a) } DETACH DELETE a")

    async def get_graph(self, project_id: str, limit: int = 5000) -> CodeGraph:
        nodes = await neo4j.run(
            "MATCH (n:File|Symbol {project_id: $pid}) RETURN n LIMIT $limit", pid=project_id, limit=limit
        )
        edges = await neo4j.run(
            f"MATCH (a:File|Symbol {{project_id: $pid}})-[r:{REL_TYPES}]->(b) "
            "RETURN a.id AS source, b.id AS target, type(r) AS kind, properties(r) AS props",
            pid=project_id,
        )
        graph = CodeGraph(nodes=[_node_from_props(r["n"]) for r in nodes])
        ids = {n.id for n in graph.nodes}
        graph.edges = [_edge(e) for e in edges if e["source"] in ids and e["target"] in ids]
        return graph

    async def get_node(self, project_id: str, node_id: str) -> NodeDetail | None:
        rows = await neo4j.run(NODE_DETAIL, id=node_id, pid=project_id)
        if not rows:
            return None
        row = rows[0]
        return NodeDetail(
            node=_node_from_props(row["n"]),
            outgoing=[_edge(e) for e in row["outgoing"]],
            incoming=[_edge(e) for e in row["incoming"]],
            findings=[Finding(**f) for f in row["findings"]],
        )

    # -- findings -------------------------------------------------------------
    async def replace_findings(self, project_id: str, findings: list[Finding]) -> None:
        await neo4j.run("MATCH (f:Finding {project_id: $pid}) DETACH DELETE f", pid=project_id)
        rows = [f.model_dump(mode="json") for f in findings]
        for chunk in _chunks(rows):
            await neo4j.run(
                """
                UNWIND $rows AS r
                CREATE (f:Finding) SET f = r
                WITH f, r
                OPTIONAL MATCH (n:File|Symbol|Crate|Unsafe|Call|Literal {id: r.node_id})
                FOREACH (_ IN CASE WHEN n IS NULL THEN [] ELSE [1] END | MERGE (n)-[:HAS_FINDING]->(f))
                """,
                rows=chunk,
            )

    async def list_findings(self, project_id: str, severity: Severity | None = None,
                            rule: str | None = None, category: Category | None = None) -> list[Finding]:
        rows = await neo4j.run(
            """
            MATCH (f:Finding {project_id: $pid})
            WHERE ($severity IS NULL OR f.severity = $severity) AND ($rule IS NULL OR f.rule = $rule)
              AND ($category IS NULL OR coalesce(f.category, 'quality') = $category)
            RETURN f
            """,
            pid=project_id, severity=severity.value if severity else None, rule=rule,
            category=category.value if category else None,
        )
        findings = [Finding(**r["f"]) for r in rows]
        findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file or "", f.line or 0))
        return findings

    # -- escape hatch for analyzers ------------------------------------------
    async def query(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        return await neo4j.run(cypher, **params)
