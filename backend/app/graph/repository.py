"""All Cypher lives here. Nothing else in the app talks to Neo4j directly."""
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.db import neo4j
from app.models.analysis import Finding, NodeDetail, Project, Severity
from app.models.graph import CodeGraph, EdgeKind, GraphEdge, GraphNode, NodeKind

CORE_PROPS = {"id", "project_id", "kind", "name", "qualified_name", "file", "line_start", "line_end", "language",
              "subkind"}
REL_TYPES = "|".join(k.value for k in EdgeKind)
LABELS = {NodeKind.file: "File", NodeKind.class_: "Symbol:Class", NodeKind.function: "Symbol:Function"}
SEVERITY_RANK = {Severity.error: 0, Severity.warning: 1, Severity.info: 2}

NODE_DETAIL = f"""
MATCH (n:File|Symbol {{id: $id, project_id: $pid}})
CALL {{ WITH n
  MATCH (n)-[r:{REL_TYPES}]->(t)
  RETURN collect({{source: n.id, target: t.id, kind: type(r)}}) AS outgoing }}
CALL {{ WITH n
  MATCH (s)-[r:{REL_TYPES}]->(n)
  RETURN collect({{source: s.id, target: n.id, kind: type(r)}}) AS incoming }}
CALL {{ WITH n
  OPTIONAL MATCH (n)-[:HAS_FINDING]->(f:Finding)
  RETURN collect(f) AS findings }}
RETURN n, outgoing, incoming, findings
"""


def _node_props(node: GraphNode, project_id: str) -> dict[str, Any]:
    """Flatten a GraphNode into Neo4j properties; metrics become top-level numeric props."""
    return {
        "id": node.id, "project_id": project_id, "kind": node.kind.value, "name": node.name,
        "qualified_name": node.qualified_name, "file": node.file, "line_start": node.line_start,
        "line_end": node.line_end, "language": node.language, "subkind": node.subkind, **node.metrics,
    }


def _node_from_props(props: dict[str, Any]) -> GraphNode:
    metrics = {k: v for k, v in props.items() if k not in CORE_PROPS and isinstance(v, (int, float))}
    return GraphNode(
        id=props["id"], kind=props["kind"], name=props["name"], qualified_name=props["qualified_name"],
        file=props["file"], line_start=props.get("line_start", 0), line_end=props.get("line_end", 0),
        language=props.get("language", "python"), subkind=props.get("subkind"), metrics=metrics,
    )


class GraphRepository:
    # -- projects -------------------------------------------------------------
    async def create_project(self, name: str, root: str) -> Project:
        project = Project(id=uuid4().hex[:12], name=name, root=root, created_at=datetime.now(timezone.utc))
        await neo4j.run(
            "CREATE (p:Project {id: $id, name: $name, root: $root, created_at: $created_at, "
            "file_count: 0, symbol_count: 0})",
            id=project.id, name=name, root=root, created_at=project.created_at.isoformat(),
        )
        return project

    async def list_projects(self) -> list[Project]:
        rows = await neo4j.run("MATCH (p:Project) RETURN p ORDER BY p.created_at DESC")
        return [Project(**row["p"]) for row in rows]

    async def get_project(self, project_id: str) -> Project | None:
        rows = await neo4j.run("MATCH (p:Project {id: $pid}) RETURN p", pid=project_id)
        return Project(**rows[0]["p"]) if rows else None

    async def delete_project(self, project_id: str) -> None:
        await neo4j.run("MATCH (n:File|Symbol|Finding {project_id: $pid}) DETACH DELETE n", pid=project_id)
        await neo4j.run("MATCH (p:Project {id: $pid}) DETACH DELETE p", pid=project_id)

    # -- graph ----------------------------------------------------------------
    async def replace_graph(self, project_id: str, graph: CodeGraph) -> None:
        """Wipe and re-create a project's graph. Findings are cleared too, since node ids may change."""
        await neo4j.run("MATCH (n:File|Symbol|Finding {project_id: $pid}) DETACH DELETE n", pid=project_id)

        for kind, label in LABELS.items():
            rows = [_node_props(n, project_id) for n in graph.nodes if n.kind == kind]
            if rows:
                await neo4j.run(f"UNWIND $rows AS r MERGE (n:{label} {{id: r.id}}) SET n = r", rows=rows)

        await neo4j.run(
            "MATCH (p:Project {id: $pid}) UNWIND $ids AS id MATCH (f:File {id: id}) MERGE (p)-[:HAS_FILE]->(f)",
            pid=project_id, ids=[n.id for n in graph.nodes if n.kind == NodeKind.file],
        )

        for kind in EdgeKind:
            pairs = [{"source": e.source, "target": e.target} for e in graph.edges if e.kind == kind]
            if pairs:
                await neo4j.run(
                    f"UNWIND $pairs AS p "
                    f"MATCH (a:File|Symbol {{id: p.source}}) MATCH (b:File|Symbol {{id: p.target}}) "
                    f"MERGE (a)-[:{kind.value}]->(b)",
                    pairs=pairs,
                )

        files = sum(n.kind == NodeKind.file for n in graph.nodes)
        await neo4j.run(
            "MATCH (p:Project {id: $pid}) SET p.file_count = $files, p.symbol_count = $symbols",
            pid=project_id, files=files, symbols=len(graph.nodes) - files,
        )

    async def get_graph(self, project_id: str, limit: int = 5000) -> CodeGraph:
        nodes = await neo4j.run(
            "MATCH (n:File|Symbol {project_id: $pid}) RETURN n LIMIT $limit", pid=project_id, limit=limit
        )
        edges = await neo4j.run(
            f"MATCH (a:File|Symbol {{project_id: $pid}})-[r:{REL_TYPES}]->(b) "
            "RETURN a.id AS source, b.id AS target, type(r) AS kind",
            pid=project_id,
        )
        graph = CodeGraph(nodes=[_node_from_props(r["n"]) for r in nodes])
        ids = {n.id for n in graph.nodes}
        graph.edges = [GraphEdge(**e) for e in edges if e["source"] in ids and e["target"] in ids]
        return graph

    async def get_node(self, project_id: str, node_id: str) -> NodeDetail | None:
        rows = await neo4j.run(NODE_DETAIL, id=node_id, pid=project_id)
        if not rows:
            return None
        row = rows[0]
        return NodeDetail(
            node=_node_from_props(row["n"]),
            outgoing=[GraphEdge(**e) for e in row["outgoing"]],
            incoming=[GraphEdge(**e) for e in row["incoming"]],
            findings=[Finding(**f) for f in row["findings"]],
        )

    # -- findings -------------------------------------------------------------
    async def replace_findings(self, project_id: str, findings: list[Finding]) -> None:
        await neo4j.run("MATCH (f:Finding {project_id: $pid}) DETACH DELETE f", pid=project_id)
        rows = [f.model_dump(mode="json") for f in findings]
        if rows:
            await neo4j.run(
                """
                UNWIND $rows AS r
                CREATE (f:Finding) SET f = r
                WITH f, r
                OPTIONAL MATCH (n:File|Symbol {id: r.node_id})
                FOREACH (_ IN CASE WHEN n IS NULL THEN [] ELSE [1] END | MERGE (n)-[:HAS_FINDING]->(f))
                """,
                rows=rows,
            )

    async def list_findings(self, project_id: str, severity: Severity | None = None,
                            rule: str | None = None) -> list[Finding]:
        rows = await neo4j.run(
            """
            MATCH (f:Finding {project_id: $pid})
            WHERE ($severity IS NULL OR f.severity = $severity) AND ($rule IS NULL OR f.rule = $rule)
            RETURN f
            """,
            pid=project_id, severity=severity.value if severity else None, rule=rule,
        )
        findings = [Finding(**r["f"]) for r in rows]
        findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file or "", f.line or 0))
        return findings

    # -- escape hatch for analyzers ------------------------------------------
    async def query(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        return await neo4j.run(cypher, **params)
