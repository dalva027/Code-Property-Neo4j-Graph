"""Rules about how files depend on each other — the ones a graph database makes cheap."""
from app.analyzers.base import Analyzer, register
from app.config import settings
from app.graph.repository import GraphRepository
from app.models.analysis import Finding, Severity


@register
class CircularImports(Analyzer):
    rule = "circular-import"
    severity = Severity.error
    description = "Two files import each other, directly or through intermediaries."

    QUERY = """
    MATCH (a:File {project_id: $pid})-[:IMPORTS]->(b:File)
    WHERE a.id < b.id AND EXISTS { (b)-[:IMPORTS*1..8]->(a) }
    RETURN a.id AS id, a.file AS file, b.file AS other
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        rows = await repo.query(self.QUERY, pid=project_id)
        return [
            self.finding(project_id, f"Circular import between {r['file']} and {r['other']}",
                         node_id=r["id"], file=r["file"], line=1)
            for r in rows
        ]


@register
class HubFiles(Analyzer):
    rule = "hub-file"
    severity = Severity.info
    description = "A file imported by many others; changes here have a wide blast radius."

    QUERY = """
    MATCH (f:File {project_id: $pid})<-[:IMPORTS]-(importer:File)
    WITH f, count(DISTINCT importer) AS fan_in
    WHERE fan_in >= $threshold
    RETURN f.id AS id, f.file AS file, fan_in
    ORDER BY fan_in DESC
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        rows = await repo.query(self.QUERY, pid=project_id, threshold=settings.hub_fan_in)
        return [
            self.finding(project_id, f"{r['file']} is imported by {r['fan_in']} files",
                         node_id=r["id"], file=r["file"], line=1)
            for r in rows
        ]
