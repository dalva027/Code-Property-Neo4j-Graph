from app.analyzers.base import Analyzer, register
from app.graph.repository import GraphRepository
from app.models.analysis import Finding, Severity


@register
class UnusedFunctions(Analyzer):
    rule = "unused-function"
    severity = Severity.warning
    description = (
        "A function that nothing calls or passes as a value, apart from itself. Entry points, decorated "
        "functions (routes, fixtures), tests and private/dunder names are skipped, as are Rust trait "
        "methods, which are reached through trait dispatch."
    )

    QUERY = """
    MATCH (f:Function {project_id: $pid})
    WHERE NOT EXISTS { (c)-[:CALLS|REFERENCES]->(f) WHERE c <> f }
      AND NOT f.name STARTS WITH '_'
      AND NOT f.name STARTS WITH 'test'
      AND f.name <> 'main'
      AND coalesce(f.decorators, 0) = 0
      AND NOT coalesce(f.subkind, '') IN ['trait fn', 'trait impl fn']
    RETURN f.id AS id, f.qualified_name AS qname, f.file AS file, f.line_start AS line
    ORDER BY f.file, f.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        rows = await repo.query(self.QUERY, pid=project_id)
        return [
            self.finding(project_id, f"{r['qname']} is never called within this project",
                         node_id=r["id"], file=r["file"], line=r["line"])
            for r in rows
        ]
