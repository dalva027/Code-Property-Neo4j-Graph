"""Size and complexity rules, driven by metrics the parser stored on each node."""
from app.analyzers.base import Analyzer, register
from app.config import settings
from app.graph.repository import GraphRepository
from app.models.analysis import Finding, Severity


@register
class HighComplexity(Analyzer):
    rule = "high-complexity"
    severity = Severity.warning
    description = "Cyclomatic complexity above MAX_COMPLEXITY."

    QUERY = """
    MATCH (f:Function {project_id: $pid}) WHERE f.complexity > $max
    RETURN f.id AS id, f.qualified_name AS qname, f.file AS file, f.line_start AS line, f.complexity AS value
    ORDER BY f.complexity DESC
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        rows = await repo.query(self.QUERY, pid=project_id, max=settings.max_complexity)
        return [
            self.finding(project_id,
                         f"{r['qname']} has cyclomatic complexity {r['value']} (limit {settings.max_complexity})",
                         node_id=r["id"], file=r["file"], line=r["line"])
            for r in rows
        ]


@register
class LongFunction(Analyzer):
    rule = "long-function"
    severity = Severity.info
    description = "Function body longer than MAX_FUNCTION_LINES."

    QUERY = """
    MATCH (f:Function {project_id: $pid}) WHERE f.loc > $max
    RETURN f.id AS id, f.qualified_name AS qname, f.file AS file, f.line_start AS line, f.loc AS value
    ORDER BY f.loc DESC
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        rows = await repo.query(self.QUERY, pid=project_id, max=settings.max_function_lines)
        return [
            self.finding(project_id, f"{r['qname']} is {r['value']} lines long (limit {settings.max_function_lines})",
                         node_id=r["id"], file=r["file"], line=r["line"])
            for r in rows
        ]


@register
class GodClass(Analyzer):
    rule = "god-class"
    severity = Severity.warning
    description = "Class with more methods than MAX_CLASS_METHODS."

    QUERY = """
    MATCH (c:Class {project_id: $pid}) WHERE c.methods > $max
    RETURN c.id AS id, c.qualified_name AS qname, c.file AS file, c.line_start AS line, c.methods AS value
    ORDER BY c.methods DESC
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        rows = await repo.query(self.QUERY, pid=project_id, max=settings.max_class_methods)
        return [
            self.finding(project_id, f"{r['qname']} has {r['value']} methods (limit {settings.max_class_methods})",
                         node_id=r["id"], file=r["file"], line=r["line"])
            for r in rows
        ]
