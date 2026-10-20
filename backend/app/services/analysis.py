import logging
from collections import Counter

from app.analyzers import REGISTRY
from app.graph.repository import GraphRepository
from app.models.analysis import AnalysisReport, Finding

log = logging.getLogger(__name__)


async def analyze_project(project_id: str, repo: GraphRepository) -> AnalysisReport:
    findings: list[Finding] = []
    for analyzer in REGISTRY:
        results = await analyzer.run(repo, project_id)
        log.info("%s: %d finding(s)", analyzer.rule, len(results))
        findings.extend(results)

    await repo.replace_findings(project_id, findings)
    return AnalysisReport(
        project_id=project_id,
        total=len(findings),
        by_severity=dict(Counter(f.severity for f in findings)),
        by_rule=dict(Counter(f.rule for f in findings)),
    )
