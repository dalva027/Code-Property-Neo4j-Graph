import logging
from collections import Counter

from app.analyzers import REGISTRY
from app.graph.repository import GraphRepository
from app.models.analysis import AnalysisReport, Finding
from app.rules import load_catalogue

log = logging.getLogger(__name__)


async def analyze_project(project_id: str, repo: GraphRepository) -> AnalysisReport:
    languages = await repo.project_languages(project_id)
    findings: list[Finding] = []
    for analyzer in REGISTRY:
        if not analyzer.applies_to(languages):
            log.info("%s: skipped (no %s files)", analyzer.rule, "/".join(analyzer.languages or ()))
            continue
        results = await analyzer.run(repo, project_id)
        log.info("%s: %d finding(s)", analyzer.rule, len(results))
        findings.extend(results)

    await repo.replace_findings(project_id, findings)
    return AnalysisReport(
        project_id=project_id,
        total=len(findings),
        by_severity=dict(Counter(f.severity for f in findings)),
        by_rule=dict(Counter(f.rule for f in findings)),
        by_category=dict(Counter(f.category for f in findings)),
        catalogue_version=load_catalogue().version,
    )
