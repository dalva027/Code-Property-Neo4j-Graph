from fastapi import APIRouter, HTTPException

from app.analyzers import REGISTRY
from app.api.deps import RepoDep
from app.models.analysis import AnalysisReport, Finding, RuleInfo, Severity
from app.services.analysis import analyze_project

router = APIRouter(prefix="/projects/{project_id}", tags=["analysis"])
rules_router = APIRouter(tags=["analysis"])


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(project_id: str, repo: RepoDep):
    """Run every registered analyzer and replace the project's findings."""
    if await repo.get_project(project_id) is None:
        raise HTTPException(404, "project not found")
    return await analyze_project(project_id, repo)


@router.get("/findings", response_model=list[Finding])
async def list_findings(project_id: str, repo: RepoDep,
                        severity: Severity | None = None, rule: str | None = None):
    return await repo.list_findings(project_id, severity=severity, rule=rule)


@rules_router.get("/rules", response_model=list[RuleInfo])
async def list_rules():
    return [RuleInfo(rule=a.rule, severity=a.severity, description=a.description) for a in REGISTRY]
