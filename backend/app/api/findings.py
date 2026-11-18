from fastapi import APIRouter, HTTPException

from app.analyzers import REGISTRY
from app.api.deps import RepoDep
from app.models.analysis import AnalysisReport, Category, Finding, RuleCatalogueInfo, Severity
from app.models.views import Evidence
from app.rules import load_catalogue
from app.services.analysis import analyze_project
from app.services.evidence import load_evidence
from app.services.ingest import require_ready

router = APIRouter(prefix="/projects/{project_id}", tags=["analysis"])
rules_router = APIRouter(tags=["analysis"])


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(project_id: str, repo: RepoDep):
    """Run every registered analyzer and replace the project's findings."""
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    require_ready(project)
    return await analyze_project(project_id, repo)


@router.get("/findings", response_model=list[Finding])
async def list_findings(project_id: str, repo: RepoDep, severity: Severity | None = None,
                        rule: str | None = None, category: Category | None = None):
    return await repo.list_findings(project_id, severity=severity, rule=rule, category=category)


@router.get("/findings/{finding_id}/evidence", response_model=Evidence)
async def finding_evidence(project_id: str, finding_id: str, repo: RepoDep):
    """The finding's evidence as a path: each step's node, the function or file that holds it, and
    the stored edge to the next step (a call, a data-flow hop, a dependency)."""
    finding = await repo.get_finding(project_id, finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")
    return await load_evidence(repo, project_id, finding)


@rules_router.get("/rules", response_model=RuleCatalogueInfo)
async def list_rules():
    """Registered rules with their category and CWE ids, plus the pattern catalogue version."""
    catalogue = load_catalogue()
    return RuleCatalogueInfo(
        catalogue_version=catalogue.version, catalogue_digest=catalogue.digest,
        rules=[a.info() for a in REGISTRY],
    )
