import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.api.deps import RepoDep
from app.models.analysis import Category
from app.services.sarif import sarif_log

router = APIRouter(prefix="/projects/{project_id}", tags=["analysis"])


@router.get("/findings.sarif", response_class=JSONResponse,
            responses={200: {"content": {"application/sarif+json": {}}}})
async def findings_sarif(project_id: str, repo: RepoDep, category: Category | None = None):
    """The project's findings as a SARIF 2.1.0 log (one run), with evidence paths as code flows.
    Opens in VS Code's SARIF viewer with the scanned project as the workspace."""
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    findings = await repo.list_findings(project_id, category=category)
    log = await sarif_log(repo, project, findings)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", project.name).strip("-") or "codegraph"
    return JSONResponse(log, media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="{stem}.sarif"'})
