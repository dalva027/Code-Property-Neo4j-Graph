from fastapi import APIRouter, HTTPException, status

from app.api.deps import RepoDep
from app.models.analysis import Project, ProjectCreate, ScanStatus
from app.services.ingest import cancel_scan, ingest_project, reingest_project

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[Project])
async def list_projects(repo: RepoDep):
    return await repo.list_projects()


@router.post("", response_model=Project, status_code=status.HTTP_202_ACCEPTED)
async def create_project(payload: ProjectCreate, repo: RepoDep):
    """Register a directory under REPOS_ROOT and start building its code graph.

    Returns at once with `status: scanning`; poll `/projects/{id}/status` until it is `ready`.
    """
    return await ingest_project(payload, repo)


@router.get("/{project_id}", response_model=Project)
async def get_project(project_id: str, repo: RepoDep):
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    return project


@router.get("/{project_id}/status", response_model=ScanStatus)
async def get_scan_status(project_id: str, repo: RepoDep):
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    return ScanStatus(
        project_id=project.id, status=project.status, error=project.error,
        scan_started_at=project.scan_started_at, scan_finished_at=project.scan_finished_at,
        file_count=project.file_count, symbol_count=project.symbol_count,
        warnings=project.warnings, advisory_db_commit=project.advisory_db_commit,
    )


@router.post("/{project_id}/ingest", response_model=Project, status_code=status.HTTP_202_ACCEPTED)
async def reingest(project_id: str, repo: RepoDep):
    """Start re-scanning the source tree. Existing findings are cleared when the new graph is written."""
    return await reingest_project(project_id, repo)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: str, repo: RepoDep):
    await cancel_scan(project_id)
    await repo.delete_project(project_id)
