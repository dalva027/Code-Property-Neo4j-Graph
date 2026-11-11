from fastapi import APIRouter, HTTPException

from app.api.deps import RepoDep
from app.models.deps import BlastRadius, ProjectAdvisory
from app.services.ingest import require_ready

router = APIRouter(prefix="/projects/{project_id}", tags=["dependencies"])


async def _ready_project(project_id: str, repo: RepoDep) -> None:
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    require_ready(project)


@router.get("/advisories", response_model=list[ProjectAdvisory])
async def list_advisories(project_id: str, repo: RepoDep):
    """RustSec advisories affecting the project's Cargo.lock files, with the crate versions they hit."""
    await _ready_project(project_id, repo)
    return await repo.list_advisories(project_id)


@router.get("/advisories/{advisory_id}/blast-radius", response_model=BlastRadius)
async def blast_radius(project_id: str, advisory_id: str, repo: RepoDep):
    """For one advisory: the affected crate versions, the dependency paths from workspace members to
    each, the functions that call into them, and the files that import them."""
    await _ready_project(project_id, repo)
    radius = await repo.blast_radius(project_id, advisory_id)
    if radius is None:
        raise HTTPException(404, f"{advisory_id} does not affect this project")
    return radius
