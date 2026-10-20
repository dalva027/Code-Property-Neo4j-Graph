from fastapi import APIRouter, HTTPException, status

from app.api.deps import RepoDep
from app.models.analysis import Project, ProjectCreate
from app.services.ingest import ingest_project, reingest_project

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[Project])
async def list_projects(repo: RepoDep):
    return await repo.list_projects()


@router.post("", response_model=Project, status_code=status.HTTP_201_CREATED)
async def create_project(payload: ProjectCreate, repo: RepoDep):
    """Register a directory under REPOS_ROOT and build its code graph."""
    return await ingest_project(payload, repo)


@router.get("/{project_id}", response_model=Project)
async def get_project(project_id: str, repo: RepoDep):
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    return project


@router.post("/{project_id}/ingest", response_model=Project)
async def reingest(project_id: str, repo: RepoDep):
    """Re-scan the source tree and rebuild the graph. Existing findings are cleared."""
    return await reingest_project(project_id, repo)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: str, repo: RepoDep):
    await repo.delete_project(project_id)
