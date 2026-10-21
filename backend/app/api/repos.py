import asyncio

from fastapi import APIRouter, Query

from app.api.deps import RepoDep
from app.models.analysis import RepoListing
from app.services.repos import list_repo_dirs

router = APIRouter(prefix="/repos", tags=["repos"])


@router.get("", response_model=RepoListing)
async def list_repos(
    repo: RepoDep,
    path: str = Query("", description="Directory under REPOS_ROOT to list; empty for the root itself"),
):
    """Browse the folders available for scanning.

    Each entry says how many parseable source files it holds and, if a project already points at
    it, which one, so the UI can open that project instead of scanning the folder twice.
    """
    projects = await repo.list_projects()
    # Walking the tree to count files is blocking I/O; keep it off the event loop.
    dirs = await asyncio.to_thread(list_repo_dirs, path, projects)
    return RepoListing(path=path.strip("/"), dirs=dirs)
