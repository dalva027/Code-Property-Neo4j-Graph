import asyncio
from pathlib import Path

from fastapi import HTTPException

from app.config import settings
from app.graph.builder import GraphBuilder
from app.graph.repository import GraphRepository
from app.models.analysis import Project, ProjectCreate


def resolve_repo_path(relative: str) -> Path:
    """Map a user-supplied path onto REPOS_ROOT and refuse anything that escapes it."""
    root = Path(settings.repos_root).resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(400, "path must stay inside REPOS_ROOT")
    if not target.is_dir():
        raise HTTPException(404, f"{relative!r} is not a directory under REPOS_ROOT")
    return target


async def _build_and_store(project: Project, repo: GraphRepository) -> Project:
    # Parsing is CPU-bound; keep it off the event loop.
    graph = await asyncio.to_thread(GraphBuilder().build, Path(project.root), project.id)
    await repo.replace_graph(project.id, graph)
    refreshed = await repo.get_project(project.id)
    assert refreshed is not None
    return refreshed


async def ingest_project(payload: ProjectCreate, repo: GraphRepository) -> Project:
    root = resolve_repo_path(payload.path)
    project = await repo.create_project(payload.name, root.as_posix())
    try:
        return await _build_and_store(project, repo)
    except Exception:
        await repo.delete_project(project.id)
        raise


async def reingest_project(project_id: str, repo: GraphRepository) -> Project:
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    if not Path(project.root).is_dir():
        raise HTTPException(404, f"project root {project.root} no longer exists")
    return await _build_and_store(project, repo)
