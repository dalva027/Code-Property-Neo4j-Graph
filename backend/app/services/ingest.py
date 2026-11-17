"""Scanning a source tree into the graph, as a background task per project.

A scan is started by creating or rescanning a project and runs in this process: parsing happens in a
worker thread, the graph writes on the event loop. The project node carries the state (`scanning`,
`ready`, `failed`) so clients poll `GET /projects/{id}/status` or the project itself.
"""
import asyncio
import contextlib
import logging
from pathlib import Path

from fastapi import HTTPException

from app.config import settings
from app.graph.builder import GraphBuilder
from app.graph.deps import scan_dependencies
from app.graph.repository import GraphRepository
from app.models.analysis import Project, ProjectCreate, ScanState

log = logging.getLogger(__name__)

_tasks: dict[str, asyncio.Task[None]] = {}


def resolve_repo_path(relative: str) -> Path:
    """Map a user-supplied path onto REPOS_ROOT and refuse anything that escapes it."""
    root = Path(settings.repos_root).resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(400, "path must stay inside REPOS_ROOT")
    if not target.is_dir():
        raise HTTPException(404, f"{relative!r} is not a directory under REPOS_ROOT")
    return target


def scan_in_progress(project_id: str) -> bool:
    task = _tasks.get(project_id)
    return task is not None and not task.done()


async def build_and_store(project: Project, repo: GraphRepository) -> None:
    """Parse the project's tree, scan its Cargo lockfiles, and replace the stored graph.

    Runs inline; the background task wraps it. Parsing and the extractor are blocking, so both run
    in a worker thread.
    """
    root = Path(project.root)
    builder = GraphBuilder()
    graph = await asyncio.to_thread(builder.build, root, project.id)
    deps = await asyncio.to_thread(scan_dependencies, root, project.id, graph)
    deps.warnings.extend(builder.warnings)
    if (code := builder.code_facts) is not None:
        deps.warnings.extend(code.warnings)
        log.info("%s: code facts for %d of %d functions, %d of %d call sites resolved, %d flow edges",
                 project.name, code.analyzed, code.functions, code.resolved_sites, code.sites, code.flows)
    await repo.replace_graph(project.id, graph)
    await repo.replace_dependencies(project.id, deps)
    reachable = await repo.mark_reachability(project.id)
    await repo.aggregate_crate_metrics(project.id)
    log.info("%s: %d functions reachable from an entry point", project.name, reachable)
    await repo.set_scan_notes(project.id, deps.warnings, deps.advisory_db_commit)


async def _scan(project: Project, repo: GraphRepository) -> None:
    try:
        await build_and_store(project, repo)
    except Exception as exc:                  # reported on the project, not re-raised
        log.exception("scan of %s (%s) failed", project.name, project.id)
        await repo.mark_scan_finished(project.id, error=f"{type(exc).__name__}: {exc}")
    else:
        await repo.mark_scan_finished(project.id)
        log.info("scan of %s (%s) finished", project.name, project.id)


def _start(project: Project, repo: GraphRepository) -> None:
    task = asyncio.create_task(_scan(project, repo), name=f"scan:{project.id}")
    _tasks[project.id] = task
    task.add_done_callback(lambda _: _tasks.pop(project.id, None) if _tasks.get(project.id) is task else None)


async def ingest_project(payload: ProjectCreate, repo: GraphRepository) -> Project:
    """Create the project and start scanning it; returns at once with status `scanning`."""
    root = resolve_repo_path(payload.path)
    project = await repo.create_project(payload.name, root.as_posix())
    _start(project, repo)
    return project


async def reingest_project(project_id: str, repo: GraphRepository) -> Project:
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    if scan_in_progress(project_id):
        raise HTTPException(409, "a scan of this project is already running")
    if not Path(project.root).is_dir():
        raise HTTPException(404, f"project root {project.root} no longer exists")
    await repo.mark_scan_started(project_id)
    _start(project, repo)
    refreshed = await repo.get_project(project_id)
    assert refreshed is not None
    return refreshed


async def cancel_scan(project_id: str) -> None:
    """Stop a running scan, e.g. before deleting its project. The parse thread finishes on its own."""
    task = _tasks.get(project_id)
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def wait_for_scan(project_id: str) -> None:
    task = _tasks.get(project_id)
    if task is not None:
        await asyncio.shield(task)


def require_ready(project: Project) -> None:
    """Graph and analysis endpoints refuse to run against a graph that is being rewritten."""
    if project.status == ScanState.scanning:
        raise HTTPException(409, "the project is still being scanned")
