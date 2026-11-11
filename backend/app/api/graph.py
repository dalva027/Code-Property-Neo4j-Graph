from fastapi import APIRouter, HTTPException, Query

from app.api.deps import RepoDep
from app.models.analysis import NodeDetail
from app.models.graph import CodeGraph
from app.services.ingest import require_ready

router = APIRouter(prefix="/projects/{project_id}", tags=["graph"])


@router.get("/graph", response_model=CodeGraph)
async def get_graph(project_id: str, repo: RepoDep, limit: int = Query(5000, ge=1, le=50_000)):
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    require_ready(project)
    return await repo.get_graph(project_id, limit=limit)


@router.get("/node", response_model=NodeDetail)
async def get_node(project_id: str, repo: RepoDep, id: str = Query(..., description="node id")):
    """One node plus its incoming/outgoing edges and attached findings.

    Node ids contain slashes and dots, so they travel as a query parameter rather than a path segment.
    """
    detail = await repo.get_node(project_id, id)
    if detail is None:
        raise HTTPException(404, "node not found")
    return detail
