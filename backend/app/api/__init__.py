from fastapi import APIRouter

from app.api import advisories, findings, graph, projects, repos

api_router = APIRouter()
api_router.include_router(projects.router)
api_router.include_router(repos.router)
api_router.include_router(graph.router)
api_router.include_router(findings.router)
api_router.include_router(findings.rules_router)
api_router.include_router(advisories.router)
