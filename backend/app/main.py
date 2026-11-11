import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import settings
from app.db import neo4j
from app.graph.repository import GraphRepository
from app.rules import load_catalogue

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    catalogue = load_catalogue()           # fail fast on a broken catalogue
    log.info("rule catalogue %s (%s)", catalogue.version, catalogue.digest[:12])
    await neo4j.connect()
    await neo4j.apply_schema()
    if interrupted := await GraphRepository().fail_interrupted_scans():
        log.warning("%d scan(s) were interrupted by the restart and marked failed", interrupted)
    yield
    await neo4j.close()


app = FastAPI(
    title="CodeGraph API",
    version="0.1.0",
    description="Static analysis over a Neo4j code graph.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(api_router, prefix="/api")


@app.get("/api/health", tags=["meta"])
async def health():
    await neo4j.run("RETURN 1")
    return {"status": "ok"}
