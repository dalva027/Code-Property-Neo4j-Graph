import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.config import settings
from app.db import neo4j

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await neo4j.connect()
    await neo4j.apply_schema()
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
