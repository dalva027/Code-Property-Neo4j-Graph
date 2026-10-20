"""Neo4j driver lifecycle and a thin query helper.

Only app.graph.repository should import this; everything else goes through the repository.
"""
import asyncio
import logging
from pathlib import Path
from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import ServiceUnavailable

from app.config import settings

log = logging.getLogger(__name__)

_driver: AsyncDriver | None = None
SCHEMA_FILE = Path(__file__).with_name("schema.cypher")


async def connect(retries: int = 10, delay: float = 2.0) -> AsyncDriver:
    """Open the driver, waiting for the database to accept connections (handy under compose)."""
    global _driver
    if _driver is not None:
        return _driver

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    for attempt in range(1, retries + 1):
        try:
            await driver.verify_connectivity()
            break
        except ServiceUnavailable:
            if attempt == retries:
                raise
            log.warning("Neo4j not ready (attempt %d/%d), retrying in %.0fs", attempt, retries, delay)
            await asyncio.sleep(delay)
    _driver = driver
    return driver


async def close() -> None:
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None


def get_driver() -> AsyncDriver:
    if _driver is None:
        raise RuntimeError("Neo4j driver not initialised; call connect() first")
    return _driver


async def run(query: str, **params: Any) -> list[dict[str, Any]]:
    """Run one Cypher statement in a managed transaction and return rows as dicts."""
    result = await get_driver().execute_query(query, params, database_=settings.neo4j_database)
    return [record.data() for record in result.records]


async def apply_schema() -> None:
    """Idempotently create constraints and indexes from schema.cypher."""
    statements = [s.strip() for s in SCHEMA_FILE.read_text().split(";") if s.strip()]
    for statement in statements:
        await run(statement)
