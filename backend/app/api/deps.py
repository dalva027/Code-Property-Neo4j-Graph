from typing import Annotated

from fastapi import Depends

from app.graph.repository import GraphRepository


def get_repo() -> GraphRepository:
    return GraphRepository()


RepoDep = Annotated[GraphRepository, Depends(get_repo)]
