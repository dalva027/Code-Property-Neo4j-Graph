"""An Analyzer is a rule expressed as a graph query. Subclass, decorate with @register, and
import the module from app/analyzers/__init__.py."""
from abc import ABC, abstractmethod
from uuid import uuid4

from app.graph.repository import GraphRepository
from app.models.analysis import Finding, Severity


class Analyzer(ABC):
    rule: str
    severity: Severity
    description: str = ""

    @abstractmethod
    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]: ...

    def finding(self, project_id: str, message: str, *, node_id: str | None = None,
                file: str | None = None, line: int | None = None,
                severity: Severity | None = None) -> Finding:
        return Finding(
            id=uuid4().hex, project_id=project_id, rule=self.rule,
            severity=severity or self.severity, message=message,
            node_id=node_id, file=file, line=line,
        )


REGISTRY: list[Analyzer] = []


def register(cls: type[Analyzer]) -> type[Analyzer]:
    REGISTRY.append(cls())
    return cls
