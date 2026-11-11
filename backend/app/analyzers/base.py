"""An Analyzer is a rule expressed as a graph query. Subclass, decorate with @register, and
import the module from app/analyzers/__init__.py."""
from abc import ABC, abstractmethod
from collections.abc import Sequence
from uuid import uuid4

from app.graph.repository import GraphRepository
from app.models.analysis import Category, Confidence, Finding, RuleInfo, Severity


class Analyzer(ABC):
    rule: str
    severity: Severity
    description: str = ""
    category: Category = Category.quality
    cwe: tuple[str, ...] = ()
    # Languages the rule applies to; None = all. The analysis service skips a rule when the
    # project has no files in any of its languages.
    languages: tuple[str, ...] | None = None
    # Bump when the rule's logic changes, so stored findings say which logic produced them.
    version: str = "1"

    @abstractmethod
    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]: ...

    def applies_to(self, project_languages: set[str]) -> bool:
        return self.languages is None or bool(project_languages.intersection(self.languages))

    def info(self) -> RuleInfo:
        return RuleInfo(
            rule=self.rule, severity=self.severity, description=self.description,
            category=self.category, cwe=list(self.cwe),
            languages=list(self.languages) if self.languages is not None else None,
            version=self.version,
        )

    def finding(self, project_id: str, message: str, *, node_id: str | None = None,
                file: str | None = None, line: int | None = None, line_end: int | None = None,
                severity: Severity | None = None, confidence: Confidence = Confidence.high,
                cwe: Sequence[str] | None = None, evidence: Sequence[str] = ()) -> Finding:
        return Finding(
            id=uuid4().hex, project_id=project_id, rule=self.rule,
            severity=severity or self.severity, message=message,
            node_id=node_id, file=file, line=line, line_end=line_end,
            category=self.category, confidence=confidence,
            cwe=list(cwe if cwe is not None else self.cwe), evidence=list(evidence),
            rule_version=self.version,
        )


REGISTRY: list[Analyzer] = []


def register(cls: type[Analyzer]) -> type[Analyzer]:
    REGISTRY.append(cls())
    return cls
