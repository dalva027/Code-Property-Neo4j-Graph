"""Score findings against a ground-truth file: per-rule and per-category precision and recall.

Ground truth is an `expected.json` next to (or anywhere outside) the scanned project:

    {
      "description": "why these findings are expected",
      "requires": ["extractor"],                          # optional; skipped without the binary
      "scope": {"categories": ["quality", "unsafe"]},     # optional; default: every category
      "findings": [{"rule": "unused-function", "file": "src/utils.rs", "line": 2}]
    }

`scope` may instead (or also) list `rules`. Only findings inside the scope are scored. A finding
matches an expected entry when rule and file agree and the expected line falls within the finding's
`line`..`line_end` (or equals `line`). Each finding matches at most one expected entry.

Command line, against the configured Neo4j:

    python -m app.evaluate --project <id> --expected repos/sample-rust/expected.json
    python -m app.evaluate --path sample-rust --expected repos/sample-rust/expected.json

`--path` scans a directory under REPOS_ROOT into a throwaway project, analyzes it, scores it and
deletes it again (`--keep` leaves it). Exit status is 0 when every rule in scope scores 1/1.
"""
import argparse
import asyncio
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from app.models.analysis import Category, Finding, RuleInfo


class ExpectedFinding(BaseModel):
    rule: str
    file: str
    line: int | None = None
    note: str | None = None


class Scope(BaseModel):
    categories: list[Category] | None = None
    rules: list[str] | None = None


class Expected(BaseModel):
    description: str = ""
    # Capabilities the case needs; "extractor" = codegraph-extract with an advisory database.
    requires: list[str] = Field(default_factory=list)
    scope: Scope = Field(default_factory=Scope)
    findings: list[ExpectedFinding] = Field(default_factory=list)


def load_expected(path: Path) -> Expected:
    return Expected.model_validate_json(path.read_text(encoding="utf-8"))


@dataclass
class RuleScore:
    rule: str
    category: Category
    expected: int = 0
    predicted: int = 0
    true_positives: int = 0
    missed: list[ExpectedFinding] = field(default_factory=list)
    unexpected: list[Finding] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        return self.true_positives / self.predicted if self.predicted else None

    @property
    def recall(self) -> float | None:
        return self.true_positives / self.expected if self.expected else None

    @property
    def ok(self) -> bool:
        return not self.missed and not self.unexpected


@dataclass
class Report:
    rules: list[RuleScore]
    categories: dict[Category, RuleScore]

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.rules)

    def failures(self) -> list[str]:
        lines = []
        for r in self.rules:
            lines += [f"missed {m.rule} at {m.file}:{m.line}" for m in r.missed]
            lines += [f"unexpected {u.rule} at {u.file}:{u.line}: {u.message}" for u in r.unexpected]
        return lines

    def to_dict(self) -> dict:
        def row(s: RuleScore) -> dict:
            return {"rule": s.rule, "category": s.category.value, "expected": s.expected,
                    "predicted": s.predicted, "true_positives": s.true_positives,
                    "precision": s.precision, "recall": s.recall}
        return {"ok": self.ok, "rules": [row(r) for r in self.rules],
                "categories": [row(c) for c in self.categories.values()], "failures": self.failures()}


def _in_scope(rule: str, category: Category, scope: Scope) -> bool:
    if scope.rules is not None and rule not in scope.rules:
        return False
    return scope.categories is None or category in scope.categories


def _matches(finding: Finding, want: ExpectedFinding) -> bool:
    if finding.rule != want.rule or finding.file != want.file:
        return False
    if want.line is None:
        return True
    start = finding.line or 0
    return start <= want.line <= (finding.line_end or start)


def score(expected: Expected, findings: Iterable[Finding], rules: Sequence[RuleInfo]) -> Report:
    """Compare findings with the expected list. `rules` supplies categories and zero-count rows."""
    category_of = {r.rule: r.category for r in rules}
    for want in expected.findings:
        category_of.setdefault(want.rule, Category.quality)
    for f in findings:
        category_of.setdefault(f.rule, f.category)

    scores = {rule: RuleScore(rule, cat) for rule, cat in category_of.items()
              if _in_scope(rule, cat, expected.scope)}
    predicted = [f for f in findings if f.rule in scores]
    for f in predicted:
        scores[f.rule].predicted += 1

    unmatched = list(predicted)
    for want in expected.findings:
        if want.rule not in scores:
            continue
        s = scores[want.rule]
        s.expected += 1
        hit = next((f for f in unmatched if _matches(f, want)), None)
        if hit is None:
            s.missed.append(want)
        else:
            unmatched.remove(hit)
            s.true_positives += 1
    for f in unmatched:
        scores[f.rule].unexpected.append(f)

    categories: dict[Category, RuleScore] = {}
    in_scope_categories = expected.scope.categories or list(Category)
    for cat in in_scope_categories:
        total = categories[cat] = RuleScore(cat.value, cat)
        for s in scores.values():
            if s.category == cat:
                total.expected += s.expected
                total.predicted += s.predicted
                total.true_positives += s.true_positives
                total.missed += s.missed
                total.unexpected += s.unexpected
    ordered = sorted(scores.values(), key=lambda s: (list(Category).index(s.category), s.rule))
    return Report(rules=ordered, categories=categories)


def format_report(report: Report) -> str:
    def pct(value: float | None) -> str:
        return "   -  " if value is None else f"{value:6.2f}"

    header = f"{'rule':28} {'category':11} {'exp':>4} {'pred':>4} {'tp':>4} {'prec':>6} {'recall':>6}"
    lines = [header, "-" * len(header)]
    for s in report.rules:
        lines.append(f"{s.rule:28} {s.category.value:11} {s.expected:4} {s.predicted:4} "
                     f"{s.true_positives:4} {pct(s.precision)} {pct(s.recall)}")
    lines += ["", f"{'category':40} {'exp':>4} {'pred':>4} {'tp':>4} {'prec':>6} {'recall':>6}"]
    for cat, s in report.categories.items():
        lines.append(f"{cat.value:40} {s.expected:4} {s.predicted:4} {s.true_positives:4} "
                     f"{pct(s.precision)} {pct(s.recall)}")
    if failures := report.failures():
        lines += ["", *failures]
    lines += ["", "OK" if report.ok else "MISMATCH"]
    return "\n".join(lines)


# -- command line ---------------------------------------------------------------------------------
async def _findings_for(args: argparse.Namespace) -> list[Finding]:
    from app.db import neo4j
    from app.graph.repository import GraphRepository
    from app.models.analysis import ProjectCreate
    from app.services.analysis import analyze_project
    from app.services.ingest import build_and_store, resolve_repo_path

    await neo4j.connect()
    await neo4j.apply_schema()
    repo = GraphRepository()
    try:
        if args.project:
            if await repo.get_project(args.project) is None:
                raise SystemExit(f"no project {args.project!r}")
            if args.analyze:
                await analyze_project(args.project, repo)
            return await repo.list_findings(args.project)

        payload = ProjectCreate(name=f"evaluate:{args.path}", path=args.path)
        project = await repo.create_project(payload.name, resolve_repo_path(payload.path).as_posix())
        try:
            await build_and_store(project, repo)
            await repo.mark_scan_finished(project.id)
            await analyze_project(project.id, repo)
            return await repo.list_findings(project.id)
        finally:
            if args.keep:
                print(f"kept project {project.id}", file=sys.stderr)
            else:
                await repo.delete_project(project.id)
    finally:
        await neo4j.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.evaluate", description=__doc__.split("\n\n")[0])
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="id of an existing, analyzed project")
    target.add_argument("--path", help="directory under REPOS_ROOT to scan into a throwaway project")
    parser.add_argument("--expected", required=True, type=Path, help="ground-truth expected.json")
    parser.add_argument("--analyze", action="store_true", help="with --project: re-run analysis first")
    parser.add_argument("--keep", action="store_true", help="with --path: keep the project afterwards")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    from app.analyzers import REGISTRY

    expected = load_expected(args.expected)
    findings = asyncio.run(_findings_for(args))
    report = score(expected, findings, [a.info() for a in REGISTRY])
    print(json.dumps(report.to_dict(), indent=2) if args.json else format_report(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
