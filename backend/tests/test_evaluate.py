"""Scoring of findings against expected.json; no Neo4j needed."""
from app.evaluate import Expected, format_report, score
from app.models.analysis import Category, Finding, RuleInfo, Severity

RULES = [
    RuleInfo(rule="unused-function", severity=Severity.warning, description="", category=Category.quality, version="1"),
    RuleInfo(rule="undocumented-unsafe", severity=Severity.warning, description="", category=Category.unsafe,
             version="1"),
]


def finding(rule: str, file: str, line: int, line_end: int | None = None, category=Category.quality) -> Finding:
    return Finding(id=f"{rule}{file}{line}", project_id="p", rule=rule, severity=Severity.warning,
                   message="m", file=file, line=line, line_end=line_end, category=category)


def expected(*items: tuple[str, str, int], **scope) -> Expected:
    return Expected.model_validate({"scope": scope,
                                    "findings": [{"rule": r, "file": f, "line": n} for r, f, n in items]})


def test_exact_match_scores_one():
    report = score(expected(("unused-function", "a.rs", 3)), [finding("unused-function", "a.rs", 3)], RULES)
    assert report.ok
    row = next(r for r in report.rules if r.rule == "unused-function")
    assert (row.precision, row.recall) == (1.0, 1.0)


def test_missed_and_unexpected_are_reported():
    report = score(expected(("unused-function", "a.rs", 3)), [finding("unused-function", "a.rs", 9)], RULES)
    assert not report.ok
    row = next(r for r in report.rules if r.rule == "unused-function")
    assert (row.true_positives, row.precision, row.recall) == (0, 0.0, 0.0)
    assert any("missed" in f for f in report.failures()) and any("unexpected" in f for f in report.failures())


def test_expected_line_inside_finding_span_matches_once():
    report = score(expected(("unused-function", "a.rs", 5), ("unused-function", "a.rs", 6)),
                   [finding("unused-function", "a.rs", 4, line_end=8)], RULES)
    row = next(r for r in report.rules if r.rule == "unused-function")
    assert row.true_positives == 1 and len(row.missed) == 1             # one finding, one match


def test_empty_security_scope_is_vacuously_ok_and_listed():
    report = score(expected(categories=["unsafe"]), [finding("unused-function", "a.rs", 3)], RULES)
    assert report.ok                                                     # quality is out of scope
    assert [r.rule for r in report.rules] == ["undocumented-unsafe"]
    assert report.categories[Category.unsafe].predicted == 0
    assert report.rules[0].precision is None and report.rules[0].recall is None


def test_unexpected_security_finding_fails():
    report = score(expected(), [finding("undocumented-unsafe", "a.rs", 1, category=Category.unsafe)], RULES)
    assert not report.ok
    assert "MISMATCH" in format_report(report)
