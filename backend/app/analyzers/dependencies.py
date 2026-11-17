"""Class D: vulnerable and risky dependencies (docs/build-plan.md section 3).

D1 is cargo-audit parity: one finding per vulnerable crate version and advisory. D2 is the triage a
graph adds on top: for each such pair, does the code call an affected function, use the crate at
all, reach it only through another dependency it uses, or not touch it? Exactly one D2 rule fires per
pair. D3 covers informational advisories, D5 duplicate versions.
"""
from typing import Any

from app.analyzers.base import Analyzer, register
from app.graph.repository import GraphRepository
from app.models.analysis import Category, Confidence, Finding, Severity

VULNERABILITIES = """
MATCH (c:Crate {project_id: $pid})-[a:AFFECTED_BY {kind: 'vulnerability'}]->(adv:Advisory)
RETURN c.id AS crate, c.name AS name, c.version AS version, c.file AS file, c.line_start AS line,
       c.workspace_member AS member, adv.id AS advisory, adv.title AS title, adv.cvss_score AS score,
       adv.patched AS patched, coalesce(a.functions, []) AS functions
ORDER BY c.name, c.version, adv.id
"""

TRIAGE = """
MATCH (c:Crate {project_id: $pid})-[a:AFFECTED_BY {kind: 'vulnerability'}]->(adv:Advisory)
CALL (c, a) {
  OPTIONAL MATCH (f:Function)-[call:CALLS]->(e:External)-[:FROM_CRATE]->(c)
  WHERE e.path IN coalesce(a.functions, [])
     OR any(alias IN coalesce(e.aliases, []) WHERE alias IN coalesce(a.functions, []))
  WITH f, call, e ORDER BY f.file, call.line
  RETURN [x IN collect(CASE WHEN f IS NULL THEN null ELSE
          {function: f.id, qname: f.qualified_name, file: f.file, line: coalesce(call.line, f.line_start),
           external: e.id, path: e.path} END) WHERE x IS NOT NULL] AS reaching
}
CALL (c) {
  OPTIONAL MATCH (:Function)-[:CALLS]->(e:External)-[:FROM_CRATE]->(c)
  RETURN count(DISTINCT e) AS called
}
CALL (c) {
  OPTIONAL MATCH (file:File)-[:USES]->(c)
  RETURN count(DISTINCT file) AS imported
}
CALL (c) {
  OPTIONAL MATCH (m:Crate {project_id: $pid, workspace_member: true})-[:DEPENDS_ON]->(d:Crate)
  WHERE d <> c AND (EXISTS { (:Function)-[:CALLS]->(:External)-[:FROM_CRATE]->(d) }
                    OR EXISTS { (:File)-[:USES]->(d) })
  OPTIONAL MATCH p = shortestPath((d)-[:DEPENDS_ON*1..15]->(c))
  WITH m, d, p WHERE p IS NOT NULL
  WITH m, d, p ORDER BY length(p), d.name
  RETURN head(collect({via: d.name, path: [m.id] + [n IN nodes(p) | n.id]})) AS through
}
RETURN c.id AS crate, c.name AS name, c.version AS version, c.file AS file, c.line_start AS line,
       adv.id AS advisory, adv.title AS title, adv.cvss_score AS score,
       coalesce(a.functions, []) AS functions, reaching, called, imported, through
ORDER BY c.name, c.version, adv.id
"""


def cvss_severity(score: float | None) -> Severity:
    """RustSec advisories without a CVSS vector still describe vulnerabilities: warning, not info."""
    if score is None:
        return Severity.warning
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.error
    if score >= 4.0:
        return Severity.warning
    return Severity.info


def _cvss(score: float | None) -> str:
    return "" if score is None else f" (CVSS {score})"


def _fixed_in(patched: list[str] | None) -> str:
    return f"; fixed in {', '.join(patched)}" if patched else "; no fixed version"


async def _triage(repo: GraphRepository, project_id: str) -> list[dict[str, Any]]:
    key = ("triage", project_id)
    if key in repo.memo:
        return repo.memo[key]
    rows = repo.memo[key] = await repo.query(TRIAGE, pid=project_id)
    for r in rows:
        if r["reaching"]:
            r["outcome"] = "reachable"
        elif r["called"] or r["imported"]:
            r["outcome"] = "used"
        elif r["through"]:
            r["outcome"] = "through"
        else:
            r["outcome"] = "unused"
    return rows


class _DependencyRule(Analyzer):
    category = Category.dependency
    languages = ("rust",)
    cwe = ("CWE-1395",)


@register
class VulnerableDependency(_DependencyRule):
    rule = "vulnerable-dependency"
    severity = Severity.warning
    description = ("A crate version in Cargo.lock is affected by a RustSec vulnerability advisory, as cargo-audit "
                   "reports it. Severity follows the advisory's CVSS score.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        return [
            self.finding(
                project_id,
                f"{r['name']} {r['version']} is affected by {r['advisory']}: {r['title']}"
                f"{_cvss(r['score'])}{_fixed_in(r['patched'])}",
                node_id=r["crate"], file=r["file"], line=r["line"], severity=cvss_severity(r["score"]),
                evidence=[r["crate"], r["advisory"]],
            )
            for r in await repo.query(VULNERABILITIES, pid=project_id)
        ]


@register
class VulnerableApiReachable(_DependencyRule):
    rule = "vulnerable-api-reachable"
    severity = Severity.error
    description = ("The code calls a function that a vulnerability advisory names as affected, in the affected "
                   "crate version. The finding sits on the first calling function.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = []
        for r in await _triage(repo, project_id):
            if r["outcome"] != "reachable":
                continue
            first, others = r["reaching"][0], len(r["reaching"]) - 1
            more = f" and {others} more call site{'s' if others > 1 else ''}" if others else ""
            findings.append(self.finding(
                project_id,
                f"{first['qname']} calls {first['path']}, affected by {r['advisory']} in {r['name']} "
                f"{r['version']}: {r['title']}{more}",
                node_id=first["function"], file=first["file"], line=first["line"],
                severity=max(cvss_severity(r["score"]), Severity.error, key=_rank),
                evidence=[first["function"], first["external"], r["crate"], r["advisory"]],
            ))
        return findings


@register
class VulnerableCrateUsed(_DependencyRule):
    rule = "vulnerable-crate-used"
    severity = Severity.warning
    description = ("The code uses a crate with a vulnerability advisory, but no call to an affected function was "
                   "seen: medium confidence when it calls the crate, low when it only imports it or reaches it "
                   "through another dependency it uses. Calls on receivers of unknown type are not matched.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = []
        for r in await _triage(repo, project_id):
            if r["outcome"] == "used":
                how = f"calls it at {r['called']} distinct path(s)" if r["called"] else "imports it but no call was seen"
                confidence = Confidence.medium if r["called"] else Confidence.low
                evidence = [r["crate"], r["advisory"]]
            elif r["outcome"] == "through":
                how = f"reaches it through {r['through']['via']}, which the code uses"
                confidence = Confidence.low
                evidence = [*r["through"]["path"], r["advisory"]]
            else:
                continue
            listed = (f"; none of the {len(r['functions'])} affected functions is called directly"
                      if r["functions"] else "; the advisory lists no affected functions")
            findings.append(self.finding(
                project_id, f"{r['name']} {r['version']} has {r['advisory']} ({r['title']}); the code {how}{listed}",
                node_id=r["crate"], file=r["file"], line=r["line"], confidence=confidence, evidence=evidence,
            ))
        return findings


@register
class VulnerableDependencyUnused(_DependencyRule):
    rule = "vulnerable-dependency-unused"
    severity = Severity.info
    description = ("A crate with a vulnerability advisory that the code neither calls nor imports, directly or "
                   "through a dependency it uses. Usually safe to deprioritise; derives and macros can still use "
                   "it, so confidence is medium.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        return [
            self.finding(
                project_id,
                f"{r['name']} {r['version']} has {r['advisory']} ({r['title']}), but the code does not use it",
                node_id=r["crate"], file=r["file"], line=r["line"], confidence=Confidence.medium,
                evidence=[r["crate"], r["advisory"]],
            )
            for r in await _triage(repo, project_id) if r["outcome"] == "unused"
        ]


@register
class UnmaintainedOrUnsound(_DependencyRule):
    rule = "unmaintained-or-unsound-dependency"
    severity = Severity.info
    cwe = ("CWE-1104",)
    description = ("An informational RustSec advisory: the crate is unmaintained, unsound, or has a notice. Unsound "
                   "is a warning, the others info. Yanked versions need the crates.io index and are not checked.")

    QUERY = """
    MATCH (c:Crate {project_id: $pid})-[a:AFFECTED_BY]->(adv:Advisory)
    WHERE a.kind IN ['unmaintained', 'unsound', 'notice']
    RETURN c.id AS crate, c.name AS name, c.version AS version, c.file AS file, c.line_start AS line,
           a.kind AS kind, adv.id AS advisory, adv.title AS title
    ORDER BY c.name, adv.id
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        return [
            self.finding(
                project_id, f"{r['name']} {r['version']} is {r['kind']} ({r['advisory']}): {r['title']}",
                node_id=r["crate"], file=r["file"], line=r["line"],
                severity=Severity.warning if r["kind"] == "unsound" else Severity.info,
                evidence=[r["crate"], r["advisory"]],
            )
            for r in await repo.query(self.QUERY, pid=project_id)
        ]


@register
class DuplicateCrateVersions(_DependencyRule):
    rule = "duplicate-crate-versions"
    severity = Severity.info
    cwe = ()
    description = "The same crate appears in Cargo.lock at several versions, which grows builds and patch effort."

    QUERY = """
    MATCH (c:Crate {project_id: $pid}) WHERE NOT c.workspace_member
    WITH c.name AS name, c.file AS file, collect(c) AS versions WHERE size(versions) > 1
    UNWIND versions AS c
    WITH name, file, c ORDER BY c.line_start
    WITH name, file, collect(c) AS versions
    RETURN name, file, versions[0].id AS crate, versions[0].line_start AS line,
           [v IN versions | v.version] AS list
    ORDER BY name
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        return [
            self.finding(project_id, f"{r['name']} is locked at {len(r['list'])} versions: {', '.join(r['list'])}",
                         node_id=r["crate"], file=r["file"], line=r["line"],
                         evidence=[r["crate"]])
            for r in await repo.query(self.QUERY, pid=project_id)
        ]


def _rank(severity: Severity) -> int:
    return [Severity.info, Severity.warning, Severity.error, Severity.critical].index(severity)
