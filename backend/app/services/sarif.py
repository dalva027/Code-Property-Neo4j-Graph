"""Findings as a SARIF 2.1.0 log, so results open in VS Code's SARIF viewer and compare with other
tools (cargo-audit, clippy, Semgrep and CodeQL all write SARIF; phase 5 normalizes on it).

One run per export. Every registered rule is listed in the driver, with its category, CWE ids
(as CodeQL-style `external/cwe/cwe-NNN` tags) and, for the security rules, a
`security-severity` score that GitHub code scanning reads. A result's location is its file and
lines, relative to `%SRCROOT%` (the scanned project's root); its evidence path becomes a code flow
over the steps that have a source location. Severity maps onto SARIF levels as
critical/error → error, warning → warning, info → note.
"""
import hashlib
import re
from typing import Any
from urllib.parse import quote

from app import __version__
from app.analyzers import REGISTRY
from app.graph.repository import GraphRepository
from app.models.analysis import Category, Finding, Project, RuleInfo, Severity
from app.models.graph import GraphNode, NodeKind
from app.rules import load_catalogue
from app.services.evidence import describe

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {Severity.critical: "error", Severity.error: "error", Severity.warning: "warning", Severity.info: "note"}
# GitHub's buckets: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
SECURITY_SEVERITY = {Severity.critical: "9.5", Severity.error: "8.0", Severity.warning: "5.5", Severity.info: "2.0"}
_LINE_SUFFIX = re.compile(r"@\d+$")


def _uri(path: str) -> str:
    return quote(path.replace("\\", "/"))


def _cwe_tag(cwe: str) -> str:
    number = cwe.removeprefix("CWE-")
    return f"external/cwe/cwe-{int(number):03d}" if number.isdigit() else cwe.lower()


def _cwe_url(cwe: str) -> str | None:
    number = cwe.removeprefix("CWE-")
    return f"https://cwe.mitre.org/data/definitions/{number}.html" if number.isdigit() else None


def _first_sentence(text: str) -> str:
    head = re.split(r"(?<=[.!?])\s", text.strip(), maxsplit=1)[0]
    return head or text


def _rule(info: RuleInfo) -> dict[str, Any]:
    security = info.category != Category.quality
    tags = (["security"] if security else ["maintainability"]) + [info.category.value]
    tags += [_cwe_tag(c) for c in info.cwe]
    properties: dict[str, Any] = {"category": info.category.value, "tags": tags, "version": info.version}
    if info.cwe:
        properties["cwe"] = list(info.cwe)
    if security:
        properties["security-severity"] = SECURITY_SEVERITY[info.severity]
    rule: dict[str, Any] = {
        "id": info.rule,
        "name": "".join(part.capitalize() for part in re.split(r"[-_]", info.rule)),
        "shortDescription": {"text": _first_sentence(info.description) or info.rule},
        "fullDescription": {"text": info.description or info.rule},
        "defaultConfiguration": {"level": LEVEL[info.severity]},
        "properties": properties,
    }
    if info.cwe and (url := _cwe_url(info.cwe[0])):
        rule["helpUri"] = url
    return rule


def _physical(file: str, line: int | None, line_end: int | None) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": _uri(file), "uriBaseId": "%SRCROOT%"}}
    if line and line > 0:
        region: dict[str, Any] = {"startLine": line}
        if line_end and line_end > line:
            region["endLine"] = line_end
        physical["region"] = region
    return physical


def _logical(node: GraphNode | None) -> list[dict[str, Any]]:
    if node is None or node.kind not in (NodeKind.function, NodeKind.class_, NodeKind.crate):
        return []
    kind = {NodeKind.function: "function", NodeKind.class_: "type", NodeKind.crate: "module"}[node.kind]
    return [{"fullyQualifiedName": node.qualified_name, "name": node.name, "kind": kind}]


def _fingerprint(finding: Finding, nodes: dict[str, tuple[GraphNode, GraphNode | None]]) -> str:
    """Stable across rescans and line shifts: the rule, the node the finding sits on, and the last
    evidence step (the sink) by name, without line numbers."""
    def name(node_id: str | None) -> str:
        if node_id is None:
            return ""
        node = nodes.get(node_id)
        return _LINE_SUFFIX.sub("", node[0].qualified_name) if node else node_id.split(":", 1)[-1]
    sink = finding.evidence[-1] if finding.evidence else None
    key = "|".join([finding.rule, name(finding.node_id) or finding.file or "", name(sink)])
    return hashlib.sha256(key.encode()).hexdigest()


def _code_flow(finding: Finding, nodes: dict[str, tuple[GraphNode, GraphNode | None]]) -> dict[str, Any] | None:
    locations = []
    for node_id in finding.evidence:
        if node_id not in nodes:
            continue
        node, owner = nodes[node_id]
        if not node.file or node.line_start <= 0:
            continue
        end = node.line_end if node.kind in (NodeKind.unsafe,) else None
        location: dict[str, Any] = {
            "physicalLocation": _physical(node.file, node.line_start, end),
            "message": {"text": describe(node, owner)},
        }
        if logical := _logical(owner if owner is not None else node):
            location["logicalLocations"] = logical
        locations.append({"location": location, "executionOrder": len(locations) + 1})
    if len(locations) < 2:
        return None
    return {"threadFlows": [{"locations": locations}]}


def _result(finding: Finding, index: int, nodes: dict[str, tuple[GraphNode, GraphNode | None]]) -> dict[str, Any]:
    node = nodes.get(finding.node_id or "")
    result: dict[str, Any] = {
        "ruleId": finding.rule,
        "ruleIndex": index,
        "level": LEVEL[finding.severity],
        "kind": "fail",
        "message": {"text": finding.message},
        "partialFingerprints": {"codegraph/v1": _fingerprint(finding, nodes)},
        "properties": {
            "severity": finding.severity.value, "category": finding.category.value,
            "confidence": finding.confidence.value, "cwe": finding.cwe, "evidence": finding.evidence,
            "ruleVersion": finding.rule_version,
        },
    }
    if finding.file:
        location: dict[str, Any] = {"physicalLocation": _physical(finding.file, finding.line, finding.line_end)}
        if logical := _logical(node[0] if node else None):
            location["logicalLocations"] = logical
        result["locations"] = [location]
    if flow := _code_flow(finding, nodes):
        result["codeFlows"] = [flow]
    return result


async def sarif_log(repo: GraphRepository, project: Project, findings: list[Finding]) -> dict[str, Any]:
    catalogue = load_catalogue()
    rules = [a.info() for a in REGISTRY]
    # A finding stored by a rule that has since been removed still gets a descriptor.
    known = {r.rule for r in rules}
    for f in findings:
        if f.rule not in known:
            known.add(f.rule)
            rules.append(RuleInfo(rule=f.rule, severity=f.severity, description=f.rule, category=f.category,
                                  cwe=f.cwe, version=f.rule_version or "?"))
    index = {r.rule: i for i, r in enumerate(rules)}
    ids = [i for f in findings for i in (*f.evidence, *([f.node_id] if f.node_id else []))]
    nodes = await repo.resolve_nodes(project.id, ids) if ids else {}
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "codegraph",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": [_rule(r) for r in rules],
                "properties": {"catalogueVersion": catalogue.version, "catalogueDigest": catalogue.digest},
            }},
            "automationDetails": {"id": f"codegraph/{project.name}/"},
            "originalUriBaseIds": {"%SRCROOT%": {
                "description": {"text": f"Root of the scanned project ({project.root})"},
            }},
            "invocations": [{"executionSuccessful": True}],
            "results": [_result(f, index[f.rule], nodes) for f in findings],
            "properties": {
                "project": project.name,
                "advisoryDbCommit": project.advisory_db_commit,
            },
        }],
    }
