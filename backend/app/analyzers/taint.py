"""Class T, injection via taint tracking, and the tainted panic rules P3 and P4
(docs/build-plan.md section 3).

Every rule here is the same question with different data: does untrusted input reach a sink of
this rule without passing a sanitizer? Sources, sinks and sanitizers come from the rule catalogue
(`app/rules/*.yaml`, keyed by the ids T1-T7, P3, P4); the path search is `flow.taint_paths`. The
rules need the data-flow graph of the rust-analyzer extractor: a project scanned with tree-sitter
alone has no `Var` nodes and these rules report nothing for it.

Severity and confidence follow the source. Input that is attacker-controlled by construction (a
request extractor, argv, stdin, a socket) gives the rule's own severity at high confidence. A path
that starts at a public parameter of a library crate is one level lower in both: it is real only
if a caller passes input in. A path through trait dispatch (an impl chosen by name, not by type)
loses one confidence level.
"""
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.analyzers import flow
from app.analyzers.base import Analyzer, register
from app.graph.repository import GraphRepository
from app.models.analysis import Category, Confidence, Finding, Severity

SINKS = """
MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(c:Call)
WHERE c.callee_path IN $paths AND NOT coalesce(f.in_test, false)
RETURN c.id AS id, c.callee_path AS path, c.detail AS detail, c.file AS file, c.line_start AS line,
       f.id AS fn, f.qualified_name AS qname, c.ret_kind AS ret_kind, coalesce(c.in_unsafe, false) AS in_unsafe,
       c.literal_args AS literal_args
ORDER BY c.file, c.line_start, c.id
"""
_LOWER = {Severity.critical: Severity.error, Severity.error: Severity.warning, Severity.warning: Severity.info,
          Severity.info: Severity.info}
_LESS = {Confidence.high: Confidence.medium, Confidence.medium: Confidence.low, Confidence.low: Confidence.low}


@dataclass(frozen=True)
class Spec:
    id: str                     # catalogue key
    rule: str
    category: Category
    severity: Severity          # for input that is attacker-controlled by construction
    cwe: tuple[str, ...]
    text: bool                  # the payload is text: numeric and bool values end the taint
    what: str                   # "{what}" in "input from <source> reaches <sink>: {what}"
    description: str
    per_function: bool = False  # one finding per function instead of one per sink


SPECS = [
    Spec("T1", "command-injection", Category.injection, Severity.critical, ("CWE-78",), True,
         "the attacker chooses the program or its arguments",
         "Untrusted input reaches std::process::Command (or tokio's) as the program or an argument, without an "
         "allow-list, a numeric parse or shell escaping on the way."),
    Spec("T2", "sql-injection", Category.injection, Severity.critical, ("CWE-89",), True,
         "the query text is built from input",
         "Untrusted input reaches the text of an SQL statement (sqlx::query, diesel::sql_query, rusqlite, "
         "tokio_postgres). Values passed as bind parameters are not findings."),
    Spec("T3", "path-traversal", Category.injection, Severity.error, ("CWE-22",), True,
         "the path is built from input",
         "Untrusted input reaches a filesystem call as its path, without reduction to a file name or a check "
         "that the canonical path stays under a base directory."),
    Spec("T4", "ssrf", Category.injection, Severity.error, ("CWE-918",), True,
         "the destination is chosen by the input",
         "Untrusted input reaches the URL or address of an outgoing request (reqwest, ureq, TcpStream::connect) "
         "without a host allow-list."),
    Spec("T5", "unsafe-length-from-input", Category.injection, Severity.critical, ("CWE-119", "CWE-787"), False,
         "a length or index taken from input is trusted by unsafe code",
         "A number derived from untrusted input is the length, count or index of an unsafe memory operation "
         "(slice::from_raw_parts, Vec::set_len, ptr::copy, get_unchecked) with no bounds check or clamp."),
    Spec("T6", "open-redirect", Category.injection, Severity.warning, ("CWE-601",), True,
         "the redirect target comes from input",
         "Untrusted input becomes the target of a redirect (axum/actix/rocket Redirect, or a hand-written "
         "Location header) without a check that it is site-relative."),
    Spec("T7", "header-injection", Category.injection, Severity.warning, ("CWE-113",), True,
         "input is written into a response header unvalidated",
         "Untrusted input is written into an HTTP header without CR/LF validation: an unchecked HeaderValue "
         "constructor or a header line assembled by hand. HeaderValue::from_str validates and is not a finding."),
    Spec("P3", "overflow-candidate", Category.panic, Severity.warning, ("CWE-190",), False,
         "the arithmetic can overflow",
         "An integer `+`, `-`, `*` or `<<` with an operand derived from untrusted input and no bounds check, "
         "clamp or checked_* arithmetic. One finding per function. Also arithmetic inside `unsafe` whose result "
         "feeds a pointer or length operation.", per_function=True),
    Spec("P4", "unbounded-allocation", Category.panic, Severity.warning, ("CWE-770",), False,
         "the allocation size comes from input",
         "A size derived from untrusted input reaches with_capacity, reserve or resize without a cap, so a small "
         "request can allocate arbitrary memory."),
]


def _when(conditions: dict[int, str], literal_args: str | None) -> bool:
    """Do the call's fixed arguments (literals, constants by name) satisfy an entry's `when`?"""
    try:
        fixed = {int(i): str(text) for i, _, text in json.loads(literal_args or "[]")}
    except (ValueError, TypeError):
        return False
    return all(i in fixed and re.search(pattern, fixed[i]) for i, pattern in conditions.items())


def sink_vias(entry: Any) -> list[str]:
    """How a value must arrive at a sink for one catalogue entry to apply."""
    if entry.template is not None:
        return ["macro"]
    vias = [f"arg:{i}" for i in entry.args or []]
    if entry.receiver:
        vias.append("recv")
    return vias or flow.ANY_VIA


class TaintRule(Analyzer):
    spec: Spec
    languages = ("rust",)
    version = "1"

    async def sinks(self, repo: GraphRepository, project_id: str, state: flow.Flow) -> list[dict[str, Any]]:
        """Call sites of this rule's sinks, each with the argument positions that matter."""
        entries = {p: [m.entry for m in state.matcher.match(p, "sinks") if m.group == self.spec.id]
                   for p in state.paths_in("sinks", self.spec.id)}
        found = []
        for r in await repo.query(SINKS, pid=project_id, paths=list(entries)):
            vias: list[str] = []
            for entry in entries[r["path"]]:
                if entry.template is not None and not re.search(entry.template, r["detail"] or ""):
                    continue
                if entry.when and not _when(entry.when, r["literal_args"]):
                    continue
                vias.extend(v for v in sink_vias(entry) if v not in vias)
            if vias and self.accepts(r):
                found.append({**r, "vias": vias})
        return found

    def accepts(self, sink: dict[str, Any]) -> bool:
        return True

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        spec = self.spec
        state = await flow.load_flow(repo, project_id)
        if not state.sources:
            return []
        sinks = await self.sinks(repo, project_id, state)
        hits = await flow.taint_paths(
            repo, state, ({"id": s["id"], "vias": s["vias"]} for s in sinks),
            blocked_paths=state.paths_in("sanitizers", spec.id),
            blocked_kinds=flow.TEXT_BLOCKED if spec.text else flow.NUMBER_BLOCKED,
            guards=state.catalogue.guards(spec.id), numbers=not spec.text,
        )
        tainted = [(s, hits[s["id"]]) for s in sinks if s["id"] in hits]
        if spec.per_function:
            return self.grouped(project_id, tainted)
        return [self.report(project_id, s, hit, [s]) for s, hit in tainted]

    def grouped(self, project_id: str, tainted: list[tuple[dict[str, Any], flow.Hit]]) -> list[Finding]:
        by_fn: dict[str, list[tuple[dict[str, Any], flow.Hit]]] = defaultdict(list)
        for sink, hit in tainted:
            by_fn[sink["fn"]].append((sink, hit))
        findings = []
        for group in by_fn.values():
            # The site reached from the strongest source represents the function.
            sink, hit = min(group, key=lambda g: (g[1].source.trusted_caller, g[0]["line"]))
            findings.append(self.report(project_id, sink, hit, [s for s, _ in group]))
        return findings

    def report(self, project_id: str, sink: dict[str, Any], hit: flow.Hit, sites: list[dict[str, Any]]) -> Finding:
        spec = self.spec
        severity, confidence = spec.severity, Confidence.high
        if hit.source.trusted_caller:
            severity, confidence = _LOWER[severity], Confidence.low
        elif hit.through_dispatch:
            confidence = _LESS[confidence]
        steps = len(hit.path)
        target = sink["path"] if len(sites) == 1 else \
            f"{len(sites)} operations (lines {', '.join(str(s['line']) for s in sites[:6])})"
        return self.finding(
            project_id,
            f"{sink['qname']}: input from {hit.source.describe()} reaches {target} in {steps} "
            f"step{'s' if steps != 1 else ''}; {spec.what}",
            node_id=sink["fn"], file=sink["file"], line=min(s["line"] for s in sites),
            line_end=max(s["line"] for s in sites), severity=severity, confidence=confidence,
            evidence=[*hit.path, *(s["id"] for s in sites[:20])],
        )


class OverflowCandidate(TaintRule):
    """P3 adds a second form to the tainted one: arithmetic inside `unsafe` that feeds a pointer or
    length operation, whatever its operands."""

    FEEDS = """
    MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(op:Call {subkind: 'arith', in_unsafe: true})
    WHERE NOT coalesce(f.in_test, false)
    MATCH (op)-[:FLOWS_TO*1..3]->(use:Call {in_unsafe: true})
    WHERE use.callee_path IN $paths
    RETURN f.id AS fn, f.qualified_name AS qname, op.id AS id, op.file AS file, op.line_start AS line,
           use.id AS use, use.callee_path AS path
    ORDER BY op.file, op.line_start
    """

    def accepts(self, sink: dict[str, Any]) -> bool:
        return sink["ret_kind"] == "int"            # typed integer arithmetic only

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = await super().run(repo, project_id)
        reported = {f.node_id for f in findings}
        state = await flow.load_flow(repo, project_id)
        memory = [p for p in state.call_paths
                  if any(m.group == "memory" for m in state.matcher.match(p, "dangerous_ops"))
                  or any(m.group == "T5" for m in state.matcher.match(p, "sinks"))]
        seen: set[str] = set()
        for r in await repo.query(self.FEEDS, pid=project_id, paths=memory):
            if r["fn"] in reported or r["fn"] in seen:
                continue
            seen.add(r["fn"])
            findings.append(self.finding(
                project_id,
                f"{r['qname']}: arithmetic inside unsafe at line {r['line']} feeds {r['path']}; an overflow "
                "there becomes an out-of-bounds pointer or length",
                node_id=r["fn"], file=r["file"], line=r["line"], severity=Severity.info,
                confidence=Confidence.low, evidence=[r["fn"], r["id"], r["use"]],
            ))
        return findings


def _make(spec: Spec) -> type[TaintRule]:
    base = OverflowCandidate if spec.id == "P3" else TaintRule
    name = "".join(part.capitalize() for part in spec.rule.split("-"))
    return type(name, (base,), {
        "spec": spec, "rule": spec.rule, "category": spec.category, "severity": spec.severity,
        "cwe": spec.cwe, "description": spec.description,
    })


RULES = [register(_make(spec)) for spec in SPECS]
