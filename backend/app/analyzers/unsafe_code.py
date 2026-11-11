"""Class U: unsafe code (docs/build-plan.md section 3).

All syntactic. `Unsafe` nodes mark spans, `Call` nodes mark the call sites the catalogue cares
about (with `in_unsafe`), and `entry_distance` on functions comes from the ingest pass.
"""
from app.analyzers.base import Analyzer, register
from app.analyzers.reach import load_reach
from app.graph.repository import GraphRepository
from app.models.analysis import Category, Confidence, Finding, Severity
from app.rules import load_catalogue

U1_MAX_CALLS = 8

# CWE by the dangerous operation's last path segment; CWE-119 (buffer bounds) otherwise.
_OP_CWE = {
    "transmute": "CWE-843", "transmute_copy": "CWE-843",
    "zeroed": "CWE-908", "uninitialized": "CWE-908", "assume_init": "CWE-908", "assume_init_read": "CWE-908",
    "assume_init_mut": "CWE-908", "set_len": "CWE-908",
    "from_raw": "CWE-415", "from_utf8_unchecked": "CWE-20",
    "get_unchecked": "CWE-125", "get_unchecked_mut": "CWE-787", "unwrap_unchecked": "CWE-476",
    "read": "CWE-125", "read_unaligned": "CWE-125", "write": "CWE-787", "write_unaligned": "CWE-787",
    "write_bytes": "CWE-787", "copy": "CWE-787", "copy_nonoverlapping": "CWE-787",
    "offset": "CWE-119", "add": "CWE-119", "sub": "CWE-119", "from_ptr": "CWE-476",
}


class _UnsafeRule(Analyzer):
    category = Category.unsafe
    languages = ("rust",)


@register
class UnsafeReachableFromEntry(_UnsafeRule):
    rule = "unsafe-reachable-from-entry"
    severity = Severity.warning
    cwe = ("CWE-676",)
    description = (f"A function containing `unsafe` code that an entry point (main, a request handler, a pub "
                   f"function of a library, or an FFI export) reaches within {U1_MAX_CALLS} calls. The evidence "
                   "is the call chain from the entry point.")

    QUERY = """
    MATCH (f:Function {project_id: $pid})
    WHERE f.entry_distance IS NOT NULL AND f.entry_distance <= $max AND NOT coalesce(f.in_test, false)
      AND coalesce(f.subkind, '') <> 'foreign fn'
      AND (coalesce(f.is_unsafe, false) OR EXISTS { (f)-[:CONTAINS]->(:Unsafe {subkind: 'block'}) })
    OPTIONAL MATCH (f)-[:CONTAINS]->(u:Unsafe)
    WITH f, collect(u.id) AS spans
    RETURN f.id AS id, f.qualified_name AS qname, f.file AS file, f.line_start AS line, f.line_end AS line_end,
           coalesce(f.is_unsafe, false) AS is_unsafe, spans
    ORDER BY f.file, f.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        reach = await load_reach(repo, project_id)
        findings = []
        for r in await repo.query(self.QUERY, pid=project_id, max=U1_MAX_CALLS):
            blocks = len(r["spans"])
            what = "is an unsafe fn" if r["is_unsafe"] else f"contains {blocks} unsafe block{'s' if blocks > 1 else ''}"
            entry = reach.entry_of(r["id"])
            confidence = Confidence.high if entry and entry.entry_kind != "pub_api" else Confidence.medium
            findings.append(self.finding(
                project_id, f"{r['qname']} {what} and is {reach.describe(r['id'])}",
                node_id=r["id"], file=r["file"], line=r["line"], line_end=r["line_end"], confidence=confidence,
                evidence=[*reach.path_to(r["id"]), *r["spans"]],
            ))
        return findings


@register
class UndocumentedUnsafe(_UnsafeRule):
    rule = "undocumented-unsafe"
    severity = Severity.info
    description = ("An `unsafe` block, fn, impl or trait without a `// SAFETY:` comment directly above it (or a "
                   "`# Safety` doc section for fns). Matches clippy's undocumented_unsafe_blocks; test code is "
                   "skipped.")

    QUERY = """
    MATCH (u:Unsafe {project_id: $pid})
    WHERE NOT u.has_safety_comment AND NOT coalesce(u.in_test, false)
    OPTIONAL MATCH (owner)-[:CONTAINS]->(u)
    RETURN u.id AS id, u.subkind AS kind, u.file AS file, u.line_start AS line, u.line_end AS line_end,
           owner.id AS owner, owner.qualified_name AS owner_name, u.trait AS trait, u.target_type AS target
    ORDER BY u.file, u.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = []
        for r in await repo.query(self.QUERY, pid=project_id):
            if r["kind"] == "impl":
                where = f"unsafe impl {r['trait'] or ''} for {r['target'] or '?'}".replace("  ", " ")
            elif r["kind"] == "block":
                where = f"unsafe block in {r['owner_name'] or r['file']}"
            else:
                where = f"unsafe {r['kind']} {r['owner_name'] or ''}".strip()
            findings.append(self.finding(
                project_id, f"{where} has no SAFETY comment explaining why it is sound",
                node_id=r["owner"] or r["id"], file=r["file"], line=r["line"], line_end=r["line_end"],
                evidence=[r["id"]],
            ))
        return findings


@register
class DangerousUnsafeOp(_UnsafeRule):
    rule = "dangerous-unsafe-op"
    severity = Severity.warning
    cwe = ("CWE-119",)
    description = ("A call inside `unsafe` to an operation from the catalogue's dangerous_ops list: transmute, "
                   "slice::from_raw_parts, Vec::set_len, get_unchecked, ptr::{read,write,copy}, Box::from_raw, "
                   "mem::{zeroed,uninitialized}, MaybeUninit::assume_init, raw pointer arithmetic. Methods on an "
                   "unknown receiver (`?::add`) are medium confidence until phase 3 adds types.")

    QUERY = """
    MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(c:Call {in_unsafe: true})
    WHERE c.subkind = 'call' AND NOT coalesce(f.in_test, false)
    RETURN f.id AS fn, f.qualified_name AS qname, c.id AS id, c.callee_path AS path, c.file AS file,
           c.line_start AS line, f.entry_distance AS distance
    ORDER BY c.file, c.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        matcher = load_catalogue().matcher()
        reach = await load_reach(repo, project_id)
        findings = []
        for r in await repo.query(self.QUERY, pid=project_id):
            if not any(m.group in ("memory", "ffi") for m in matcher.match(r["path"], "dangerous_ops")):
                continue
            name = r["path"].rsplit("::", 1)[-1]
            unknown = r["path"].startswith("?::")
            findings.append(self.finding(
                project_id,
                f"{r['qname']} calls {r['path']} inside unsafe; the function is {reach.describe(r['fn'])}",
                node_id=r["fn"], file=r["file"], line=r["line"],
                confidence=Confidence.medium if unknown else Confidence.high,
                cwe=[_OP_CWE.get(name, "CWE-119")],
                evidence=[*reach.path_to(r["fn"]), r["id"]] if r["distance"] is not None else [r["fn"], r["id"]],
            ))
        return findings


@register
class UnsafeSendSyncImpl(_UnsafeRule):
    rule = "unsafe-send-sync-impl"
    severity = Severity.warning
    cwe = ("CWE-662",)
    description = ("`unsafe impl Send` or `unsafe impl Sync`: a hand-written promise that a type is safe to move "
                   "or share across threads, a common source of data races when wrong.")

    QUERY = """
    MATCH (u:Unsafe {project_id: $pid, subkind: 'impl'})
    WHERE u.trait IN ['Send', 'Sync'] AND NOT coalesce(u.in_test, false)
    OPTIONAL MATCH (owner)-[:CONTAINS]->(u)
    RETURN u.id AS id, u.file AS file, u.line_start AS line, u.line_end AS line_end, u.trait AS trait,
           u.target_type AS target, owner.id AS owner, u.has_safety_comment AS documented
    ORDER BY u.file, u.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        return [
            self.finding(
                project_id,
                f"unsafe impl {r['trait']} for {r['target'] or '?'}"
                + ("" if r["documented"] else ", without a SAFETY comment"),
                node_id=r["owner"] or r["id"], file=r["file"], line=r["line"], line_end=r["line_end"],
                evidence=[r["id"]],
            )
            for r in await repo.query(self.QUERY, pid=project_id)
        ]


@register
class FfiSurface(_UnsafeRule):
    rule = "ffi-surface"
    severity = Severity.info
    description = ("The FFI boundary, for review rather than as a defect: `extern` fns and `#[no_mangle]` exports "
                   "(entry points callable from C), foreign fn declarations in `extern` blocks, and functions "
                   "taking raw pointers.")

    QUERY = """
    MATCH (f:Function {project_id: $pid})
    WHERE (f.abi IS NOT NULL OR coalesce(f.no_mangle, false) OR coalesce(f.raw_pointer_params, 0) > 0)
      AND NOT coalesce(f.in_test, false)
    RETURN f.id AS id, f.qualified_name AS qname, f.file AS file, f.line_start AS line, f.line_end AS line_end,
           f.abi AS abi, coalesce(f.no_mangle, false) AS no_mangle, f.subkind AS subkind,
           coalesce(f.raw_pointer_params, 0) AS raw
    ORDER BY f.file, f.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = []
        for r in await repo.query(self.QUERY, pid=project_id):
            parts = []
            if r["subkind"] == "foreign fn":
                parts.append(f"foreign fn declared in an extern \"{r['abi']}\" block")
            elif r["abi"]:
                parts.append(f"extern \"{r['abi']}\" fn")
            if r["no_mangle"]:
                parts.append("#[no_mangle] export")
            if r["raw"]:
                parts.append(f"{r['raw']} raw pointer parameter(s)")
            findings.append(self.finding(
                project_id, f"{r['qname']} is part of the FFI surface: {', '.join(parts)}",
                node_id=r["id"], file=r["file"], line=r["line"], line_end=r["line_end"], evidence=[r["id"]],
            ))
        return findings
