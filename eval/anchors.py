"""Anchor cases (docs/build-plan.md section 7.6): real RustSec advisories, scanned on the snapshot
just before their fix, that a phase's rules are expected to detect.

Each case names the repository checkout under eval/corpus/anchors/, the workspace member to scan,
the rule that should fire, and the file (and function, where the advisory names one) it should
fire on. The script scans the member into a throwaway project, runs the analyzers, and reports
per case whether a finding of the expected rule lands on the expected file (and function), plus
how many findings of that rule the member produced in total, which is the noise the finding has
to stand out from.

Phase 2 checkouts are made by hand under eval/corpus/anchors/ (see eval/README.md). Phase 3 cases
use the vulnerable snapshots that eval/rustxec/fetch.py puts under eval/corpus/rustxec/<id>/vuln.
Nothing is built or executed. The phase 3 rules need the rust-analyzer extractor
(CODEGRAPH_EXTRACTOR), which downloads the dependencies' sources to resolve calls into them.

A case's result is a smoke test, not a measure of recall: the cases were chosen because a rule
should detect them (docs/build-plan.md section 7.8).

    cd backend && .venv/bin/python ../eval/anchors.py [--phase N] [case id ...]
"""
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.db import neo4j
from app.graph.repository import GraphRepository
from app.services.analysis import analyze_project
from app.services.ingest import build_and_store

CORPUS = Path(__file__).resolve().parent / "corpus" / "anchors"
RUSTXEC = "../rustxec/{}/vuln"          # relative to CORPUS: a RustXec case's vulnerable snapshot
LABELLED = "(labelled function)"        # not a rule: the advisory's affected function must be a graph symbol
# Crate names of the phase 3 cases whose package is the repository root, for the report.
PACKAGES = {"RUSTSEC-2021-0080": "tar", "RUSTSEC-2022-0072": "hyper-staticfile", "RUSTSEC-2021-0079": "hyper",
            "RUSTSEC-2021-0003": "smallvec"}


@dataclass(frozen=True)
class Case:
    id: str
    phase: int
    checkout: str              # directory under eval/corpus/anchors
    member: str                # workspace member to scan, relative to the checkout ("" = root)
    rule: str
    file: str                  # expected file, relative to the member
    function: str | None = None  # substring of the expected function's qualified name
    note: str = ""


CASES = [
    Case("RUSTSEC-2024-0357", 2, "openssl", "openssl", "dangerous-unsafe-op", "src/bio.rs", "MemBio.get_buf",
         "slice::from_raw_parts with a null pointer"),
    Case("RUSTSEC-2025-0005", 2, "grcov", "", "dangerous-unsafe-op", "src/covdir.rs", "get_coverage",
         "get_unchecked_mut without a bounds check"),
    Case("RUSTSEC-2024-0437", 2, "protobuf", "protobuf", "unbounded-recursion", "src/coded_input_stream",
         "skip_group", "skip_group <-> skip_field recursion on unknown fields"),
    Case("RUSTSEC-2024-0401", 2, "zlib-rs", "zlib-rs", "unbounded-recursion", "src/inflate", "inflate",
         "stack overflow on crafted input"),
    Case("RUSTSEC-2025-0021", 2, "gix-features", "gix-features", "weak-hash-algorithm", "src/hash.rs", "hash",
         "SHA-1 without collision detection"),
    Case("RUSTSEC-2024-0343", 2, "nano-id", "", "insecure-randomness", "src/lib.rs", None,
         "reduced alphabet in base58/base62; the RNG itself is getrandom, so an RNG-choice rule cannot see it"),
    Case("RUSTSEC-2021-0113", 2, "metrics-util", "metrics-util", "unsafe-send-sync-impl", "src/bucket.rs",
         "Block", "unconditional unsafe impl Send/Sync for Block<T>, which AtomicBucket<T> is built from"),
    # -- phase 3: taint rules, on library crates, so sources are public parameters (library mode)
    Case("RUSTSEC-2024-0335", 3, RUSTXEC.format("RUSTSEC-2024-0335"), "gix-transport", "command-injection",
         "src/client/blocking_io/ssh/program_kind.rs", "prepare_invocation",
         "user@host from the URL becomes an ssh argument; the Command call itself is in the gix-command crate"),
    Case("RUSTSEC-2024-0350", 3, RUSTXEC.format("RUSTSEC-2024-0350"), "gix-fs", "path-traversal",
         "src/stack.rs", "make_relative_path_current",
         "unvalidated components pushed onto the worktree root; the fs calls are in gix-worktree"),
    Case("RUSTSEC-2021-0080", 3, RUSTXEC.format("RUSTSEC-2021-0080"), "", "path-traversal",
         "src/entry.rs", "unpack_in", "archive-controlled path reaches create_dir_all before validation"),
    Case("RUSTSEC-2022-0072", 3, RUSTXEC.format("RUSTSEC-2022-0072"), "", "open-redirect",
         "src/response_builder.rs", "build", "Location header built from the request path"),
    Case("RUSTSEC-2024-0009", 3, RUSTXEC.format("RUSTSEC-2024-0009"), "http", "header-injection",
         "src/conn.rs", "write_headers", "hand-written header serialization"),
    Case("RUSTSEC-2021-0079", 3, RUSTXEC.format("RUSTSEC-2021-0079"), "", "overflow-candidate",
         "src/proto/h1/decode.rs", "read_size", "chunk size computed from wire bytes with unchecked * and +"),
    Case("RUSTSEC-2021-0003", 3, RUSTXEC.format("RUSTSEC-2021-0003"), "", "overflow-candidate",
         "src/lib.rs", "insert_many",
         "the plan lists it under P3; the frozen RustXec expectation is dangerous-unsafe-op (ptr::copy past capacity)"),
    Case("RUSTSEC-2021-0124", 3, RUSTXEC.format("RUSTSEC-2021-0124"), "tokio", LABELLED,
         "src/sync/oneshot.rs", "sync.oneshot.Receiver.close",
         "a race in an atomic state machine that no rule is expected to see (frozen as out of reach); the case "
         "checks that the function the advisory labels, tokio::sync::oneshot::Receiver::close, is in the graph"),
]


def subject(message: str) -> str:
    """The part of a finding's message that names where it is. A taint finding also names the
    function its input came from, which must not count as a hit on that function."""
    return message.split(": input from", 1)[0]


async def run_case(case: Case, repo: GraphRepository) -> tuple[str, str]:
    root = CORPUS / case.checkout / case.member
    if not root.is_dir():
        return "MISSING", f"no checkout at {root}"
    project = await repo.create_project(f"anchor:{case.id}", root.resolve().as_posix())
    try:
        await build_and_store(project, repo)
        await repo.mark_scan_finished(project.id)
        if case.rule == LABELLED:
            rows = await repo.query(
                "MATCH (f:Function {project_id: $pid}) WHERE f.qualified_name ENDS WITH $name AND f.file STARTS WITH $file "
                "RETURN f.qualified_name AS qname, f.file AS file, f.line_start AS line",
                pid=project.id, name=case.function, file=case.file)
            if rows:
                return "LOCATED", f"{rows[0]['file']}:{rows[0]['line']} {rows[0]['qname']}"
            return "MISSED", f"no function named {case.function} in {case.file}"
        await analyze_project(project.id, repo)
        findings = [f for f in await repo.list_findings(project.id) if f.rule == case.rule]
    finally:
        await repo.delete_project(project.id)
    on_file = [f for f in findings if (f.file or "").startswith(case.file)]
    on_fn = [f for f in on_file if case.function is None or case.function in subject(f.message)]
    if on_fn:
        first = on_fn[0]
        return "DETECTED", f"{first.file}:{first.line} ({len(findings)} {case.rule} findings in the member)"
    if on_file:
        return "FILE ONLY", f"{len(on_file)} on {case.file}, none naming {case.function} ({len(findings)} total)"
    return "MISSED", f"{len(findings)} {case.rule} findings, none on {case.file}"


async def main(only: list[str]) -> int:
    phase = None
    if "--phase" in only:
        at = only.index("--phase")
        phase = int(only[at + 1])
        only = only[:at] + only[at + 2:]
    await neo4j.connect()
    await neo4j.apply_schema()
    repo = GraphRepository()
    detected = total = 0
    try:
        for case in CASES:
            if (only and case.id not in only) or (phase is not None and case.phase != phase):
                continue
            total += 1
            status, detail = await run_case(case, repo)
            detected += status in ("DETECTED", "LOCATED")
            name = (case.member or PACKAGES.get(case.id, case.id)) if case.phase == 3 else case.checkout
            print(f"{case.id}  {name:13} {case.rule:28} {status:9} {detail}")
            if case.note:
                print(f"{'':18}{case.note}")
    finally:
        await neo4j.close()
    print(f"{detected}/{total} detected")
    return 0 if detected == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
