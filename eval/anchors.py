"""Anchor cases (docs/build-plan.md section 7.6): real RustSec advisories, scanned on the snapshot
just before their fix, that a phase's rules are expected to detect.

Each case names the repository checkout under eval/corpus/anchors/, the workspace member to scan,
the rule that should fire, and the file (and function, where the advisory names one) it should
fire on. The script scans the member into a throwaway project, runs the analyzers, and reports
per case whether a finding of the expected rule lands on the expected file (and function), plus
how many findings of that rule the member produced in total, which is the noise the finding has
to stand out from.

Checkouts are made by hand (see eval/README.md); nothing is built or executed.

    cd backend && .venv/bin/python ../eval/anchors.py [case id ...]
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
]


async def run_case(case: Case, repo: GraphRepository) -> tuple[str, str]:
    root = CORPUS / case.checkout / case.member
    if not root.is_dir():
        return "MISSING", f"no checkout at {root}"
    project = await repo.create_project(f"anchor:{case.id}", root.resolve().as_posix())
    try:
        await build_and_store(project, repo)
        await repo.mark_scan_finished(project.id)
        await analyze_project(project.id, repo)
        findings = [f for f in await repo.list_findings(project.id) if f.rule == case.rule]
    finally:
        await repo.delete_project(project.id)
    on_file = [f for f in findings if (f.file or "").startswith(case.file)]
    on_fn = [f for f in on_file if case.function is None or case.function in f.message]
    if on_fn:
        first = on_fn[0]
        return "DETECTED", f"{first.file}:{first.line} ({len(findings)} {case.rule} findings in the member)"
    if on_file:
        return "FILE ONLY", f"{len(on_file)} on {case.file}, none naming {case.function} ({len(findings)} total)"
    return "MISSED", f"{len(findings)} {case.rule} findings, none on {case.file}"


async def main(only: list[str]) -> int:
    await neo4j.connect()
    await neo4j.apply_schema()
    repo = GraphRepository()
    detected = total = 0
    try:
        for case in CASES:
            if only and case.id not in only:
                continue
            total += 1
            status, detail = await run_case(case, repo)
            detected += status == "DETECTED"
            print(f"{case.id}  {case.checkout:13} {case.rule:28} {status:9} {detail}")
            if case.note:
                print(f"{'':18}{case.note}")
    finally:
        await neo4j.close()
    print(f"{detected}/{total} detected")
    return 0 if detected == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1:])))
