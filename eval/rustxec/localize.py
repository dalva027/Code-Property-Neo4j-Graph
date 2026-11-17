"""RustXec step 2, localize (docs/build-plan.md section 7.4): ground truth per case, from the
advisory's affected functions where the index has them and from the fix diff otherwise.

Diff route: `git diff -w -U0 vuln fixed`, minus tests, benches, examples, docs, changelogs,
lockfiles, manifests and CI files, minus hunks that only touch comments, blank lines, imports or
test code. What is left is mapped by its old-side line numbers onto function spans of the
*vulnerable* snapshot, taken from the project's own tree-sitter parser (`kind == "function"`,
innermost span). Per changed line:

  * a removed or replaced line inside a function            -> that function
  * lines inserted strictly inside a function                -> that function
  * a removed or replaced line outside every function        -> a file-level entry with its lines
  * lines inserted outside every function (new items)        -> ignored, unless the case has
                                                                nothing else: then the file

`granularity` is `function` when at least one function was found, else `file`. A fix is flagged
as a large refactor, and the case excluded, when after filtering it still touches more than
MAX_FUNCTIONS functions or more than MAX_FILES Rust files (see the constants below). Cases with
advisory functions are never excluded for that, their ground truth does not come from the diff.

Advisory route: every `affected.functions` path is looked up among the function symbols of the
workspace member at the vulnerable revision, by function name and enclosing type or module.
Paths that cannot be found (macro-generated or re-exported items) stay in the list unmapped.

Only the parser's symbol table is used. No analyzer, rule or finding is involved here: section
7.8 condition 1 forbids looking at detection results while the ground truth and `expected_rules`
are being decided.

Output: `eval/corpus/rustxec/localize.json` with the full detail per case, and new entries in
`eval/rustxec/cases.yaml`. cases.yaml is the frozen, curated record: an entry that is already
there is never rewritten (differences are only reported) unless `--overwrite-auto` is given, and
even then `expected_rules`, `expected_reason`, `frozen`, `review` and `source: manual` entries
are left alone.

    backend/.venv/bin/python eval/rustxec/localize.py [--overwrite-auto] [case id ...]
    backend/.venv/bin/python eval/rustxec/localize.py --show RUSTSEC-2024-0357   # advisory + kept diff
"""
import argparse
import csv
import datetime
import json
import logging
import os
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.graph.parsers.rust import RustParser

DEFAULT_METADATA = HERE / "metadata.csv"
DEFAULT_CORPUS = HERE.parent / "corpus" / "rustxec"
DEFAULT_CASES = HERE / "cases.yaml"
DEFAULT_ADVISORY_DB = ROOT / "backend" / ".advisory-db"

FREEZE_DATE = datetime.date(2026, 11, 11)
CATALOGUE = "0.3.0"

# Large-refactor threshold, applied to what is left after filtering.
MAX_FUNCTIONS = 15
MAX_FILES = 8

CLASS_OF = {
    "memory-corruption": "U", "memory-exposure": "U", "thread-safety": "U",
    "denial-of-service": "P",
    "format-injection": "T", "code-execution": "T", "privilege-escalation": "T",
    "crypto-failure": "C",
}

HEADER = """\
# RustXec cases: ground truth and expected rules (docs/build-plan.md sections 7.4 and 7.8).
#
# FREEZE RULE. `expected_rules` was decided per case from the advisory text and the fix diff
# alone, before the run step was executed for the first time, and is frozen at the date and rule
# catalogue version in `frozen`. No analyzer, rule or finding was consulted. Detection, fix-awareness
# and triage rank are reported over the cases with a non-empty `expected_rules`; coverage over all
# 102; both always together. After freezing, a change to `expected_rules`, `ground_truth` or
# `excluded` is never a silent edit: it is appended to `amendments` below as
#   - {id: RUSTSEC-..., date: YYYY-MM-DD, field: expected_rules, old: [...], new: [...], reason: "..."}
# and the case keeps its original `frozen` stamp.
#
# Fields: id; class (U/P/T/C from the RustSec category, section 7.3); repo; vuln_rev (fix commit's
# first parent); fixed_rev; member (directory of the package's Cargo.toml, "" = repository root);
# ground_truth (entries with `function` are qualified names of our parser with their file and line
# span in the vulnerable snapshot; entries without are file-level; `outside_member: true` marks a
# file that is not under `member`; `advisory_path` is the path as the advisory names it); granularity
# (function | file); source (advisory | diff | manual); excluded (reason, or null); expected_rules
# with expected_reason; frozen; review (only on the hand-reviewed sample; the reviews so far are
# machine reviews pending human confirmation and are labelled as such).
# File paths are relative to the repository root. Written by eval/rustxec/localize.py, which adds
# missing cases and never rewrites an existing entry without --overwrite-auto.
"""

AUTO_FIELDS = ("class", "repo", "vuln_rev", "fixed_rev", "member", "ground_truth", "granularity", "source", "excluded")
FIELD_ORDER = ("id", "class", "repo", "vuln_rev", "fixed_rev", "member", "ground_truth", "granularity", "source",
               "excluded", "expected_rules", "expected_reason", "frozen", "review")

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}

TEST_DIRS = {"tests", "test", "testing", "testdata", "test-data", "test_data", "fuzz", "fuzzing", "fuzz_targets",
             "fixtures", "proptest-regressions", "compile-fail", "compile_fail", "ui", "testsuite", "test-suite",
             "integration-tests", "tests-integration", "tests-build", "stress-test", "conformance"}
BENCH_DIRS = {"benches", "bench", "benchmarks", "benchmark"}
EXAMPLE_DIRS = {"examples", "example", "demo", "demos", "samples"}
DOC_DIRS = {"docs", "doc", "book", "guide", "man"}
CI_DIRS = {".github", ".circleci", "ci", ".cargo", ".config", ".gitlab", "scripts", "tools", "nix"}
DOC_EXT = {".md", ".markdown", ".txt", ".rst", ".adoc", ".html", ".svg", ".png", ".jpg", ".pdf", ".1", ".tex"}
CHANGELOG = re.compile(r"^(changelog|changes|releases?|release[-_]notes|news|history)(\.|$)", re.IGNORECASE)
TEST_FILE = re.compile(r"^(tests?|.*_tests?|tests?_.*)\.rs$")
USE_START = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?use\s")
TEST_MOD = re.compile(r"#\[cfg\((?:all\()?test\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")
TRIVIAL_LINE = re.compile(r"^\s*(//.*|/\*.*|\*.*|(pub(\([a-z ]+\))?\s+)?use\s.*|extern\s+crate\s.*|#!\[doc\(html_root_url.*)?$")


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-c", "core.quotePath=false", *args], cwd=repo, env=GIT_ENV, capture_output=True,
                          text=True, errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])}: {proc.stderr.strip()[-200:]}")
    return proc.stdout


def blob(repo: Path, rev: str, path: str) -> str | None:
    try:
        return git(repo, "show", f"{rev}:{path}")
    except RuntimeError:
        return None


def drop_reason(path: str) -> str | None:
    """Why a changed file says nothing about where the vulnerable code is; None = keep."""
    parts = path.split("/")
    name, dirs = parts[-1], set(parts[:-1])
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    if lower == "cargo.lock" or ext == ".lock" or lower in ("package-lock.json", "go.sum"):
        return "lockfile"
    if CHANGELOG.match(lower):
        return "changelog"
    if dirs & TEST_DIRS or TEST_FILE.match(lower):
        return "test"
    if dirs & BENCH_DIRS:
        return "bench"
    if dirs & EXAMPLE_DIRS:
        return "example"
    if dirs & DOC_DIRS or ext in DOC_EXT or lower.startswith(("readme", "license", "copying", "authors", "security")):
        return "doc"
    if lower == "cargo.toml":
        return "manifest"
    if dirs & CI_DIRS or lower.startswith(".") or ext in (".yml", ".yaml", ".nix", ".sh", ".json") \
            or lower in ("deny.toml", "rustfmt.toml", "clippy.toml", "makefile", "justfile", "rust-toolchain", "rust-toolchain.toml"):
        return "ci-or-config"
    return None


def parse_diff(text: str) -> list[dict]:
    """Unified diff (-U0) -> [{old, new, hunks: [{old_start, old_lines, new_start, new_lines}]}]."""
    files: list[dict] = []
    cur: dict | None = None
    hunk: dict | None = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            cur = {"old": None, "new": None, "hunks": []}
            files.append(cur)
            hunk = None
        elif cur is None:
            continue
        elif hunk is None and line.startswith("--- "):
            target = line[4:].split("\t")[0]
            cur["old"] = None if target == "/dev/null" else target.removeprefix("a/")
        elif hunk is None and line.startswith("+++ "):
            target = line[4:].split("\t")[0]
            cur["new"] = None if target == "/dev/null" else target.removeprefix("b/")
        elif line.startswith("@@ "):
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                continue
            hunk = {"old_start": int(m[1]), "old_lines": [], "new_start": int(m[3]), "new_lines": [],
                    "old_count": int(m[2] or 1), "new_count": int(m[4] or 1)}
            cur["hunks"].append(hunk)
        elif hunk is not None and line.startswith("-"):
            hunk["old_lines"].append(line[1:])
        elif hunk is not None and line.startswith("+"):
            hunk["new_lines"].append(line[1:])
    return [f for f in files if f["old"] or f["new"]]


class Symbols:
    """Function spans of one revision, parsed on demand with the project's Rust parser."""

    def __init__(self, repo: Path, rev: str, member: str | None, manifests: set[str]) -> None:
        self.repo, self.rev, self.member, self.manifests = repo, rev, member, manifests
        self.parser = RustParser()
        self.cache: dict[str, list] = {}
        self.text: dict[str, list[str]] = {}
        self.tests: dict[str, list[tuple[int, int]]] = {}

    def package_dir(self, path: str) -> str:
        """Nearest ancestor directory that holds a Cargo.toml ("" = repository root)."""
        parts = path.split("/")[:-1]
        while parts:
            if "/".join(parts) + "/Cargo.toml" in self.manifests:
                return "/".join(parts)
            parts.pop()
        return ""

    def inside_member(self, path: str) -> bool:
        return self.member is not None and (self.member == "" or path.startswith(self.member + "/"))

    def functions(self, path: str) -> list:
        if path not in self.cache:
            source = blob(self.repo, self.rev, path)
            base = self.member if self.inside_member(path) else self.package_dir(path)
            rel = path[len(base) + 1:] if base else path
            symbols = RustParser.parse(self.parser, rel, source).symbols if source is not None else []
            self.cache[path] = [s for s in symbols if s.kind == "function"]
        return self.cache[path]

    def lines(self, path: str) -> list[str]:
        if path not in self.text:
            self.text[path] = (blob(self.repo, self.rev, path) or "").splitlines()
        return self.text[path]

    def test_ranges(self, path: str) -> list[tuple[int, int]]:
        """Line ranges of `#[cfg(test)] mod x { ... }` blocks, by brace counting."""
        if path not in self.tests:
            source = "\n".join(re.sub(r'//.*|"(\\.|[^"\\])*"', "", line) for line in self.lines(path))
            ranges = []
            for m in TEST_MOD.finditer(source):
                depth, i = 1, m.end()
                while depth and i < len(source):
                    depth += {"{": 1, "}": -1}.get(source[i], 0)
                    i += 1
                ranges.append((source.count("\n", 0, m.start()) + 1, source.count("\n", 0, i) + 1))
            self.tests[path] = ranges
        return self.tests[path]

    def classify(self, path: str, line: int):
        """What a line belongs to: ("fn", symbol), ("test", None), ("import", None) or ("item", None)."""
        owner = self.innermost(path, line)
        if owner is not None:
            return ("test", None) if owner.attrs.get("in_test") else ("fn", owner)
        if any(a <= line <= b for a, b in self.test_ranges(path)):
            return "test", None
        lines = self.lines(path)
        for i in range(line - 2, max(line - 42, -1), -1):      # a continuation line of a multi-line `use`
            if i >= len(lines) or ";" in lines[i]:
                break
            if USE_START.match(lines[i]):
                return "import", None
        return "item", None

    def innermost(self, path: str, line: int):
        best = None
        for fn in self.functions(path):
            if fn.line_start <= line <= fn.line_end and (best is None or fn.line_end - fn.line_start < best.line_end - best.line_start):
                best = fn
        return best


def localize_diff(repo: Path, record: dict) -> dict:
    vuln, fixed, member = record["vuln_rev"], record["fixed_rev"], record.get("member")
    manifests = {p for p in git(repo, "ls-tree", "-r", "--name-only", vuln).splitlines() if p.endswith("Cargo.toml")}
    old_syms = Symbols(repo, vuln, member, manifests)
    new_syms = Symbols(repo, fixed, member, manifests)
    diff = parse_diff(git(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M", "-w",
                          "--ignore-blank-lines", "-U0", vuln, fixed))
    dropped: Counter = Counter()
    other_files: list[str] = []
    functions: dict[tuple[str, str], dict] = {}
    file_lines: dict[str, list[int]] = {}
    inserted_only: dict[str, list[str]] = {}
    changed_lines = 0
    rust_files: set[str] = set()

    for f in diff:
        path = f["old"] or f["new"]
        reason = drop_reason(path)
        if reason:
            dropped[reason] += 1
            continue
        if not path.endswith(".rs"):
            other_files.append(path)
            continue
        if f["old"] is None:
            # A file that does not exist in the vulnerable snapshot cannot locate anything in it.
            news = [fn for fn in new_syms.functions(f["new"])]
            if news and all(fn.attrs.get("in_test") for fn in news):
                dropped["test"] += 1
            else:
                inserted_only.setdefault(f["new"], []).append("new file")
            continue
        file_hit = False
        for h in f["hunks"]:
            old_code = [(n, old_syms.classify(path, n)) for i, t in enumerate(h["old_lines"])
                        if not TRIVIAL_LINE.match(t) for n in [h["old_start"] + i]]
            new_code = [(n, new_syms.classify(f["new"], n)) for i, t in enumerate(h["new_lines"])
                        if not TRIVIAL_LINE.match(t) for n in [h["new_start"] + i]] if f["new"] else []
            old_code = [(n, c) for n, c in old_code if c[0] != "import"]
            new_code = [(n, c) for n, c in new_code if c[0] != "import"]
            if not old_code and not new_code:
                dropped["comment-or-import hunk"] += 1
                continue
            if all(c[0] == "test" for _, c in old_code) and all(c[0] == "test" for _, c in new_code):
                dropped["test hunk"] += 1
                continue
            old_code = [(n, c) for n, c in old_code if c[0] != "test"]
            new_code = [(n, c) for n, c in new_code if c[0] != "test"]
            if old_code:
                changed_lines += len(old_code) + len(new_code)
                file_hit = True
                for n, (kind, owner) in old_code:
                    if kind == "fn":
                        functions.setdefault((path, owner.qualified_name), {"fn": owner, "lines": []})["lines"].append(n)
                    else:
                        file_lines.setdefault(path, []).append(n)
                continue
            # Pure insertion: between old lines p and p+1 (old_count 0), or replacing trivia at p.
            point = h["old_start"]
            after = point + 1 if h["old_count"] == 0 else point
            kind, owner = old_syms.classify(path, point)
            if kind == "test":
                dropped["test hunk"] += 1
                continue
            changed_lines += len(new_code)
            file_hit = True
            if kind == "fn" and after <= owner.line_end and old_syms.innermost(path, after) is owner:
                functions.setdefault((path, owner.qualified_name), {"fn": owner, "lines": []})["lines"].append(point)
            else:
                added = sorted({c[1].qualified_name for _, c in new_code if c[0] == "fn"})
                inserted_only.setdefault(path, []).extend(added or ["item-level lines"])
        if file_hit:
            rust_files.add(path)

    truth: list[dict] = []
    for (path, qname), hit in sorted(functions.items(), key=lambda kv: (kv[0][0], kv[1]["fn"].line_start)):
        entry = {"file": path, "function": qname, "lines": [hit["fn"].line_start, hit["fn"].line_end]}
        if not old_syms.inside_member(path):
            entry["outside_member"] = True
        truth.append(entry)
    for path, lines in sorted(file_lines.items()):
        entry = {"file": path, "lines": [min(lines), max(lines)]}
        if not old_syms.inside_member(path):
            entry["outside_member"] = True
        truth.append(entry)
    if not truth:
        for path in sorted(inserted_only) or sorted(other_files):
            entry = {"file": path}
            if not old_syms.inside_member(path):
                entry["outside_member"] = True
            truth.append(entry)

    n_functions = len(functions)
    excluded = None
    if not truth:
        excluded = "no source change left after dropping tests, docs, manifests and configuration: " \
                   + ", ".join(f"{n} {k}" for k, n in sorted(dropped.items()))
    elif n_functions > MAX_FUNCTIONS or len(rust_files) > MAX_FILES:
        excluded = (f"large refactor: the fix touches {n_functions} functions in {len(rust_files)} Rust files "
                    f"({changed_lines} changed lines) after filtering; threshold is more than {MAX_FUNCTIONS} "
                    f"functions or more than {MAX_FILES} files")
    return {
        "ground_truth": truth,
        "granularity": "function" if functions else "file",
        "source": "diff",
        "excluded": excluded,
        "detail": {"dropped": dict(dropped), "other_files": other_files, "rust_files": sorted(rust_files),
                   "functions": n_functions, "changed_lines": changed_lines,
                   "inserted_outside_functions": {k: sorted(set(v)) for k, v in inserted_only.items()}},
    }


def advisory_paths(field: str) -> list[str]:
    return re.findall(r'"([A-Za-z0-9_:<> ,]+)"\s*=', field or "")


def advisory_db_paths(advisory_db: Path, package: str, case_id: str) -> list[str]:
    """`[affected.functions]` of the advisory-db checkout. It names functions for more cases than
    the RustXec index does; these are only recorded in localize.json as a cross-check of the diff."""
    path = advisory_db / "crates" / package / f"{case_id}.md"
    if not path.exists():
        return []
    m = re.search(r"```toml\n(.*?)```", path.read_text(), re.DOTALL)
    try:
        front = tomllib.loads(m.group(1)) if m else {}
    except tomllib.TOMLDecodeError:
        return []
    return list(((front.get("affected") or {}).get("functions") or {}).keys())


def localize_advisory(repo: Path, record: dict, paths: list[str]) -> dict:
    vuln, member = record["vuln_rev"], record.get("member") or ""
    manifests = {p for p in git(repo, "ls-tree", "-r", "--name-only", vuln).splitlines() if p.endswith("Cargo.toml")}
    syms = Symbols(repo, vuln, record.get("member"), manifests)
    truth: list[dict] = []
    for apath in paths:
        segs = [s for s in apath.split("::") if s][1:]          # drop the crate name
        name, owner = segs[-1], (segs[-2] if len(segs) > 1 else None)
        pathspec = [member] if member else ["."]
        try:
            listing = git(repo, "grep", "-l", "-w", "-e", f"fn {name}", vuln, "--", *pathspec)
        except RuntimeError:
            listing = ""
        candidates = []
        for line in listing.splitlines():
            path = line.split(":", 1)[1]
            if not path.endswith(".rs") or drop_reason(path):
                continue
            for fn in syms.functions(path):
                if fn.name != name or fn.attrs.get("in_test"):
                    continue
                chain = [s for s in fn.qualified_name.split(".") if not s.startswith("<")]
                shared = len(set(segs[:-1]) & set(chain[:-1]))     # module and type segments in common
                candidates.append((path, fn, len(chain) > 1 and chain[-2] == owner, shared))
        exact = [c for c in candidates if c[2]]
        if exact:       # same type name in several modules: keep the one(s) sharing most of the path
            best = max(c[3] for c in exact)
            exact = [c for c in exact if c[3] == best]
        chosen = exact or (candidates if len(candidates) == 1 else [])
        if not chosen:
            truth.append({"file": None, "advisory_path": apath})
            continue
        for path, fn, _, _ in chosen:
            if any(t.get("function") == fn.qualified_name and t["file"] == path for t in truth):
                continue        # two advisory paths (a type and its re-export or wrapper) name the same function
            truth.append({"file": path, "function": fn.qualified_name, "lines": [fn.line_start, fn.line_end],
                          "advisory_path": apath})
    mapped = sum(1 for t in truth if t.get("function"))
    return {"ground_truth": truth, "granularity": "function", "source": "advisory", "excluded": None,
            "detail": {"advisory_paths": len(paths), "mapped_functions": mapped,
                       "unmapped": [t["advisory_path"] for t in truth if not t.get("function")]}}


# ---- cases.yaml ------------------------------------------------------------------------------

def scalar(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(scalar(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {scalar(v)}" for k, v in value.items()) + "}"
    raise TypeError(type(value))


def plain(value: str) -> str:
    """Unquoted where YAML reads it back as the same string."""
    return value if re.fullmatch(r"[A-Za-z][A-Za-z0-9_./:+-]*", value) and value not in ("null", "true", "false") else scalar(value)


def dump_cases(doc: dict) -> str:
    out = [HEADER.rstrip("\n"), ""]
    amendments = doc.get("amendments") or []
    if amendments:
        out.append("amendments:")
        out.extend(f"  - {scalar(a)}" for a in amendments)
    else:
        out.append("amendments: []")
    out.append("cases:")
    for case in doc["cases"]:
        out.append("")
        keys = [k for k in FIELD_ORDER if k in case] + [k for k in case if k not in FIELD_ORDER]
        for i, key in enumerate(keys):
            lead = "  - " if i == 0 else "    "
            value = case[key]
            if key == "ground_truth" and value:
                out.append(f"{lead}{key}:")
                out.extend(f"      - {scalar(entry)}" for entry in value)
            elif key == "expected_rules":
                out.append(f"{lead}{key}: [" + ", ".join(plain(v) for v in value) + "]")
            elif isinstance(value, str) and key in ("id", "class", "repo", "granularity", "source"):
                out.append(f"{lead}{key}: {plain(value)}")
            else:
                out.append(f"{lead}{key}: {scalar(value)}")
    return "\n".join(out) + "\n"


def load_cases(path: Path) -> dict:
    if not path.exists():
        return {"amendments": [], "cases": []}
    doc = yaml.safe_load(path.read_text()) or {}
    doc.setdefault("amendments", [])
    doc.setdefault("cases", [])
    return doc


def new_entry(case_id: str, klass: str, record: dict, loc: dict | None) -> dict:
    if record.get("status") != "ok":
        return {"id": case_id, "class": klass, "repo": record.get("repo"), "vuln_rev": None, "fixed_rev": None,
                "member": None, "ground_truth": [], "granularity": "file", "source": "diff",
                "excluded": f"not rebuilt: {record.get('reason', 'not fetched')}",
                "expected_rules": [], "expected_reason": "not decided: the case could not be rebuilt",
                "frozen": {"date": FREEZE_DATE, "catalogue": CATALOGUE}}
    return {"id": case_id, "class": klass, "repo": record["repo"], "vuln_rev": record["vuln_rev"],
            "fixed_rev": record["fixed_rev"], "member": record.get("member"),
            "ground_truth": loc["ground_truth"], "granularity": loc["granularity"], "source": loc["source"],
            "excluded": loc["excluded"],
            "expected_rules": [], "expected_reason": "UNDECIDED",
            "frozen": {"date": FREEZE_DATE, "catalogue": CATALOGUE}}


def show(case_id: str, row: dict, record: dict, repo: Path, advisory_db: Path, context: int) -> None:
    advisory = advisory_db / "crates" / row["package"] / f"{case_id}.md"
    print(f"===== {case_id}  {row['package']}  {row['categories']}  CWE {row['CWE']}")
    print(advisory.read_text() if advisory.exists() else f"(no advisory text at {advisory})")
    print(f"----- fix: {record.get('link')}  ({record.get('resolved_by')}; vuln = {record.get('vuln_rule')})")
    names = git(repo, "diff", "--name-only", "-M", record["vuln_rev"], record["fixed_rev"]).splitlines()
    kept = [n for n in names if not drop_reason(n)]
    print(f"----- {len(names)} files changed, {len(kept)} kept: {' '.join(kept)}")
    if kept:
        print(git(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M", "-w", f"-U{context}",
                  record["vuln_rev"], record["fixed_rev"], "--", *kept))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("ids", nargs="*", help="case ids (default: all)")
    ap.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    ap.add_argument("--advisory-db", type=Path, default=DEFAULT_ADVISORY_DB)
    ap.add_argument("--overwrite-auto", action="store_true",
                    help="re-derive the automatic fields of existing entries whose source is not manual")
    ap.add_argument("--show", action="store_true", help="print advisory text and the kept diff of the given cases")
    ap.add_argument("--context", type=int, default=6, help="context lines for --show")
    args = ap.parse_args()
    logging.getLogger().setLevel(logging.ERROR)   # the parser warns on every file with a syntax error

    with args.metadata.open(encoding="utf-8-sig", newline="") as fh:
        rows = {r["id"]: r for r in csv.DictReader(fh)}
    fetch_path = args.corpus / "fetch.json"
    if not fetch_path.exists():
        print(f"{fetch_path} is missing: run fetch.py first", file=sys.stderr)
        return 2
    records = json.loads(fetch_path.read_text())

    if args.show:
        for case_id in args.ids:
            show(case_id, rows[case_id], records[case_id], args.corpus / case_id / "repo.git", args.advisory_db, args.context)
        return 0

    doc = load_cases(args.cases)
    existing = {c["id"]: c for c in doc["cases"]}
    detail_path = args.corpus / "localize.json"
    details = json.loads(detail_path.read_text()) if detail_path.exists() else {}
    added = changed = differing = 0

    for case_id, row in rows.items():
        if args.ids and case_id not in args.ids:
            continue
        record = records.get(case_id) or {"status": "failed", "reason": "no fetch record"}
        categories = json.loads(row["categories"])
        klass = CLASS_OF[categories[0]]
        loc = None
        if record.get("status") == "ok":
            repo = args.corpus / case_id / "repo.git"
            diff_loc = localize_diff(repo, record)
            paths = advisory_paths(row["affected.functions"])
            loc = localize_advisory(repo, record, paths) if paths else diff_loc
            details[case_id] = {"package": row["package"], "source": loc["source"], "detail": loc["detail"],
                                "ground_truth": loc["ground_truth"], "excluded": loc["excluded"],
                                "diff": {"ground_truth": diff_loc["ground_truth"], "granularity": diff_loc["granularity"],
                                         "excluded": diff_loc["excluded"], **diff_loc["detail"]}}
            db_paths = [] if paths else advisory_db_paths(args.advisory_db, row["package"], case_id)
            if db_paths:
                named = localize_advisory(repo, record, db_paths)["ground_truth"]
                in_diff = {(t["file"], t.get("function")) for t in diff_loc["ground_truth"]}
                details[case_id]["advisory_db"] = {
                    "ground_truth": named,
                    "mapped": sum(1 for t in named if t.get("function")),
                    "in_diff_ground_truth": sum(1 for t in named if t.get("function") and (t["file"], t["function"]) in in_diff)}
        entry = new_entry(case_id, klass, record, loc)
        old = existing.get(case_id)
        if old is None:
            doc["cases"].append(entry)
            existing[case_id] = entry
            added += 1
            status = "added"
        else:
            diffs = [k for k in AUTO_FIELDS if old.get(k) != entry.get(k)]
            if not diffs:
                status = "unchanged"
            elif args.overwrite_auto and old.get("source") != "manual":
                for k in diffs:
                    old[k] = entry[k]
                changed += 1
                status = "rewritten: " + ", ".join(diffs)
            else:
                differing += 1
                status = "kept (" + ("manual" if old.get("source") == "manual" else "frozen") + "), differs in: " + ", ".join(diffs)
        gt = existing[case_id]
        print(f"{case_id}  {row['package']:22} {klass} {gt['source']:8} {gt['granularity']:8} "
              f"{len(gt['ground_truth']):3} entries  {status}{'  EXCLUDED' if gt['excluded'] else ''}")

    order = {case_id: i for i, case_id in enumerate(rows)}
    doc["cases"].sort(key=lambda c: order.get(c["id"], len(order)))
    args.cases.write_text(dump_cases(doc))
    detail_path.write_text(json.dumps(details, indent=1, sort_keys=True) + "\n")
    yaml.safe_load(args.cases.read_text())    # the file must read back
    print(f"\n{added} added, {changed} rewritten, {differing} existing entries differ from the automatic result "
          f"and were kept; {len(doc['cases'])} cases in {args.cases}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
