"""Code facts from the rust-analyzer extractor, joined onto the tree-sitter parse.

`codegraph-extract code` loads a Cargo workspace with rust-analyzer and reports, per function,
every call site resolved to its definition (a workspace function, or an external path with the
receiver's real type: `std::option::Option::unwrap`, not `?::unwrap`), the calls macro expansions
make, index and integer-arithmetic operations with operand types, and a def-use data-flow graph.

Those are the facts that need name resolution and types. Everything lexical stays with the
tree-sitter parser: symbol spans, SAFETY comments, attributes, secret literals, complexity. The two
are joined by source position, which both parsers agree on: a function by its name token, a call by
the token that anchors it (the method name, or the start of the callee path). So for a function
the extractor analyzed, its calls, operations and data flow replace what tree-sitter guessed, and
for one it did not (cfg-disabled code, a file outside the module tree) the lexical facts stand.
The extractor also lists every item it sees, which a test compares with tree-sitter's symbols.

An external callee has several defensible names (where it is defined, where it is exported, the
`std` facade of a `core` item), so the extractor sends candidates, most public first. The loader
keeps the first one the rule catalogue matches, else the first; the rest become `aliases`.
"""
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path

from app.config import settings
from app.graph.extractor import ExtractorUnavailable, extractor_path
from app.graph.extractor import run as run_extractor_cli
from app.graph.parsers.base import (
    ParsedCall,
    ParsedFile,
    ParsedFlow,
    ParsedOp,
    ParsedRef,
    ParsedSymbol,
    ParsedVar,
)
from app.rules import PathMatcher

log = logging.getLogger(__name__)

CODE_SCHEMA_VERSION = 1
_STD = {"std", "core", "alloc"}


@dataclass
class OverlayStats:
    """What one extraction contributed, for scan notes and the evaluation."""
    functions: int = 0              # functions the extractor listed in scanned files
    analyzed: int = 0               # of those, analyzed by rust-analyzer and joined to a symbol
    unmatched: int = 0              # extractor functions with no tree-sitter symbol at that position
    sites: int = 0
    resolved_sites: int = 0
    method_calls: int = 0
    resolved_method_calls: int = 0
    macro_sites: int = 0            # sites that come from a macro expansion
    vars: int = 0
    flows: int = 0
    warnings: list[str] = field(default_factory=list)

    def add(self, other: "OverlayStats") -> None:
        for name in ("functions", "analyzed", "unmatched", "sites", "resolved_sites", "method_calls",
                     "resolved_method_calls", "macro_sites", "vars", "flows"):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.warnings.extend(other.warnings)


# -- running the extractor ---------------------------------------------------------------------
def enabled() -> bool:
    return settings.code_facts.lower() != "off"


def find_manifests(root: Path, ignored: set[str]) -> list[Path]:
    """Every Cargo.toml under `root`, shallowest first."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignored)
        if "Cargo.toml" in filenames:
            found.append(Path(dirpath) / "Cargo.toml")
    return sorted(found, key=lambda p: (len(p.parts), p.as_posix()))


@lru_cache(maxsize=4)
def _extractor_version(binary: str) -> str:
    try:
        return run_extractor_cli(["--version"], 120).strip()
    except ExtractorUnavailable:
        return "unknown"


def _cache_key(manifest: Path, root: Path, ignored: set[str]) -> str:
    """Hash of the extractor in use and of every source, manifest and lockfile under `root`.

    The extractor is identified by its path and its `--version`: after rebuilding it without a
    version bump (a wrapper script hides the binary's timestamp), empty the cache directory.
    """
    digest = hashlib.sha256()
    binary = extractor_path() or ""
    version = _extractor_version(binary)
    digest.update(f"{CODE_SCHEMA_VERSION}\0{binary}\0{version}\0{manifest.relative_to(root)}\0".encode())
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ignored)
        for name in sorted(filenames):
            if name.endswith(".rs") or name in ("Cargo.toml", "Cargo.lock"):
                path = Path(dirpath) / name
                digest.update(path.relative_to(root).as_posix().encode() + b"\0")
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def run_code_extractor(manifest: Path, root: Path, ignored: set[str] | None = None) -> dict:
    """Facts for the workspace of `manifest`, limited to files under `root`."""
    cache_file = None
    if settings.code_facts_cache:
        cache_dir = Path(settings.code_facts_cache)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{_cache_key(manifest, root, ignored or set())}.json"
        if cache_file.is_file():
            try:
                return _checked(json.loads(cache_file.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, ExtractorUnavailable):
                cache_file.unlink(missing_ok=True)
    args = ["code", "--manifest-path", str(manifest), "--root", str(root)]
    if settings.code_facts_offline:
        args.append("--offline")
    stdout = run_extractor_cli(args, settings.code_facts_timeout_seconds)
    try:
        facts = _checked(json.loads(stdout))
    except json.JSONDecodeError as exc:
        raise ExtractorUnavailable(f"unreadable extractor output: {exc}") from exc
    if cache_file is not None:
        cache_file.write_text(stdout, encoding="utf-8")
    return facts


def _checked(facts: dict) -> dict:
    if facts.get("schema_version") != CODE_SCHEMA_VERSION:
        raise ExtractorUnavailable(
            f"extractor code schema {facts.get('schema_version')}, expected {CODE_SCHEMA_VERSION}")
    return facts


def load_code_facts(root: Path, files: list[ParsedFile], matcher: PathMatcher,
                    ignored: set[str]) -> OverlayStats | None:
    """Run the extractor for each Cargo workspace under `root` and overlay its facts onto `files`.

    Returns None when there is nothing to do (no Cargo project, extractor switched off). A missing
    binary or a failed run is a warning in the stats; the tree-sitter facts then stand as they are.
    """
    if not enabled() or not any(pf.language == "rust" for pf in files):
        return None
    manifests = find_manifests(root, ignored)
    if not manifests:
        return None
    total = OverlayStats()
    if extractor_path() is None:
        total.warnings.append(f"code facts skipped: {settings.codegraph_extractor} not found; calls are resolved "
                              "lexically and there is no data flow")
        return total
    covered: set[str] = set()         # files some workspace already reported
    failed: list[str] = []            # directory prefixes of manifests whose run failed
    for manifest in manifests:
        rel_dir = manifest.parent.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        mine = [pf.path for pf in files if pf.language == "rust" and pf.path.startswith(prefix)]
        if not mine or all(path in covered for path in mine):
            continue                  # a member of a workspace that was already loaded
        if any(prefix.startswith(above) for above in failed):
            # Most likely a member of the workspace that just failed to load: running it would
            # load the same workspace again and fail the same way, once per member.
            continue
        try:
            facts = run_code_extractor(manifest, root, ignored)
        except ExtractorUnavailable as exc:
            total.warnings.append(f"code facts skipped for {manifest.relative_to(root)}: {exc}")
            log.warning("code extractor failed for %s: %s", manifest, exc)
            failed.append(prefix)
            continue
        covered.update(f["path"] for f in facts["files"])
        stats = overlay(files, facts, matcher)
        stats.warnings = [f"{manifest.relative_to(root)}: {w}" for w in stats.warnings]
        total.add(stats)
    return total


# -- joining facts onto the parse ----------------------------------------------------------------
def _choose(candidates: list[str], matcher: PathMatcher, section: str | None = None) -> str | None:
    for path in candidates:
        if matcher.matches(path, section):
            return path
    return candidates[0] if candidates else None


def _attrs(site: dict) -> tuple[tuple[str, str | bool | int], ...]:
    attrs: dict[str, str | bool | int] = {"ret_kind": site.get("ret_kind") or "unknown",
                                           "arg_count": site.get("arg_count", 0)}
    if site.get("recv_type"):
        attrs["recv_type"] = site["recv_type"][0]
    if site.get("in_macro"):
        attrs["in_macro"] = True
    if site.get("writes_out"):
        attrs["writes_out"] = True
    if site.get("base_kind"):
        attrs["base_kind"] = site["base_kind"]
    if site.get("detail") and site["kind"] == "macro":
        attrs["detail"] = site["detail"]            # the format string of a format-like macro
    return tuple(attrs.items())


def overlay(files: list[ParsedFile], facts: dict, matcher: PathMatcher) -> OverlayStats:
    """Replace the calls and operations of every analyzed function with the extractor's, and attach
    variables and flow edges. Mutates `files`; pure otherwise, so it is tested on a fixture."""
    stats = OverlayStats(warnings=list(facts.get("warnings", [])))
    by_path = {pf.path: pf for pf in files if pf.language == "rust"}
    file_path = {f["id"]: f["path"] for f in facts["files"]}
    local_crates = {c["name"] for c in facts.get("crates", [])}
    fns = {f["id"]: f for f in facts["fns"]}

    by_pos: dict[str, dict[tuple[int, int], ParsedSymbol]] = {
        path: {(s.name_line, s.name_col): s for s in pf.symbols if s.kind == "function"}
        for path, pf in by_path.items()
    }
    symbols: dict[int, tuple[ParsedFile, ParsedSymbol]] = {}
    for fn in fns.values():
        path = file_path.get(fn["file"])
        pf = by_path.get(path) if path is not None else None
        if pf is None:
            continue
        stats.functions += 1
        sym = by_pos[pf.path].get((fn["line"], fn["col"]))
        if sym is None:
            stats.unmatched += 1
            continue
        if fn["analyzed"]:
            symbols[fn["id"]] = (pf, sym)
            _typed_signature(sym, fn, matcher)
    analyzed = {fid for fid in symbols if fns[fid]["has_body"]}
    stats.analyzed = len(analyzed)
    analyzed_names: dict[str, set[str]] = {}
    for fid in analyzed:
        pf, sym = symbols[fid]
        analyzed_names.setdefault(pf.path, set()).add(sym.qualified_name)

    # Tree-sitter's calls of analyzed functions step aside; they stay available by position for
    # the sites rust-analyzer could not resolve.
    lexical: dict[tuple[str, str, int, int], ParsedCall] = {}
    for path, names in analyzed_names.items():
        pf = by_path[path]
        kept = []
        for call in pf.calls:
            if call.caller in names:
                lexical.setdefault((path, call.caller, call.line, call.col), call)
            else:
                kept.append(call)
        pf.calls = kept
        pf.ops = [op for op in pf.ops if op.caller not in names]

    site_file: dict[int, ParsedFile] = {}
    for site in facts["sites"]:
        if site["fn"] not in analyzed:
            continue
        pf, sym = symbols[site["fn"]]
        caller = sym.qualified_name
        kind, name, line, col = site["kind"], site["name"], site["line"], site["col"]
        common = {"site": site["id"], "seq": site.get("seq", 0), "attrs": _attrs(site)}
        site_file[site["id"]] = pf
        stats.sites += 1
        stats.macro_sites += bool(site.get("in_macro"))
        if kind in ("index", "arith", "struct"):
            pf.ops.append(ParsedOp(caller, kind, line, col, bool(site["in_unsafe"]), site.get("detail") or "",
                                   **common))
            continue
        stats.method_calls += kind == "method"
        literal_args = tuple((int(i), str(k), str(t)) for i, k, t in site.get("literal_args", []))
        base = {"caller": caller, "line": line, "col": col, "in_unsafe": bool(site["in_unsafe"]),
                "literal_args": literal_args, "is_macro": kind == "macro", **common}
        ts = lexical.get((pf.path, caller, line, col))
        target = symbols.get(site["target"]) if site.get("target") is not None else None
        if target is not None:
            stats.resolved_sites += 1
            stats.resolved_method_calls += kind == "method"
            call = ParsedCall(callee=target[1].qualified_name, external=None, resolvable=True, **base)
        elif site.get("target") is not None or (
                kind == "macro" and site.get("def_crate") in local_crates):
            # A workspace function or macro with no symbol in the scanned files: the site still
            # exists for data flow, with nothing to point at.
            stats.resolved_sites += 1
            call = ParsedCall(callee=name, external=None, resolvable=False, **base)
        elif site["resolved"] and site["paths"]:
            stats.resolved_sites += 1
            stats.resolved_method_calls += kind == "method"
            candidates = list(site["paths"])
            written = ts.external if ts is not None and kind == "call" else None
            if written and "::" in written and written not in candidates:
                # The path as written, after `use` aliases. When it starts at a crate it is the
                # name the user chose (`sha2::Sha256::digest` for a trait method that several
                # crates re-export), so it leads; `Foo::bar` from a glob import only follows.
                if written[0].islower():
                    candidates.insert(0, written)
                else:
                    candidates.append(written)
            path = _choose(candidates, matcher) or candidates[0]
            crate = site.get("def_crate")
            call = ParsedCall(callee=name, external=path, resolvable=False,
                              aliases=tuple(c for c in candidates if c != path),
                              crate=crate if crate and crate not in _STD else None, **base)
        elif ts is not None:
            # Unresolved by rust-analyzer: keep the lexical guess, with the site's identity.
            call = replace(ts, **common)
        elif kind == "method":
            call = ParsedCall(callee=f"_.{name}", external=f"?::{name}", resolvable=True, **base)
        else:
            call = ParsedCall(callee=name, external=None, resolvable=False, **base)
        pf.calls.append(call)

    for ref in facts.get("refs", []):
        if ref["fn"] not in analyzed:
            continue
        pf, sym = symbols[ref["fn"]]
        target = symbols.get(ref["target"]) if ref.get("target") is not None else None
        if target is not None:
            pf.refs.append(ParsedRef(sym.qualified_name, target[1].qualified_name, ref["line"], None,
                                     ref.get("via", ""), resolvable=True))
        elif ref.get("paths"):
            pf.refs.append(ParsedRef(sym.qualified_name, "", ref["line"], _choose(ref["paths"], matcher),
                                     ref.get("via", ""), resolvable=False))

    var_file: dict[int, ParsedFile] = {}
    for var in facts.get("vars", []):
        entry = symbols.get(var["fn"])
        if entry is None:
            continue
        pf, sym = entry
        var_file[var["id"]] = pf
        stats.vars += 1
        pf.vars.append(ParsedVar(
            id=var["id"], function=sym.qualified_name, name=var["name"], kind=var["kind"], line=var["line"],
            col=var["col"], index=var.get("index"), type=var.get("ty"), ty_kind=var.get("ty_kind") or "unknown",
            type_path=(var.get("type_paths") or [None])[0],
            param_type=_choose(var.get("param_type_paths") or [], matcher, "sources"),
            guards=tuple(var.get("guards") or ()),
        ))

    def endpoint(ref: str) -> tuple[tuple[str, int], ParsedFile | None]:
        kind, number = ref[0], int(ref[1:])
        return (kind, number), (var_file if kind == "v" else site_file).get(number)

    for flow in facts.get("flows", []):
        source, source_file = endpoint(flow["from"])
        target, target_file = endpoint(flow["to"])
        if source_file is None or target_file is None:
            continue
        stats.flows += 1
        source_file.flows.append(ParsedFlow(source, target, flow["kind"], flow.get("via", "")))

    for trait_fn, impl_fn in facts.get("dispatch", []):
        if trait_fn in symbols and impl_fn in symbols:
            pf, sym = symbols[impl_fn]
            pf.dispatch.append((symbols[trait_fn][1].qualified_name, sym.qualified_name))

    for pf in by_path.values():
        pf.calls.sort(key=lambda c: (c.line, c.col, c.seq))
        pf.ops.sort(key=lambda o: (o.line, o.col, o.seq))
    return stats


def _typed_signature(sym: ParsedSymbol, fn: dict, matcher: PathMatcher) -> None:
    """Put resolved parameter types into the symbol's `params`, so a handler is recognised by its
    extractor types even when they were imported by glob or re-export."""
    if fn.get("ret_kind"):
        sym.attrs["ret_kind"] = fn["ret_kind"]
    if fn.get("ret_type"):
        sym.attrs["ret_type"] = fn["ret_type"]
    typed = {p["index"]: p for p in fn.get("params", []) if p.get("type_paths")}
    if not typed or "params" not in sym.attrs:
        return
    try:
        params = json.loads(str(sym.attrs["params"]))
    except ValueError:
        return
    for param in params:
        fact = typed.get(param.get("index"))
        if fact is not None:
            param["path"] = _choose(fact["type_paths"], matcher, "sources")
    sym.attrs["params"] = json.dumps(params, separators=(",", ":"))
