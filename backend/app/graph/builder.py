"""Walks a source tree, runs the language parsers, and resolves cross-references into a CodeGraph.

Pure Python, no database access, so it is easy to unit test.

Calls that do not resolve to a project symbol become External nodes when the parser supplied a
`::` path for them (Rust does; Python does not, so its unresolved calls are still dropped).
CALLS edges carry `line` (first call site), `count` (call sites from that caller) and `unsafe`
(any call site inside an `unsafe` span).

Security facts from the parsers become their own nodes: `Unsafe` spans contained by their
function, `Call` nodes for index/arithmetic operations and for call sites whose callee is in the
rule catalogue (so rules have a line and literal arguments per site), and redacted `Literal` nodes.
Functions passed as values give `REFERENCES` edges; a function handed to a web-framework routing
builder (`get(handler)`, `.service(index)`, `routes![..]`) or taking a framework extractor type is
marked `entry_kind = handler`, and `pub` functions of a library crate `pub_api`.

For Cargo projects the rust-analyzer extractor (app/graph/facts.py) overlays resolved and typed
facts onto the parse before the graph is assembled. Every call site it reports becomes a `Call`
node; parameters, locals and return values become `Var` nodes declared by their function; and its
def-use edges become `FLOWS_TO` (within a function), `PASSES` (argument to the callee's parameter)
and `RETURNS_TO` (the callee's return value to the call site). Without the extractor none of
those exist and the graph is the tree-sitter one.
"""
import json
import logging
import os
from collections import defaultdict
from pathlib import Path

from app.graph import facts
from app.graph.parsers import ParsedCall, ParsedFile, parser_for
from app.graph.parsers.base import ParsedOp
from app.models.graph import AttrValue, CodeGraph, EdgeKind, GraphEdge, GraphNode, NodeKind
from app.rules import Catalogue, PathMatcher, load_catalogue

log = logging.getLogger(__name__)

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
}
# Callees that take a request handler as an argument on axum, actix-web, rocket, poem, salvo, tide
# and tower; a function passed to one of these is an entry point.
HANDLER_VIA = {
    "get", "post", "put", "patch", "delete", "head", "options", "trace", "connect", "any",
    "route", "service", "to", "handler", "routes!", "to_async", "service_fn", "at",
}
_ENTRY_PRIORITY = {"test": 0, "main": 1, "ffi": 2, "handler": 3, "pub_api": 4}
_METHOD_SUBKINDS = {"method", "trait fn", "trait impl fn"}
_FLOW_EDGES = {"flow": EdgeKind.flows_to, "pass": EdgeKind.passes, "ret": EdgeKind.returns_to}


class GraphBuilder:
    def __init__(self, ignored_dirs: set[str] | None = None, catalogue: Catalogue | None = None):
        self.ignored_dirs = ignored_dirs or IGNORED_DIRS
        self.matcher: PathMatcher = (catalogue or load_catalogue()).matcher()
        # What the code extractor contributed to the last build; None when it did not run.
        self.code_facts: facts.OverlayStats | None = None
        self.warnings: list[str] = []      # files the last build had to skip, for the scan notes

    def build(self, root: Path, project_id: str) -> CodeGraph:
        self.warnings = []
        files = self._parse_tree(root)
        self.code_facts = facts.load_code_facts(root, files, self.matcher, self.ignored_dirs)
        return self._assemble(files, project_id)

    # -- pass 1: parse every supported file ---------------------------------------
    def _parse_tree(self, root: Path) -> list[ParsedFile]:
        parsed: list[ParsedFile] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in self.ignored_dirs)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                parser = parser_for(path)
                if parser is None:
                    continue
                rel = path.relative_to(root).as_posix()
                try:
                    source = path.read_text(encoding="utf-8", errors="replace")
                    parsed.append(parser.parse(rel, source))
                except SyntaxError as exc:
                    log.warning("skipping %s: %s", rel, exc)
                except RecursionError:
                    # The tree-sitter walk recurses over the syntax tree; a method chain or a
                    # binary expression a few hundred levels deep exhausts Python's stack. One
                    # such file must not fail the scan of a whole project.
                    log.warning("skipping %s: expression nesting too deep to walk", rel)
                    self.warnings.append(f"{rel} was skipped: its expressions nest too deeply to parse")
        return parsed

    # -- pass 2: build nodes, then resolve edges -----------------------------------
    def _assemble(self, files: list[ParsedFile], project_id: str) -> CodeGraph:
        def nid(qualified: str) -> str:
            return f"{project_id}:{qualified}"

        graph = CodeGraph()
        module_to_file: dict[str, str] = {}
        by_qname: dict[str, GraphNode] = {}
        by_name: dict[str, list[str]] = defaultdict(list)
        ids: set[str] = set()

        def emit(node: GraphNode) -> bool:
            if node.id in ids:
                return False
            ids.add(node.id)
            graph.nodes.append(node)
            return True

        for pf in files:
            attrs: dict = {}
            if pf.extern_crates:
                attrs["uses_crates"] = sorted(pf.extern_crates)
            if pf.in_test:
                attrs["in_test"] = True
            file_node = GraphNode(
                id=nid(pf.path), kind=NodeKind.file, name=Path(pf.path).name,
                qualified_name=pf.module, file=pf.path, line_start=1, line_end=pf.loc,
                language=pf.language, metrics={"loc": pf.loc, "symbols": len(pf.symbols), **pf.metrics},
                attrs=attrs,
            )
            emit(file_node)
            module_to_file[pf.module] = file_node.id

            for sym in pf.symbols:
                if sym.qualified_name in by_qname:
                    log.warning("duplicate symbol %s in %s; keeping the first", sym.qualified_name, pf.path)
                    continue
                node = GraphNode(
                    id=nid(sym.qualified_name), kind=NodeKind(sym.kind), name=sym.name,
                    qualified_name=sym.qualified_name, file=pf.path,
                    line_start=sym.line_start, line_end=sym.line_end,
                    language=pf.language, subkind=sym.subkind, metrics=dict(sym.metrics), attrs=dict(sym.attrs),
                )
                emit(node)
                by_qname[sym.qualified_name] = node
                by_name[sym.name].append(sym.qualified_name)
                container = nid(sym.parent) if sym.parent else file_node.id
                graph.edges.append(GraphEdge(source=container, target=node.id, kind=EdgeKind.contains))

        # `pub` functions of a library crate (one with a lib.rs) are reachable from outside.
        library_crates = {pf.crate for pf in files if pf.language == "rust" and pf.crate and pf.module == pf.crate}
        for pf in files:
            if pf.crate not in library_crates:
                continue
            for sym in pf.symbols:
                node = by_qname.get(sym.qualified_name)
                if node is not None and node.kind == NodeKind.function and node.attrs.get("visibility") == "pub" \
                        and "entry_kind" not in node.attrs and not node.attrs.get("in_test"):
                    node.attrs["entry_kind"] = "pub_api"

        seen: dict[tuple[str, str, EdgeKind], GraphEdge] = {}

        def add(source: str, target: str, kind: EdgeKind, props: dict | None = None) -> GraphEdge | None:
            key = (source, target, kind)
            if source == target and kind != EdgeKind.calls:       # self-calls stay: recursion matters
                return None
            if key in seen:
                return seen[key]
            edge = seen[key] = GraphEdge(source=source, target=target, kind=kind, props=dict(props or {}))
            graph.edges.append(edge)
            return edge

        externals: dict[str, str] = {}                  # `::` path -> node id
        site_nodes: dict[int, str] = {}                 # extractor site id -> Call node id
        var_nodes: dict[int, str] = {}                  # extractor var id -> Var node id

        def external(path: str, language: str, is_macro: bool = False, subkind: str | None = None,
                     crate: str | None = None, aliases: tuple[str, ...] = ()) -> str:
            if path not in externals:
                head, _, _ = path.partition("::")
                attrs: dict[str, AttrValue] = {"path": path, "is_macro": is_macro}
                if crate:
                    attrs["crate"] = crate              # the defining crate, known to the extractor
                elif head and head != "?" and "::" in path:
                    attrs["crate"] = head
                if aliases:
                    attrs["aliases"] = list(aliases)    # other paths the same item goes by
                node = GraphNode(
                    id=nid(path), kind=NodeKind.external, name=path.rsplit("::", 1)[-1],
                    qualified_name=path, language=language,
                    subkind=subkind or ("macro" if is_macro else "external"), attrs=attrs,
                )
                emit(node)
                externals[path] = node.id
            return externals[path]

        def mark_entry(node: GraphNode, kind: str) -> None:
            current = node.attrs.get("entry_kind")
            if current is None or _ENTRY_PRIORITY[kind] < _ENTRY_PRIORITY[str(current)]:
                node.attrs["entry_kind"] = kind

        def call_site(pf: ParsedFile, call: ParsedCall, caller_id: str, target_id: str | None) -> None:
            suffix = f":{call.seq}" if call.seq else ""
            site = GraphNode(
                id=nid(f"{pf.path}#call:{call.line}:{call.col}{suffix}"), kind=NodeKind.call,
                name=(call.external or call.callee).rsplit("::", 1)[-1].rsplit(".", 1)[-1],
                qualified_name=f"{call.caller}#call@{call.line}", file=pf.path, line_start=call.line,
                line_end=call.line, language=pf.language, subkind="call",
                attrs={"callee_path": call.external or call.callee, "in_unsafe": call.in_unsafe,
                       "literal_args": json.dumps([list(a) for a in call.literal_args], separators=(",", ":")),
                       **dict(call.attrs)},
            )
            if emit(site):
                add(caller_id, site.id, EdgeKind.has_call)
                if target_id:
                    add(site.id, target_id, EdgeKind.targets)
            if call.site is not None:
                site_nodes.setdefault(call.site, site.id)

        def op_site(pf: ParsedFile, op: ParsedOp) -> None:
            suffix = f":{op.seq}" if op.seq else ""
            node = GraphNode(
                id=nid(f"{pf.path}#op:{op.line}:{op.col}{suffix}"), kind=NodeKind.call, name=op.op,
                qualified_name=f"{op.caller}#{op.op}@{op.line}", file=pf.path, line_start=op.line,
                line_end=op.line, language=pf.language, subkind=op.op,
                attrs={"callee_path": f"ops::{op.op}", "in_unsafe": op.in_unsafe, "detail": op.detail,
                       **dict(op.attrs)},
            )
            if emit(node):
                add(nid(op.caller), node.id, EdgeKind.has_call)
            if op.site is not None:
                site_nodes.setdefault(op.site, node.id)

        for pf in files:
            src = nid(pf.path)
            for module in pf.imports:
                if target := module_to_file.get(module):
                    add(src, target, EdgeKind.imports)          # external imports are dropped

            for call in pf.calls:
                target = self._resolve(call.callee, call.caller, by_qname, by_name) if call.resolvable else None
                target_id: str | None
                if target:
                    target_id = nid(target)
                elif call.external:
                    target_id = external(call.external, pf.language, call.is_macro, crate=call.crate,
                                         aliases=call.aliases)
                elif call.site is not None:
                    target_id = None                            # a data-flow site with no known callee
                else:
                    continue                                    # unresolved, nothing to point at
                caller_id = nid(call.caller)
                if target_id and (edge := add(caller_id, target_id, EdgeKind.calls)):
                    edge.props["count"] = int(edge.props.get("count", 0)) + 1
                    edge.props.setdefault("line", call.line)
                    if call.in_unsafe:
                        edge.props["unsafe"] = True
                # The extractor's sites all get a node (data flow runs through them); tree-sitter's
                # only where the catalogue needs a line and literal arguments.
                if call.site is not None or (call.external and self.matcher.matches(call.external)):
                    call_site(pf, call, caller_id, target_id)

            for ref in pf.refs:
                caller_id = nid(ref.caller)
                target = self._resolve(ref.ref, ref.caller, by_qname, by_name) if ref.resolvable else None
                if target:
                    node = by_qname[target]
                    if node.kind != NodeKind.function:
                        continue
                    add(caller_id, node.id, EdgeKind.references, {"via": ref.via, "line": ref.line})
                    if ref.via in HANDLER_VIA:
                        mark_entry(node, "handler")
                elif ref.external and self.matcher.matches(ref.external):
                    add(caller_id, external(ref.external, pf.language, subkind="item"), EdgeKind.references,
                        {"via": ref.via, "line": ref.line})

            for cls, base in pf.inherits:
                if target := self._resolve(base, cls, by_qname, by_name):
                    add(nid(cls), nid(target), EdgeKind.inherits)
            for impl in pf.implements:
                source = self._resolve(impl.type, impl.scope, by_qname, by_name)
                target = self._resolve(impl.trait, impl.scope, by_qname, by_name)
                props = {"unsafe": True, "line": impl.line} if impl.is_unsafe else {}
                if source and target:
                    add(nid(source), nid(target), EdgeKind.implements, props)
                elif source and impl.trait_external and self.matcher.matches(impl.trait_external):
                    add(nid(source), external(impl.trait_external, pf.language, subkind="trait"),
                        EdgeKind.implements, props)

            for u in pf.unsafes:
                owner = nid(u.container) if u.container else (nid(u.owner_type) if u.owner_type else src)
                if owner not in ids:
                    owner = src
                attrs = {"has_safety_comment": u.has_safety_comment, "in_test": u.in_test}
                if u.trait:
                    attrs["trait"] = u.trait
                if u.target_type:
                    attrs["target_type"] = u.target_type
                node = GraphNode(
                    id=nid(f"{pf.path}#unsafe:{u.line_start}:{u.col}"), kind=NodeKind.unsafe, name=f"unsafe {u.kind}",
                    qualified_name=f"{u.container or pf.module}#unsafe@{u.line_start}", file=pf.path,
                    line_start=u.line_start, line_end=u.line_end, language=pf.language, subkind=u.kind,
                    metrics={"loc": u.line_end - u.line_start + 1}, attrs=attrs,
                )
                if emit(node):
                    add(owner, node.id, EdgeKind.contains)

            for op in pf.ops:
                op_site(pf, op)

            for var in pf.vars:
                owner = nid(var.function)
                if owner not in ids:
                    continue
                base = f"{var.function}#ret" if var.kind == "ret" else \
                    f"{pf.path}#var:{var.line}:{var.col}:{var.name}"
                node_id = nid(base)
                if node_id in ids:                              # several locals made by one macro call
                    node_id = nid(f"{base}~{var.id}")
                attrs: dict[str, AttrValue] = {"ty_kind": var.ty_kind}
                if var.type:
                    attrs["type"] = var.type
                if var.type_path:
                    attrs["type_path"] = var.type_path
                if var.param_type:
                    attrs["param_type"] = var.param_type
                if var.guards:
                    attrs["guards"] = list(var.guards)
                node = GraphNode(
                    id=node_id, kind=NodeKind.var, name=var.name, qualified_name=f"{var.function}#{var.name}",
                    file=pf.path, line_start=var.line, line_end=var.line, language=pf.language, subkind=var.kind,
                    metrics={"index": var.index} if var.index is not None else {}, attrs=attrs,
                )
                if emit(node):
                    add(owner, node_id, EdgeKind.declares)
                var_nodes[var.id] = node_id

            for lit in pf.literals:
                owner = nid(lit.container) if lit.container and nid(lit.container) in ids else src
                attrs = {"preview": lit.preview, "sha256": lit.sha256, "in_test": lit.in_test}
                if lit.binding:
                    attrs["binding"] = lit.binding
                if lit.pattern:
                    attrs["pattern"] = lit.pattern
                node = GraphNode(
                    id=nid(f"{pf.path}#lit:{lit.line}:{lit.col}"), kind=NodeKind.literal,
                    name=lit.binding or lit.pattern or "literal",
                    qualified_name=f"{lit.container or pf.module}#literal@{lit.line}", file=pf.path,
                    line_start=lit.line, line_end=lit.line, language=pf.language, subkind=lit.pattern or "bound",
                    metrics={"entropy": lit.entropy, "length": lit.length}, attrs=attrs,
                )
                if emit(node):
                    add(owner, node.id, EdgeKind.has_literal)

        # Data flow: the extractor's edges, now that both ends have node ids. An edge keeps every
        # `via` it was seen with, because a sink asks which argument position a value arrived at.
        for pf in files:
            for flow in pf.flows:
                source = (var_nodes if flow.source[0] == "v" else site_nodes).get(flow.source[1])
                target = (var_nodes if flow.target[0] == "v" else site_nodes).get(flow.target[1])
                if not source or not target or source == target:
                    continue
                key = (source, target, _FLOW_EDGES[flow.kind])
                if key in seen:
                    vias = seen[key].props["vias"]
                    if isinstance(vias, list) and flow.via not in vias:
                        vias.append(flow.via)
                else:
                    add(source, target, _FLOW_EDGES[flow.kind], {"via": flow.via, "vias": [flow.via]})
            for trait_fn, impl_fn in pf.dispatch:
                if nid(trait_fn) in ids and nid(impl_fn) in ids:
                    add(nid(trait_fn), nid(impl_fn), EdgeKind.references, {"via": "dispatch"})

        # Handlers by parameter type: a function taking a framework extractor (catalogue sources).
        for node in graph.nodes:
            if node.kind != NodeKind.function or "params" not in node.attrs:
                continue
            for param in json.loads(str(node.attrs["params"])):
                path = param.get("path")
                if path and any(m.entry.kind == "type" for m in self.matcher.match(path, "sources")):
                    mark_entry(node, "handler")
                    break
        return graph

    @staticmethod
    def _resolve(ref: str, scope: str, by_qname: dict[str, GraphNode],
                 by_name: dict[str, list[str]]) -> str | None:
        """Best-effort, purely lexical resolution of a dotted reference to a known symbol."""
        parts = scope.split(".")

        if ref.startswith(("self.", "cls.")):
            # Method on the enclosing class: walk outward until a class scope matches.
            member = ref.split(".", 1)[1]
            for i in range(len(parts), 0, -1):
                candidate = ".".join(parts[:i] + [member])
                if candidate in by_qname:
                    return candidate
            return None

        if ref in by_qname:                                     # fully qualified
            return ref
        for i in range(len(parts) - 1, 0, -1):                 # sibling in an enclosing scope
            candidate = ".".join(parts[:i] + [ref])
            if candidate in by_qname:
                return candidate

        simple = ref.rsplit(".", 1)[-1]                         # unique suffix / simple-name match
        candidates = by_name.get(simple, [])
        if ref.startswith("_."):
            # A method on an unknown receiver matches a method, never a free function: `.sum()` on an
            # iterator must not resolve to a project fn named `sum`.
            candidates = [q for q in candidates if by_qname[q].subkind in _METHOD_SUBKINDS]
        suffix_matches = [q for q in candidates if q.endswith("." + ref)]
        if len(suffix_matches) == 1:
            return suffix_matches[0]
        return candidates[0] if len(candidates) == 1 else None
