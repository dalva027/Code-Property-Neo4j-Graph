"""Walks a source tree, runs the language parsers, and resolves cross-references into a CodeGraph.

Pure Python, no database access, so it is easy to unit test.
"""
import logging
import os
from collections import defaultdict
from pathlib import Path

from app.graph.parsers import ParsedFile, parser_for
from app.models.graph import CodeGraph, EdgeKind, GraphEdge, GraphNode, NodeKind

log = logging.getLogger(__name__)

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
}


class GraphBuilder:
    def __init__(self, ignored_dirs: set[str] | None = None):
        self.ignored_dirs = ignored_dirs or IGNORED_DIRS

    def build(self, root: Path, project_id: str) -> CodeGraph:
        return self._assemble(self._parse_tree(root), project_id)

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
        return parsed

    # -- pass 2: build nodes, then resolve edges -----------------------------------
    def _assemble(self, files: list[ParsedFile], project_id: str) -> CodeGraph:
        def nid(qualified: str) -> str:
            return f"{project_id}:{qualified}"

        graph = CodeGraph()
        module_to_file: dict[str, str] = {}
        by_qname: dict[str, GraphNode] = {}
        by_name: dict[str, list[str]] = defaultdict(list)

        for pf in files:
            file_node = GraphNode(
                id=nid(pf.path), kind=NodeKind.file, name=Path(pf.path).name,
                qualified_name=pf.module, file=pf.path, line_start=1, line_end=pf.loc,
                language=pf.language, metrics={"loc": pf.loc, "symbols": len(pf.symbols)},
            )
            graph.nodes.append(file_node)
            module_to_file[pf.module] = file_node.id

            for sym in pf.symbols:
                if sym.qualified_name in by_qname:
                    log.warning("duplicate symbol %s in %s; keeping the first", sym.qualified_name, pf.path)
                    continue
                node = GraphNode(
                    id=nid(sym.qualified_name), kind=NodeKind(sym.kind), name=sym.name,
                    qualified_name=sym.qualified_name, file=pf.path,
                    line_start=sym.line_start, line_end=sym.line_end,
                    language=pf.language, subkind=sym.subkind, metrics=dict(sym.metrics),
                )
                graph.nodes.append(node)
                by_qname[sym.qualified_name] = node
                by_name[sym.name].append(sym.qualified_name)
                container = nid(sym.parent) if sym.parent else file_node.id
                graph.edges.append(GraphEdge(source=container, target=node.id, kind=EdgeKind.contains))

        seen: set[tuple[str, str, EdgeKind]] = set()

        def add(source: str, target: str, kind: EdgeKind) -> None:
            key = (source, target, kind)
            if source == target or key in seen:
                return
            seen.add(key)
            graph.edges.append(GraphEdge(source=source, target=target, kind=kind))

        for pf in files:
            src = nid(pf.path)
            for module in pf.imports:
                if target := module_to_file.get(module):
                    add(src, target, EdgeKind.imports)          # external imports are dropped
            for caller, callee in pf.calls:
                if target := self._resolve(callee, caller, by_qname, by_name):
                    add(nid(caller), nid(target), EdgeKind.calls)
            for cls, base in pf.inherits:
                if target := self._resolve(base, cls, by_qname, by_name):
                    add(nid(cls), nid(target), EdgeKind.inherits)
            for scope, typ, trait in pf.implements:
                source = self._resolve(typ, scope, by_qname, by_name)
                target = self._resolve(trait, scope, by_qname, by_name)
                if source and target:
                    add(nid(source), nid(target), EdgeKind.implements)
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
        suffix_matches = [q for q in candidates if q.endswith("." + ref)]
        if len(suffix_matches) == 1:
            return suffix_matches[0]
        return candidates[0] if len(candidates) == 1 else None
