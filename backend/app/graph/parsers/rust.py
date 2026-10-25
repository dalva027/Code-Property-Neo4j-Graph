"""Rust parser built on tree-sitter.

Rust items map onto the shared model: struct/enum/union/trait become "class" symbols and fns become
"function" symbols, each with a `subkind` saying which Rust item it was. Paths are rewritten from
`a::b::c` to dotted qualified names (resolving `crate`, `self`, `super`, `Self` and `use` aliases)
so the builder's lexical resolution works unchanged.
"""
import logging
from dataclasses import dataclass

import tree_sitter_rust
from tree_sitter import Language, Node, Parser

from app.graph.parsers.base import ParsedFile, ParsedSymbol

log = logging.getLogger(__name__)

RUST = Language(tree_sitter_rust.language())

_TYPE_ITEMS = {"struct_item": "struct", "enum_item": "enum", "union_item": "union", "trait_item": "trait"}
_FN_ITEMS = ("function_item", "function_signature_item")
_BRANCHES = {"if_expression", "while_expression", "for_expression", "match_arm"}
_SCOPES = {"closure_expression", "function_item", "impl_item", "mod_item", "trait_item"}
_PATH_NODES = {"identifier", "type_identifier", "crate", "self", "super", "metavariable"}
_COMMENTS = ("line_comment", "block_comment")

# Attributes that say nothing about how a fn is reached; anything else (#[test], #[tokio::main],
# #[no_mangle], proc-macro attributes...) marks it as an entry point, like a Python decorator.
_NON_ENTRY_ATTRS = {
    "inline", "must_use", "allow", "warn", "deny", "forbid", "expect", "doc", "cfg", "cfg_attr",
    "deprecated", "track_caller", "cold",
}


def _text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _segments(node: Node | None) -> list[str] | None:
    """`a::b::<T>::c` -> ["a", "b", "c"]; None for anything that is not a plain path."""
    if node is None:
        return None
    if node.type in _PATH_NODES:
        return [_text(node)]
    if node.type in ("scoped_identifier", "scoped_type_identifier"):
        name = node.child_by_field_name("name")
        path = node.child_by_field_name("path")
        head = _segments(path) if path is not None else []
        return head + [_text(name)] if head is not None and name is not None else None
    if node.type == "generic_type":
        return _segments(node.child_by_field_name("type"))
    if node.type == "generic_function":
        return _segments(node.child_by_field_name("function"))
    if node.type == "reference_type":
        return _segments(node.child_by_field_name("type"))
    return None


def _complexity(fn: Node) -> int:
    """Cyclomatic complexity of one fn body, not descending into closures or nested items."""
    body = fn.child_by_field_name("body")
    if body is None:
        return 1
    score = 1
    stack = [body]
    while stack:
        node = stack.pop()
        if node.type in _SCOPES:
            continue
        if node.type in _BRANCHES:
            score += 1
        elif node.type == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and op.type in ("&&", "||"):
                score += 1
        stack.extend(node.children)
    return score


def _entry_attributes(item: Node) -> int:
    """Count the attributes directly above an item that mark it as an entry point."""
    count = 0
    node = item.prev_sibling
    while node is not None and node.type in ("attribute_item", *_COMMENTS):
        if node.type == "attribute_item":
            attr = next((c for c in node.named_children if c.type == "attribute"), None)
            path = attr.named_children[0] if attr is not None and attr.named_children else None
            name = _text(path) if path is not None else ""
            if name not in _NON_ENTRY_ATTRS and not name.startswith(("rustfmt::", "clippy::")):
                count += 1
        node = node.prev_sibling
    return count


def _loc(node: Node) -> int:
    return node.end_point[0] - node.start_point[0] + 1


def module_names(rel_path: str) -> tuple[str, str]:
    """Return (dotted module name, crate root) for a .rs file path relative to the project root.

    `<crate>/src/lib.rs` is the crate root itself, `src/main.rs` is `<crate>.main` (so a lib and a
    bin in one package don't collide), and `src/a.rs` / `src/a/mod.rs` are both `<crate>.a`. The
    crate is named after its directory, or "crate" when the package sits at the project root.
    Files outside `src/` (tests, examples, build.rs) are their own crate roots.
    """
    parts = rel_path.removesuffix(".rs").split("/")
    if parts[-1] == "mod":
        parts = parts[:-1]
    if "src" in parts[:-1]:
        i = len(parts) - 1 - parts[::-1].index("src")
        crate_dir = parts[:i]
        crate = crate_dir[-1].replace("-", "_") if crate_dir else "crate"
        inner = parts[i + 1:]
        if inner == ["lib"]:
            inner = []
        module = ".".join([crate, *inner])
        return module, crate
    module = ".".join(p.replace("-", "_") for p in parts) or "crate"
    return module, module


@dataclass
class _Container:
    kind: str                  # "module" | "impl" | "trait impl" | "trait" | "fn"
    symbol: str | None         # qualified name of the enclosing symbol node, if there is one


class _Walker:
    def __init__(self, parsed: ParsedFile, crate: str):
        self.parsed = parsed
        self.crate = crate
        self.modules: list[str] = [parsed.module]      # innermost module path (inline `mod` aware)
        self.scope: list[str] = [parsed.module]        # qualified-name prefix for new symbols
        self.containers: list[_Container] = [_Container("module", None)]
        self.functions: list[str] = []                  # enclosing fns, innermost last
        self.self_type: list[str] = []                  # what `Self` means inside the current impl
        self.aliases: dict[str, str] = {}               # name brought in by `use` -> dotted path
        self.local_types: set[str] = set()
        self.impl_counts: dict[str, int] = {}
        self.seen: set[str] = set()

    # -- path handling -------------------------------------------------------
    def _rewrite(self, segs: list[str], aliases: bool = True) -> tuple[str, bool]:
        """Turn path segments into a dotted name. The flag says whether the path was anchored
        (crate/self/super/Self/alias) rather than left relative to wherever it is used."""
        head, rest = segs[0], segs[1:]
        if head == "crate":
            return ".".join([self.crate, *rest]), True
        if head == "self":
            return ".".join([self.modules[-1], *rest]), True
        if head == "super":
            base = self.modules[-1].split(".")
            while segs and segs[0] == "super":
                base = base[:-1]
                segs = segs[1:]
            return ".".join([*base, *segs]), True
        if head == "Self" and self.self_type:
            return ".".join([self.self_type[-1], *rest]), True
        if aliases and head in self.aliases:
            return ".".join([self.aliases[head], *rest]), True
        return ".".join(segs), False

    def _use_leaves(self, node: Node, prefix: list[str]) -> list[tuple[list[str], str | None]]:
        """Expand a use tree into (full path segments, local name) leaves; name None for globs."""
        if node.type in ("scoped_identifier", *_PATH_NODES):
            segs = prefix + (_segments(node) or [])
            if segs and segs[-1] == "self":                     # `use a::{self}`
                segs = segs[:-1]
            return [(segs, segs[-1])] if segs else []
        if node.type == "use_as_clause":
            segs = prefix + (_segments(node.child_by_field_name("path")) or [])
            alias = node.child_by_field_name("alias")
            return [(segs, _text(alias) if alias is not None else None)] if segs else []
        if node.type == "use_wildcard":
            path = next((c for c in node.named_children if c.type != "*"), None)
            segs = prefix + (_segments(path) or [])
            return [(segs, None)] if segs else []
        if node.type == "use_list":
            return [leaf for child in node.named_children for leaf in self._use_leaves(child, prefix)]
        if node.type == "scoped_use_list":
            path = node.child_by_field_name("path")
            inner = prefix + (_segments(path) or [])
            lst = node.child_by_field_name("list")
            return self._use_leaves(lst, inner) if lst is not None else []
        return []

    # -- pass 1: types, impls and `use` aliases, so pass 2 can resolve forward references --------
    def prescan(self, node: Node) -> None:
        for child in node.named_children:
            if child.type in _TYPE_ITEMS and (name := child.child_by_field_name("name")) is not None:
                self.local_types.add(f"{self.modules[-1]}.{_text(name)}")
            elif child.type == "use_declaration" and (arg := child.child_by_field_name("argument")):
                for segs, name in self._use_leaves(arg, []):
                    if name is not None and name != "_":
                        self.aliases[name] = self._rewrite(segs, aliases=False)[0]
            elif child.type == "impl_item" and (segs := _segments(child.child_by_field_name("type"))):
                body = child.child_by_field_name("body")
                fns = sum(c.type == "function_item" for c in body.named_children) if body else 0
                key = f"{self.modules[-1]}.{segs[-1]}"
                self.impl_counts[key] = self.impl_counts.get(key, 0) + fns
            elif child.type == "mod_item" and (body := child.child_by_field_name("body")) is not None:
                self.modules.append(f"{self.modules[-1]}.{_text(child.child_by_field_name('name'))}")
                self.prescan(body)
                self.modules.pop()

    # -- pass 2: symbols, imports, calls ---------------------------------------------------
    def visit(self, node: Node) -> None:
        handler = getattr(self, f"_visit_{node.type}", None)
        if handler is not None:
            handler(node)
        else:
            for child in node.children:
                self.visit(child)

    def _unique(self, qname: str) -> str:
        candidate, n = qname, 1
        while candidate in self.seen:
            n += 1
            candidate = f"{qname}~{n}"
        self.seen.add(candidate)
        return candidate

    def _symbol(self, node: Node, kind: str, subkind: str, qname: str, parent: str | None,
                metrics: dict[str, int]) -> None:
        name = node.child_by_field_name("name")
        self.parsed.symbols.append(ParsedSymbol(
            kind=kind, name=_text(name) if name is not None else "?", qualified_name=qname,
            line_start=node.start_point[0] + 1, line_end=node.end_point[0] + 1,
            parent=parent, metrics=metrics, subkind=subkind,
        ))

    def _visit_use_declaration(self, node: Node) -> None:
        arg = node.child_by_field_name("argument")
        if arg is None:
            return
        for segs, _ in self._use_leaves(arg, []):
            if not segs:
                continue
            path, anchored = self._rewrite(segs, aliases=False)
            candidates = [path, path.rpartition(".")[0]]
            if not anchored:
                # 2018 "uniform paths": `use a::X` may name a child module of the current one.
                local = f"{self.modules[-1]}.{path}"
                candidates += [local, local.rpartition(".")[0]]
            # The builder keeps whichever candidate is a real file; external crates drop out.
            self.parsed.imports.extend(c for c in candidates if c and c not in self.parsed.imports)

    def _visit_mod_item(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        if body is None:                                         # `mod foo;` declares a file
            return
        path = f"{self.modules[-1]}.{_text(node.child_by_field_name('name'))}"
        self.modules.append(path)
        self.scope.append(path)
        self.containers.append(_Container("module", None))
        self.visit(body)
        self.containers.pop()
        self.scope.pop()
        self.modules.pop()

    def _type_item(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        if name is None:
            return
        subkind = _TYPE_ITEMS[node.type]
        qname = self._unique(f"{self.scope[-1]}.{_text(name)}")
        body = node.child_by_field_name("body")
        metrics = {"loc": _loc(node)}
        if subkind == "trait":
            metrics["methods"] = sum(c.type in _FN_ITEMS for c in body.named_children) if body else 0
        else:
            metrics["methods"] = self.impl_counts.get(qname, 0)
            if subkind == "enum":
                metrics["variants"] = sum(c.type == "enum_variant" for c in body.named_children) if body else 0
            elif body is not None:
                metrics["fields"] = sum(c.type == "field_declaration" or body.field_name_for_child(i) == "type"
                                        for i, c in enumerate(body.children))
        self._symbol(node, "class", subkind, qname, self.containers[-1].symbol, metrics)

        if subkind != "trait":
            return
        bounds = node.child_by_field_name("bounds")
        for bound in bounds.named_children if bounds is not None else []:
            if segs := _segments(bound):
                self.parsed.inherits.append((qname, self._rewrite(segs)[0]))
        if body is not None:
            self.scope.append(qname)
            self.containers.append(_Container("trait", qname))
            self.self_type.append(qname)
            self.visit(body)
            self.self_type.pop()
            self.containers.pop()
            self.scope.pop()

    _visit_struct_item = _visit_enum_item = _visit_union_item = _visit_trait_item = _type_item

    def _visit_impl_item(self, node: Node) -> None:
        type_segs = _segments(node.child_by_field_name("type"))
        trait_node = node.child_by_field_name("trait")
        trait_segs = _segments(trait_node)
        body = node.child_by_field_name("body")
        module = self.modules[-1]

        if type_segs:
            type_ref, _ = self._rewrite(type_segs)
            candidates = [f"{module}.{type_segs[0]}", type_ref] if len(type_segs) == 1 else [type_ref]
            local = next((q for q in candidates if q in self.local_types), None)
            base = local or f"{self.scope[-1]}.{type_segs[-1]}"
            self_path = local or type_ref
        else:                                                    # tuples, slices, fn pointers...
            type_ref, local, base, self_path = None, None, f"{self.scope[-1]}.<impl>", None

        if trait_segs and type_ref:
            scope = f"{module}.{type_segs[-1]}"
            self.parsed.implements.append((scope, type_ref, self._rewrite(trait_segs)[0]))

        if body is None:
            return
        self.scope.append(f"{base}.<{trait_segs[-1]}>" if trait_segs else base)
        self.containers.append(_Container("trait impl" if trait_node is not None else "impl", local))
        if self_path:
            self.self_type.append(self_path)
        self.visit(body)
        if self_path:
            self.self_type.pop()
        self.containers.pop()
        self.scope.pop()

    def _fn_item(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        if name is None:
            return
        container = self.containers[-1]
        subkind = {"impl": "method", "trait impl": "trait impl fn", "trait": "trait fn"}.get(container.kind, "fn")
        qname = self._unique(f"{self.scope[-1]}.{_text(name)}")
        params = node.child_by_field_name("parameters")
        self._symbol(node, "function", subkind, qname, container.symbol, {
            "complexity": _complexity(node),
            "loc": _loc(node),
            "parameters": sum(c.type in ("parameter", "self_parameter") for c in params.named_children)
            if params is not None else 0,
            "decorators": _entry_attributes(node),
        })

        body = node.child_by_field_name("body")
        if body is None:
            return
        self.scope.append(qname)
        self.containers.append(_Container("fn", qname))
        self.functions.append(qname)
        self.visit(body)
        self.functions.pop()
        self.containers.pop()
        self.scope.pop()

    _visit_function_item = _visit_function_signature_item = _fn_item

    def _visit_call_expression(self, node: Node) -> None:
        func = node.child_by_field_name("function")
        if self.functions and func is not None:
            callee: str | None = None
            if func.type == "field_expression":
                value, field = func.child_by_field_name("value"), func.child_by_field_name("field")
                if field is not None:
                    # Receiver types are unknown; "_." keeps the builder from guessing a sibling.
                    receiver = "self" if value is not None and value.type == "self" else "_"
                    callee = f"{receiver}.{_text(field)}"
            elif segs := _segments(func):
                callee = self._rewrite(segs)[0]
            if callee:
                self.parsed.calls.append((self.functions[-1], callee))
        for child in node.children:
            self.visit(child)


class RustParser:
    language = "rust"
    extensions = (".rs",)

    def __init__(self) -> None:
        self._parser = Parser(RUST)

    def parse(self, rel_path: str, source: str) -> ParsedFile:
        tree = self._parser.parse(source.encode("utf-8"))
        if tree.root_node.has_error:
            log.warning("%s: syntax errors, graph may be incomplete", rel_path)
        module, crate = module_names(rel_path)
        parsed = ParsedFile(path=rel_path, module=module, language=self.language,
                            loc=source.count("\n") + 1)
        walker = _Walker(parsed, crate)
        walker.prescan(tree.root_node)
        walker.visit(tree.root_node)
        return parsed
