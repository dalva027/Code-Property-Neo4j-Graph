"""Rust parser built on tree-sitter.

Rust items map onto the shared model: struct/enum/union/trait become "class" symbols and fns become
"function" symbols, each with a `subkind` saying which Rust item it was. Paths are rewritten from
`a::b::c` to dotted qualified names (resolving `crate`, `self`, `super`, `Self` and `use` aliases)
so the builder's lexical resolution works unchanged.

Every call also carries an `external` path in `::` form, which the builder uses when the call does
not resolve to a project symbol: `std::mem::transmute`, `?::unwrap` for a method on an unknown
receiver, `std::println!` for a macro. Calls into this crate that fail to resolve (enum variant
constructors, macro-generated items) and bare single-segment names (locals, prelude constructors)
get no external path and are dropped, as before.

Macro bodies are token trees to tree-sitter. For format-like macros (`println!`, `format!`,
`assert!`, `vec!`, `log::info!`, ...) the argument tokens are re-parsed as an expression list so
calls inside them are seen.

Security facts (docs/build-plan.md, phase 2) come from the same walk: `unsafe` spans with
SAFETY-comment detection, function visibility/abi/async/entry kind, functions passed as values,
calls made inside `unsafe`, index and arithmetic operations, literal call arguments, and string
literals that look like secrets. Everything is syntactic; nothing here knows types.
"""
import hashlib
import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field

import tree_sitter_rust
from tree_sitter import Language, Node, Parser

from app.graph.parsers.base import (
    ParsedCall,
    ParsedFile,
    ParsedImpl,
    ParsedLiteral,
    ParsedOp,
    ParsedRef,
    ParsedSymbol,
    ParsedUnsafe,
)
from app.rules import SecretPatterns, load_catalogue

log = logging.getLogger(__name__)

RUST = Language(tree_sitter_rust.language())

_TYPE_ITEMS = {"struct_item": "struct", "enum_item": "enum", "union_item": "union", "trait_item": "trait"}
_FN_ITEMS = ("function_item", "function_signature_item")
_BRANCHES = {"if_expression", "while_expression", "for_expression", "match_arm"}
_SCOPES = {"closure_expression", "function_item", "impl_item", "mod_item", "trait_item"}
_PATH_NODES = {"identifier", "type_identifier", "crate", "self", "super", "metavariable"}
_COMMENTS = ("line_comment", "block_comment")
_LITERALS = {
    "integer_literal": "int", "float_literal": "float", "boolean_literal": "bool", "char_literal": "char",
    "string_literal": "str", "raw_string_literal": "str", "array_expression": "array",
}
_PATTERN_OWNERS = {"let_declaration", "parameter", "for_expression", "match_arm", "let_condition"}

# Attributes that say nothing about how a fn is reached; anything else (#[test], #[tokio::main],
# #[no_mangle], proc-macro attributes...) marks it as an entry point, like a Python decorator.
_NON_ENTRY_ATTRS = {
    "inline", "must_use", "allow", "warn", "deny", "forbid", "expect", "doc", "cfg", "cfg_attr",
    "deprecated", "track_caller", "cold",
}
_MAIN_ATTRS = {"tokio::main", "actix_web::main", "async_std::main", "rocket::main", "launch", "ntex::main",
               "actix_rt::main", "smol_potat::main", "async_main"}
_HANDLER_ATTRS = {"get", "post", "put", "patch", "delete", "head", "options", "trace", "connect", "route",
                  "routes", "handler", "debug_handler"}
_TEST_ATTRS = {"test", "bench", "rstest", "quickcheck", "proptest", "test_case"}

# Macros that ship with std; an unqualified invocation of one of these is `std::<name>!`.
_STD_MACROS = {
    "assert", "assert_eq", "assert_ne", "cfg", "column", "compile_error", "concat", "dbg",
    "debug_assert", "debug_assert_eq", "debug_assert_ne", "env", "eprint", "eprintln", "file",
    "format", "format_args", "include", "include_bytes", "include_str", "line", "matches",
    "module_path", "option_env", "panic", "print", "println", "stringify", "thread_local", "todo",
    "unimplemented", "unreachable", "vec", "write", "writeln",
}
# Macros whose arguments are ordinary expressions, so re-parsing them finds the calls inside.
# Matched on the last path segment, so `log::info!` and `tracing::info!` both qualify.
_EXPR_MACROS = {
    "assert", "assert_eq", "assert_ne", "dbg", "debug_assert", "debug_assert_eq", "debug_assert_ne",
    "eprint", "eprintln", "format", "format_args", "panic", "print", "println", "todo",
    "unimplemented", "unreachable", "vec", "write", "writeln",
    "trace", "debug", "info", "warn", "error", "event",          # log / tracing
    "anyhow", "bail", "ensure", "eyre",                          # anyhow / eyre
    "routes",                                                    # rocket: routes![a, b]
}
# Prelude names that are called unqualified. Constructors (Some, Ok, Err) are deliberately absent.
_PRELUDE_FNS = {"drop": "std::mem::drop"}
_PRELUDE_TYPES = {
    "Box": "std::boxed::Box", "Option": "std::option::Option", "Result": "std::result::Result",
    "String": "std::string::String", "Vec": "std::vec::Vec",
    "Send": "std::marker::Send", "Sync": "std::marker::Sync",
}
UNKNOWN_RECEIVER = "?"
_BUILTIN_ROOTS = {"std", "core", "alloc", "crate", "self", "super", "Self"}

_SAFETY = re.compile(r"safety", re.IGNORECASE)
# A bound name or a comparison that suggests the recursion depth is limited. Whole words only:
# `LengthDelimited` must not count as "limit", nor `bytes_remaining` as a budget.
_DEPTH_GUARD = re.compile(r"(?i)(?<![a-z])(depth|nest(ed|ing)?|recursion|recurs(e|ive)|budget|fuel|max_depth)(?![a-z])")
_COMPARISONS = {"<", ">", "<=", ">=", "==", "!="}
_ARITH = {"+", "-", "*", "<<", "+=", "-=", "*=", "<<="}


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


def _attributes(item: Node) -> list[tuple[str, str]]:
    """(name, arguments) of the attributes directly above an item, e.g. ("cfg", "test")."""
    found = []
    node = item.prev_sibling
    while node is not None and node.type in ("attribute_item", *_COMMENTS):
        if node.type == "attribute_item":
            attr = next((c for c in node.named_children if c.type == "attribute"), None)
            path = attr.named_children[0] if attr is not None and attr.named_children else None
            args = attr.child_by_field_name("arguments") if attr is not None else None
            found.append((_text(path) if path is not None else "", _text(args)[1:-1] if args is not None else ""))
        node = node.prev_sibling
    return found


def _entry_attribute_count(attrs: list[tuple[str, str]]) -> int:
    """How many attributes mark the item as an entry point (the `decorators` metric)."""
    return sum(1 for name, _ in attrs
               if name not in _NON_ENTRY_ATTRS and not name.startswith(("rustfmt::", "clippy::")))


def _loc(node: Node) -> int:
    return node.end_point[0] - node.start_point[0] + 1


def _has_modifier(node: Node, keyword: str) -> bool:
    mods = next((c for c in node.children if c.type == "function_modifiers"), None)
    return any(c.type == keyword for c in (mods.children if mods is not None else node.children))


def _abi(node: Node) -> str | None:
    """`extern "C"` -> "C"; bare `extern` -> "C"; None when the item has no extern modifier."""
    mods = next((c for c in node.children if c.type == "function_modifiers"), node)
    ext = next((c for c in mods.children if c.type == "extern_modifier"), None)
    if ext is None:
        return None
    lit = next((c for c in ext.named_children if c.type == "string_literal"), None)
    return _text(lit).strip('"') if lit is not None else "C"


def _visibility(node: Node) -> str:
    vis = next((c for c in node.children if c.type == "visibility_modifier"), None)
    if vis is None:
        return "private"
    text = _text(vis)
    return "pub" if text == "pub" else "pub(crate)"


def _string_value(node: Node) -> str:
    """The content of a string literal without quotes, prefixes (`b`, `r#`) or escapes resolved."""
    text = _text(node)
    start = text.find('"')
    end = text.rfind('"')
    return text[start + 1:end] if 0 <= start < end else ""


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _has_identifier(node: Node) -> bool:
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("identifier", "field_expression", "call_expression", "scoped_identifier"):
            return True
        stack.extend(n.named_children)
    return False


def _contains_type(node: Node, type_name: str) -> bool:
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == type_name:
            return True
        stack.extend(n.named_children)
    return False


def _identifiers_under(node: Node) -> list[str]:
    """Names bound by a pattern: plain identifiers, not the segments of enum/struct paths."""
    out, stack = [], [node]
    while stack:
        n = stack.pop()
        if n.type == "identifier":
            out.append(_text(n))
        elif n.type not in ("scoped_identifier", "scoped_type_identifier", "generic_type"):
            stack.extend(n.named_children)
    return out


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


def is_test_path(rel_path: str) -> bool:
    parts = rel_path.split("/")
    return "tests" in parts[:-1] or "benches" in parts[:-1]


@dataclass
class _Container:
    kind: str                  # "module" | "impl" | "trait impl" | "trait" | "fn" | "foreign"
    symbol: str | None         # qualified name of the enclosing symbol node, if there is one
    visibility: str = "private"
    abi: str | None = None


@dataclass
class _Fn:
    qname: str
    symbol: ParsedSymbol
    bound: set[str] = field(default_factory=set)    # locals and params, so they are not taken for fn refs
    depth_guard: bool = False


class _Walker:
    def __init__(self, parsed: ParsedFile, crate: str, lines: list[str], secrets: SecretPatterns | None):
        self.parsed = parsed
        self.crate = crate
        self.lines = lines
        self.modules: list[str] = [parsed.module]      # innermost module path (inline `mod` aware)
        self.scope: list[str] = [parsed.module]        # qualified-name prefix for new symbols
        self.containers: list[_Container] = [_Container("module", None)]
        self.functions: list[str] = []                  # enclosing fns, innermost last
        self.fn_stack: list[_Fn] = []
        self.self_type: list[str] = []                  # what `Self` means inside the current impl
        self.aliases: dict[str, str] = {}               # name brought in by `use` -> dotted path
        self.local_types: set[str] = set()
        self.local_type_vis: dict[str, str] = {}
        self.impl_counts: dict[str, int] = {}
        self.seen: set[str] = set()
        self.local_mods: set[str] = set()               # names of `mod x;` / `mod x { }` in this file
        self.local_macros: set[str] = set()             # `macro_rules!` names defined in this file
        self.line_offset = 0                            # rows to add while walking a re-parsed macro
        self.unsafe_depth = 0
        self.test_depth = 0
        self._snippet_parser: Parser | None = None
        self.secret_identifiers = [re.compile(p) for p in secrets.identifiers] if secrets else []
        self.secret_formats = [(n, re.compile(p)) for n, p in secrets.formats.items()] if secrets else []
        self.counts: Counter[str] = Counter()

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
                qname = f"{self.modules[-1]}.{_text(name)}"
                self.local_types.add(qname)
                self.local_type_vis[qname] = _visibility(child)
            elif child.type == "use_declaration" and (arg := child.child_by_field_name("argument")):
                for segs, name in self._use_leaves(arg, []):
                    if name is not None and name != "_":
                        self.aliases[name] = self._rewrite(segs, aliases=False)[0]
            elif child.type == "impl_item" and (segs := _segments(child.child_by_field_name("type"))):
                body = child.child_by_field_name("body")
                fns = sum(c.type == "function_item" for c in body.named_children) if body else 0
                key = f"{self.modules[-1]}.{segs[-1]}"
                self.impl_counts[key] = self.impl_counts.get(key, 0) + fns
            elif child.type == "macro_definition" and (name := child.child_by_field_name("name")):
                self.local_macros.add(_text(name))
            if child.type == "mod_item" and (name := child.child_by_field_name("name")) is not None:
                self.local_mods.add(_text(name))
            if child.type == "mod_item" and (body := child.child_by_field_name("body")) is not None:
                self.modules.append(f"{self.modules[-1]}.{_text(child.child_by_field_name('name'))}")
                self.prescan(body)
                self.modules.pop()

    # -- pass 2: symbols, imports, calls ---------------------------------------------------
    def visit(self, node: Node) -> None:
        if self.fn_stack:
            self._note_bindings(node)
        handler = getattr(self, f"_visit_{node.type}", None)
        if handler is not None:
            handler(node)
        else:
            for child in node.children:
                self.visit(child)

    def _note_bindings(self, node: Node) -> None:
        """Track names bound in the current fn (params, lets, patterns) and depth-guard hints."""
        fn = self.fn_stack[-1]
        if node.type in _PATTERN_OWNERS:
            pattern = node.child_by_field_name("pattern")
            if pattern is not None:
                names = _identifiers_under(pattern)
                fn.bound.update(names)
                if not fn.depth_guard and any(_DEPTH_GUARD.search(n) for n in names):
                    fn.depth_guard = True
        elif node.type == "closure_parameters":
            fn.bound.update(_identifiers_under(node))
        elif node.type == "binary_expression" and not fn.depth_guard:
            op = node.child_by_field_name("operator")
            if op is not None and op.type in _COMPARISONS and _DEPTH_GUARD.search(_text(node)):
                fn.depth_guard = True

    @property
    def in_test(self) -> bool:
        return self.parsed.in_test or self.test_depth > 0

    @property
    def in_unsafe(self) -> bool:
        return self.unsafe_depth > 0

    def _unique(self, qname: str) -> str:
        candidate, n = qname, 1
        while candidate in self.seen:
            n += 1
            candidate = f"{qname}~{n}"
        self.seen.add(candidate)
        return candidate

    def _symbol(self, node: Node, kind: str, subkind: str, qname: str, parent: str | None,
                metrics: dict[str, int], attrs: dict | None = None) -> ParsedSymbol:
        name = node.child_by_field_name("name")
        sym = ParsedSymbol(
            kind=kind, name=_text(name) if name is not None else "?", qualified_name=qname,
            line_start=self._line(node), line_end=node.end_point[0] + 1 + self.line_offset,
            parent=parent, metrics=metrics, subkind=subkind, attrs=attrs or {},
            name_line=self._line(name) if name is not None else 0,
            name_col=name.start_point[1] if name is not None else 0,
        )
        self.parsed.symbols.append(sym)
        return sym

    def _visit_use_declaration(self, node: Node) -> None:
        arg = node.child_by_field_name("argument")
        if arg is None:
            return
        for segs, _ in self._use_leaves(arg, []):
            if not segs:
                continue
            path, anchored = self._rewrite(segs, aliases=False)
            if not anchored:
                self._note_extern(segs[0])
            candidates = [path, path.rpartition(".")[0]]
            if not anchored:
                # 2018 "uniform paths": `use a::X` may name a child module of the current one.
                local = f"{self.modules[-1]}.{path}"
                candidates += [local, local.rpartition(".")[0]]
            # The builder keeps whichever candidate is a real file; external crates drop out.
            self.parsed.imports.extend(c for c in candidates if c and c not in self.parsed.imports)

    def _note_extern(self, head: str) -> None:
        if head not in _BUILTIN_ROOTS and head not in self.local_mods and head not in self.parsed.extern_crates:
            self.parsed.extern_crates.append(head)

    def _visit_extern_crate_declaration(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        if name is not None:
            self._note_extern(_text(name))

    def _visit_mod_item(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        if body is None:                                         # `mod foo;` declares a file
            return
        is_test = any(name == "cfg" and "test" in args for name, args in _attributes(node))
        path = f"{self.modules[-1]}.{_text(node.child_by_field_name('name'))}"
        self.modules.append(path)
        self.scope.append(path)
        self.containers.append(_Container("module", None))
        self.test_depth += is_test
        self.visit(body)
        self.test_depth -= is_test
        self.containers.pop()
        self.scope.pop()
        self.modules.pop()

    def _visit_foreign_mod_item(self, node: Node) -> None:
        """`extern "C" { fn ...; }`: declarations of foreign functions, part of the FFI surface."""
        body = node.child_by_field_name("body")
        if body is None:
            return
        self.containers.append(_Container("foreign", None, abi=_abi(node) or "C"))
        self.visit(body)
        self.containers.pop()

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
        visibility = _visibility(node)
        attrs: dict = {"visibility": visibility}
        if self.in_test:
            attrs["in_test"] = True
        derives = [args for name_, args in _attributes(node) if name_ == "derive"]
        if derives:
            attrs["derives"] = sorted({d.strip() for d in ",".join(derives).split(",") if d.strip()})
        self._symbol(node, "class", subkind, qname, self.containers[-1].symbol, metrics, attrs)

        if subkind == "trait" and any(c.type == "unsafe" for c in node.children):
            self._unsafe(node, "trait", container=None, owner_type=qname, trait=_text(name))

        if subkind != "trait":
            return
        bounds = node.child_by_field_name("bounds")
        for bound in bounds.named_children if bounds is not None else []:
            if segs := _segments(bound):
                self.parsed.inherits.append((qname, self._rewrite(segs)[0]))
        if body is not None:
            self.scope.append(qname)
            self.containers.append(_Container("trait", qname, visibility=visibility))
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
        is_unsafe = any(c.type == "unsafe" for c in node.children)

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
            self.parsed.implements.append(ParsedImpl(
                scope=scope, type=type_ref, trait=self._rewrite(trait_segs)[0], is_unsafe=is_unsafe,
                line=self._line(node), trait_external=self._external_path(trait_segs),
            ))
        if is_unsafe:
            self._unsafe(node, "impl", container=None, owner_type=local,
                         trait=trait_segs[-1] if trait_segs else None,
                         target_type=type_segs[-1] if type_segs else None)

        if body is None:
            return
        # Methods of a trait impl are as visible as the type; unknown types are assumed pub.
        visibility = self.local_type_vis.get(local, "pub") if trait_node is not None else "private"
        self.scope.append(f"{base}.<{trait_segs[-1]}>" if trait_segs else base)
        self.containers.append(_Container("trait impl" if trait_node is not None else "impl", local,
                                          visibility=visibility))
        if self_path:
            self.self_type.append(self_path)
        self.visit(body)
        if self_path:
            self.self_type.pop()
        self.containers.pop()
        self.scope.pop()

    # -- functions --------------------------------------------------------------------------
    def _params(self, node: Node) -> tuple[list[dict], int]:
        """(params as JSON-able dicts, raw-pointer parameter count)."""
        params_node = node.child_by_field_name("parameters")
        out: list[dict] = []
        raw = 0
        if params_node is None:
            return out, raw
        for child in params_node.named_children:
            if child.type == "self_parameter":
                out.append({"index": len(out), "name": "self", "type": _text(child)})
            elif child.type == "parameter":
                pattern = child.child_by_field_name("pattern")
                typ = child.child_by_field_name("type")
                entry: dict = {"index": len(out), "name": _text(pattern).removeprefix("mut ").strip() if pattern else "_",
                               "type": _text(typ)[:80] if typ is not None else "_"}
                if typ is not None:
                    if _contains_type(typ, "pointer_type"):
                        raw += 1
                        entry["raw_pointer"] = True
                    if (segs := _segments(typ)) and (path := self._external_path(segs)):
                        entry["path"] = path
                out.append(entry)
            elif child.type == "variadic_parameter":
                out.append({"index": len(out), "name": "...", "type": "..."})
        return out, raw

    def _fn_item(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        if name is None:
            return
        container = self.containers[-1]
        subkind = {"impl": "method", "trait impl": "trait impl fn", "trait": "trait fn",
                   "foreign": "foreign fn"}.get(container.kind, "fn")
        qname = self._unique(f"{self.scope[-1]}.{_text(name)}")
        attrs_list = _attributes(node)
        attr_names = {n for n, _ in attrs_list}
        is_test = bool(attr_names & _TEST_ATTRS) or any(n.endswith("::test") for n in attr_names)
        is_unsafe = _has_modifier(node, "unsafe") or container.kind == "foreign"
        abi = container.abi if container.kind == "foreign" else _abi(node)
        no_mangle = "no_mangle" in attr_names or "export_name" in attr_names or \
            any(n == "unsafe" and "no_mangle" in a for n, a in attrs_list)
        visibility = container.visibility if container.kind in ("trait", "trait impl") else _visibility(node)
        params, raw_pointers = self._params(node)

        attrs: dict = {"visibility": visibility, "params": json.dumps(params, separators=(",", ":"))}
        if is_unsafe:
            attrs["is_unsafe"] = True
        if _has_modifier(node, "async"):
            attrs["is_async"] = True
        if abi is not None:
            attrs["abi"] = abi
        if no_mangle:
            attrs["no_mangle"] = True
        in_test = self.in_test or is_test
        if in_test:
            attrs["in_test"] = True
        entry = self._entry_kind(_text(name), attr_names, is_test, abi, no_mangle, container)
        if entry:
            attrs["entry_kind"] = entry
        metrics = {
            "complexity": _complexity(node),
            "loc": _loc(node),
            "parameters": len(params),
            "decorators": _entry_attribute_count(attrs_list),
        }
        if raw_pointers:
            metrics["raw_pointer_params"] = raw_pointers
        sym = self._symbol(node, "function", subkind, qname, container.symbol, metrics, attrs)

        if container.kind == "foreign":
            self.counts["foreign_fns"] += 1
        elif is_unsafe:
            self.counts["unsafe_fns"] += 1
            self.counts["unsafe_lines"] += _loc(node)
            self._unsafe(node, "fn", container=qname, in_test=in_test)

        body = node.child_by_field_name("body")
        if body is None:
            return
        self.scope.append(qname)
        self.containers.append(_Container("fn", qname))
        self.functions.append(qname)
        fn = _Fn(qname, sym, bound={p["name"] for p in params})
        fn.depth_guard = any(_DEPTH_GUARD.search(p["name"]) for p in params)
        self.fn_stack.append(fn)
        self.test_depth += is_test
        self.unsafe_depth += is_unsafe
        self.visit(body)
        self.unsafe_depth -= is_unsafe
        self.test_depth -= is_test
        self.fn_stack.pop()
        if fn.depth_guard:
            sym.attrs["depth_guard"] = True
        self.functions.pop()
        self.containers.pop()
        self.scope.pop()

    _visit_function_item = _visit_function_signature_item = _fn_item

    def _entry_kind(self, name: str, attrs: set[str], is_test: bool, abi: str | None, no_mangle: bool,
                    container: _Container) -> str | None:
        if is_test or self.in_test:
            return "test"
        if container.kind == "foreign":
            return None
        if attrs & _MAIN_ATTRS or any(a.endswith("::main") for a in attrs):
            return "main"
        if name == "main" and container.kind == "module" and self.modules[-1] == self.parsed.module:
            return "main"
        if abi is not None or no_mangle:
            return "ffi"
        if any(a.rsplit("::", 1)[-1] in _HANDLER_ATTRS for a in attrs):
            return "handler"
        return None                                              # pub_api and handler-by-use: builder

    # -- unsafe -----------------------------------------------------------------------------
    def _has_safety_comment(self, row: int, col: int) -> bool:
        """A `SAFETY:` style comment on the lines directly above `row`, or after the keyword on it."""
        if 0 <= row < len(self.lines) and _SAFETY.search(self.lines[row][col:]):
            after = self.lines[row][col:]
            if "//" in after or "/*" in after:
                return True
        r = row - 1
        while r >= 0:
            line = self.lines[r].strip()
            if not line or line.startswith("#["):
                r -= 1
                continue
            if line.startswith(("//", "/*", "*")) or line.endswith("*/"):
                if _SAFETY.search(line):
                    return True
                r -= 1
                continue
            return False
        return False

    def _unsafe(self, node: Node, kind: str, container: str | None, in_test: bool | None = None,
                owner_type: str | None = None, trait: str | None = None, target_type: str | None = None) -> None:
        row, col = node.start_point
        self.parsed.unsafes.append(ParsedUnsafe(
            kind=kind, line_start=row + 1 + self.line_offset, line_end=node.end_point[0] + 1 + self.line_offset,
            col=col, has_safety_comment=self._has_safety_comment(row, col), container=container,
            in_test=self.in_test if in_test is None else in_test, owner_type=owner_type, trait=trait,
            target_type=target_type,
        ))
        if kind == "impl":
            self.counts["unsafe_impls"] += 1
        elif kind == "trait":
            self.counts["unsafe_traits"] += 1

    def _visit_unsafe_block(self, node: Node) -> None:
        self.counts["unsafe_blocks"] += 1
        self.counts["unsafe_lines"] += _loc(node)
        self._unsafe(node, "block", container=self.functions[-1] if self.functions else None)
        self.unsafe_depth += 1
        for child in node.children:
            self.visit(child)
        self.unsafe_depth -= 1

    # -- calls ---------------------------------------------------------------------------
    def _line(self, node: Node) -> int:
        return node.start_point[0] + 1 + self.line_offset

    def _is_internal(self, dotted: str, segs: list[str], anchored: bool) -> bool:
        """True for paths into this crate; when those fail to resolve there is nothing external."""
        if dotted == self.crate or dotted.startswith(self.crate + "."):
            return True
        if anchored:
            return False
        head = segs[0]
        return head in self.local_mods or f"{self.modules[-1]}.{head}" in self.local_types

    def _external_path(self, segs: list[str]) -> str | None:
        dotted, anchored = self._rewrite(segs)
        if self._is_internal(dotted, segs, anchored):
            return None
        parts = dotted.split(".")
        if not anchored:
            if len(parts) == 1:
                return _PRELUDE_FNS.get(parts[0]) or _PRELUDE_TYPES.get(parts[0])   # locals, globs: unknown
            if parts[0] in _PRELUDE_TYPES:
                parts = [_PRELUDE_TYPES[parts[0]], *parts[1:]]
        return "::".join(parts)

    def _certainly_external(self, segs: list[str], external: str | None) -> bool:
        """The path leaves the project for sure: std/core/alloc, a prelude name, a `use`d external
        crate, or an unanchored lowercase head that is no module of this file (a dependency crate).
        An unknown capitalised head may come from a glob import, so it stays resolvable."""
        if external is None or external.startswith(UNKNOWN_RECEIVER):
            return False
        head = segs[0]
        if head in ("std", "core", "alloc") or head in _PRELUDE_TYPES or head in _PRELUDE_FNS:
            return True
        if head in self.aliases:
            target = self.aliases[head].split(".")[0]
            return target != self.crate and target not in self.local_mods
        return len(segs) > 1 and head[:1].islower() and head not in self.local_mods

    def _literal_args(self, arguments: Node | None) -> tuple[tuple[int, str, str], ...]:
        if arguments is None:
            return ()
        out = []
        index = 0
        for arg in arguments.named_children:
            if arg.type in _COMMENTS:
                continue
            kind = _LITERALS.get(arg.type)
            if arg.type == "unary_expression" and arg.named_children and arg.named_children[0].type in (
                    "integer_literal", "float_literal"):
                kind = _LITERALS[arg.named_children[0].type]
            if kind is not None:
                text = _string_value(arg)[:24] if kind == "str" else _text(arg)[:24]
                out.append((index, kind, text))
            index += 1
        return tuple(out)

    def _record_refs(self, arguments: Node | None, via: str) -> None:
        """Arguments that are bare function/item paths: `spawn(worker)`, `get(handler)`."""
        if arguments is None or not self.functions:
            return
        bound = self.fn_stack[-1].bound if self.fn_stack else set()
        for arg in arguments.named_children:
            node = arg
            while node.type == "reference_expression" and (inner := node.child_by_field_name("value")) is not None:
                node = inner
            segs = _segments(node)
            if not segs or node.type == "type_identifier":
                continue
            if len(segs) == 1 and (segs[0] in bound or not segs[0][:1].islower()):
                continue                                          # a local, or a constructor/type
            external = self._external_path(segs)
            self.parsed.refs.append(ParsedRef(self.functions[-1], self._rewrite(segs)[0], self._line(arg),
                                              external, via, resolvable=not self._certainly_external(segs, external)))

    def _visit_call_expression(self, node: Node) -> None:
        func = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if self.functions and func is not None:
            callee: str | None = None
            external: str | None = None
            via = ""
            resolvable = True
            anchor = func                       # where the call "is": the method name for chained calls
            if func.type == "field_expression":
                value, fld = func.child_by_field_name("value"), func.child_by_field_name("field")
                if fld is not None:
                    # Receiver types are unknown; "_." keeps the builder from guessing a sibling.
                    receiver = "self" if value is not None and value.type == "self" else "_"
                    callee = f"{receiver}.{_text(fld)}"
                    external = f"{UNKNOWN_RECEIVER}::{_text(fld)}"
                    via = _text(fld)
                    anchor = fld
            elif segs := _segments(func):
                callee = self._rewrite(segs)[0]
                external = self._external_path(segs)
                via = segs[-1]
                resolvable = not self._certainly_external(segs, external)
            if callee:
                self.parsed.calls.append(ParsedCall(
                    self.functions[-1], callee, self._line(anchor), external, col=anchor.start_point[1],
                    in_unsafe=self.in_unsafe, literal_args=self._literal_args(arguments), resolvable=resolvable,
                ))
                self._record_refs(arguments, via)
        for child in node.children:
            self.visit(child)

    def _visit_macro_invocation(self, node: Node) -> None:
        segs = _segments(node.child_by_field_name("macro"))
        if not segs:
            return
        name = segs[-1]
        if self.functions:
            external: str | None
            if len(segs) == 1 and name in self.local_macros:
                external = None
            elif len(segs) == 1 and name in _STD_MACROS and name not in self.aliases:
                external = f"std::{name}!"
            else:
                dotted = self._rewrite(segs)[0]
                internal = dotted == self.crate or dotted.startswith(self.crate + ".")
                external = None if internal else "::".join(dotted.split(".")) + "!"
            if external:
                # A callee ending in "!" never matches a project symbol, so it always goes external.
                self.parsed.calls.append(ParsedCall(self.functions[-1], f"{name}!", self._line(node),
                                                    external, is_macro=True, col=node.start_point[1],
                                                    in_unsafe=self.in_unsafe))
        if name in _EXPR_MACROS:
            tree = next((c for c in node.children if c.type == "token_tree"), None)
            if tree is not None:
                self._visit_macro_arguments(tree, f"{name}!")

    def _visit_macro_arguments(self, tree: Node, via: str) -> None:
        """Parse `name!(a, b(c))` arguments as `__f(a, b(c))` (or `[a; n]` for `vec!`) and walk them."""
        inner = _text(tree)[1:-1]
        if self._snippet_parser is None:
            self._snippet_parser = Parser(RUST)
        target = None
        for prefix, suffix in (("fn __m(){__f(", ");}"), ("fn __m(){[", "];}")):
            root = self._snippet_parser.parse(f"{prefix}{inner}{suffix}".encode()).root_node
            target = _snippet_expression(root)
            if target is not None and not root.has_error:
                break
        if target is None:
            return
        # The prefix sits on the token tree's first row, so snippet rows map 1:1 onto file rows.
        saved = self.line_offset
        self.line_offset += tree.start_point[0]
        if target.type == "arguments":
            self._record_refs(target, via)
        for child in target.children:
            self.visit(child)
        self.line_offset = saved

    # -- operations: index and arithmetic -------------------------------------------------
    def _visit_index_expression(self, node: Node) -> None:
        if self.functions and len(node.named_children) >= 2:
            index = node.named_children[-1]
            if _has_identifier(index):
                self.parsed.ops.append(ParsedOp(self.functions[-1], "index", self._line(node), node.start_point[1],
                                                self.in_unsafe, _text(index)[:40]))
        for child in node.children:
            self.visit(child)

    def _arith(self, node: Node) -> None:
        op = node.child_by_field_name("operator")
        if self.functions and self.in_unsafe and op is not None and op.type in _ARITH:
            self.parsed.ops.append(ParsedOp(self.functions[-1], "arith", self._line(node), node.start_point[1],
                                            True, op.type))
        for child in node.children:
            self.visit(child)

    _visit_binary_expression = _visit_compound_assignment_expr = _arith

    # -- string literals ---------------------------------------------------------------------
    def _binding_for(self, node: Node) -> str | None:
        """The name a literal is bound to or passed to: let/const/static/field/assignment/method."""
        n = node
        for _ in range(6):
            p = n.parent
            if p is None:
                return None
            if p.type in ("arguments", "reference_expression", "parenthesized_expression", "type_cast_expression"):
                n = p
                continue
            if p.type == "field_expression" and p.child_by_field_name("value") == n:
                n = p                                            # `"lit".to_string()`: keep climbing
                continue
            if p.type == "call_expression":
                func = p.child_by_field_name("function")
                if func is None:
                    return None
                if func.type == "field_expression" and n.type == "arguments":
                    fld = func.child_by_field_name("field")
                    name = _text(fld) if fld is not None else ""
                    return name if self._secret_like(name) else None
                n = p                                            # Some("x"), String::from("x"), Secret::new("x")
                continue
            if p.type == "let_declaration":
                pattern = p.child_by_field_name("pattern")
                return _text(pattern).removeprefix("mut ").strip() if pattern is not None else None
            if p.type in ("const_item", "static_item"):
                name = p.child_by_field_name("name")
                return _text(name) if name is not None else None
            if p.type == "field_initializer":
                fld = p.child_by_field_name("field")
                return _text(fld) if fld is not None else None
            if p.type == "assignment_expression" and p.child_by_field_name("right") == n:
                left = p.child_by_field_name("left")
                if left is None:
                    return None
                fld = left.child_by_field_name("field") if left.type == "field_expression" else None
                return _text(fld) if fld is not None else _text(left).rsplit(".", 1)[-1]
            return None
        return None

    def _secret_like(self, name: str) -> bool:
        return bool(name) and any(rx.search(name) for rx in self.secret_identifiers)

    def _visit_string_literal(self, node: Node) -> None:
        if not self.secret_identifiers and not self.secret_formats:
            return
        value = _string_value(node)
        if not value:
            return
        binding = self._binding_for(node)
        pattern = next((name for name, rx in self.secret_formats if rx.search(value)), None)
        if pattern is None and not self._secret_like(binding or ""):
            return
        self.parsed.literals.append(ParsedLiteral(
            container=self.functions[-1] if self.functions else None,
            line=self._line(node), col=node.start_point[1],
            preview=(value[:4] + "…") if len(value) > 4 else "*" * len(value),
            sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
            entropy=round(_entropy(value), 3), length=len(value),
            binding=binding, pattern=pattern, in_test=self.in_test,
        ))

    _visit_raw_string_literal = _visit_string_literal


def _snippet_expression(root: Node) -> Node | None:
    """The argument list (or array) inside a `fn __m(){ ... }` snippet built from a macro call."""
    fn = next((c for c in root.named_children if c.type == "function_item"), None)
    body = fn.child_by_field_name("body") if fn is not None else None
    stmt = body.named_children[0] if body is not None and body.named_children else None
    expr = stmt.named_children[0] if stmt is not None and stmt.type == "expression_statement" and \
        stmt.named_children else stmt
    if expr is None:
        return None
    if expr.type == "call_expression":
        return expr.child_by_field_name("arguments")
    return expr if expr.type == "array_expression" else None


class RustParser:
    language = "rust"
    extensions = (".rs",)

    def __init__(self, secrets: SecretPatterns | None = None) -> None:
        self._parser = Parser(RUST)
        self._secrets = secrets if secrets is not None else load_catalogue().secrets

    def parse(self, rel_path: str, source: str) -> ParsedFile:
        tree = self._parser.parse(source.encode("utf-8"))
        if tree.root_node.has_error:
            log.warning("%s: syntax errors, graph may be incomplete", rel_path)
        module, crate = module_names(rel_path)
        parsed = ParsedFile(path=rel_path, module=module, language=self.language,
                            loc=source.count("\n") + 1, crate=crate, in_test=is_test_path(rel_path))
        walker = _Walker(parsed, crate, source.splitlines(), self._secrets)
        walker.prescan(tree.root_node)
        walker.visit(tree.root_node)
        parsed.metrics = {k: walker.counts.get(k, 0) for k in
                          ("unsafe_blocks", "unsafe_fns", "unsafe_impls", "unsafe_traits", "unsafe_lines", "foreign_fns")}
        parsed.metrics["unsafe_density"] = round(parsed.metrics["unsafe_lines"] / parsed.loc, 4) if parsed.loc else 0.0
        return parsed
