"""Language-agnostic parse output. Each language parser produces ParsedFile; the builder
turns a list of them into a CodeGraph. Adding a language = implementing LanguageParser.

Beyond symbols, imports and calls, a parser may report security facts (all optional, Rust fills
them in): unsafe spans, functions passed as values, index/arithmetic operations, and string
literals that look like secrets. The builder turns those into Unsafe, Call and Literal nodes.
"""
from dataclasses import dataclass, field
from typing import Protocol

from app.models.graph import AttrValue


@dataclass
class ParsedSymbol:
    kind: str                       # "class" | "function"
    name: str
    qualified_name: str             # e.g. "pkg.module.Class.method"
    line_start: int
    line_end: int
    parent: str | None              # qualified name of the enclosing symbol; None = top level
    metrics: dict[str, int] = field(default_factory=dict)
    subkind: str | None = None      # language-specific flavour, e.g. "struct", "trait", "method"
    # Non-numeric facts: visibility, is_unsafe, is_async, abi, entry_kind, in_test, params (JSON)...
    attrs: dict[str, AttrValue] = field(default_factory=dict)


@dataclass(frozen=True)
class ParsedCall:
    caller: str                     # qualified name of the calling function
    callee: str                     # reference as written, rewritten to dotted form for resolution
    line: int = 0
    # Where the call goes when it does not resolve to a project symbol, as a `::` path
    # ("std::mem::transmute", "?::unwrap" for an unknown receiver, "println!" for a macro).
    # None means an unresolved call is dropped, which is what Python does.
    external: str | None = None
    is_macro: bool = False
    col: int = 0
    in_unsafe: bool = False
    # Literal arguments as (0-based index, kind, text): kind is int, float, bool, str, char or array.
    literal_args: tuple[tuple[int, str, str], ...] = ()
    # False when the path certainly leaves the project (`std::`, a dependency crate, a prelude
    # type), so the builder must not resolve it to a project symbol by name.
    resolvable: bool = True


@dataclass(frozen=True)
class ParsedRef:
    """A function or item path passed as a value: `get(handler)`, `thread::spawn(worker)`."""
    caller: str
    ref: str                        # dotted, for resolution against project symbols
    line: int
    external: str | None            # `::` path when it is not a project item
    via: str                        # the callee that received the value: "get", "spawn", "routes!"
    resolvable: bool = True


@dataclass(frozen=True)
class ParsedUnsafe:
    kind: str                       # "block" | "fn" | "impl" | "trait"
    line_start: int
    line_end: int
    col: int
    has_safety_comment: bool
    container: str | None           # enclosing function (the fn itself for kind "fn"); None = file level
    in_test: bool
    owner_type: str | None = None   # impl/trait: the type's qualified name when it is local
    trait: str | None = None        # impl/trait: trait name as written (last segment)
    target_type: str | None = None  # impl: type as written (last segment)


@dataclass(frozen=True)
class ParsedOp:
    """An index or arithmetic operation worth a Call node: `v[i]`, `a + b` inside unsafe."""
    caller: str
    op: str                         # "index" | "arith"
    line: int
    col: int
    in_unsafe: bool
    detail: str                     # the index expression, or the operator


@dataclass(frozen=True)
class ParsedLiteral:
    """A string literal that is bound to a secret-like name or matches a secret format.

    The value never leaves the parser: only a redacted preview, a hash and its entropy do.
    """
    container: str | None
    line: int
    col: int
    preview: str
    sha256: str
    entropy: float
    length: int
    binding: str | None             # let/const/field/method name it was bound to or passed to
    pattern: str | None             # name of the matching secret format, if any
    in_test: bool


@dataclass(frozen=True)
class ParsedImpl:
    scope: str                      # resolution scope
    type: str                       # type as written; resolved by the builder (may be in another file)
    trait: str                      # trait as written
    is_unsafe: bool = False
    line: int = 0
    trait_external: str | None = None   # `::` path of the trait when it is not a project trait


@dataclass
class ParsedFile:
    path: str                       # relative to project root, posix separators
    module: str                     # dotted module name
    language: str
    loc: int
    crate: str = ""                 # dotted crate root the module belongs to (Rust)
    symbols: list[ParsedSymbol] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)                # dotted module names
    calls: list[ParsedCall] = field(default_factory=list)
    inherits: list[tuple[str, str]] = field(default_factory=list)   # (class qualified name, base as written)
    implements: list[ParsedImpl] = field(default_factory=list)
    # Names of external crates this file brings in by `use` or `extern crate` (Rust only), so a
    # dependency used only for derives or traits still counts as used.
    extern_crates: list[str] = field(default_factory=list)
    refs: list[ParsedRef] = field(default_factory=list)
    unsafes: list[ParsedUnsafe] = field(default_factory=list)
    ops: list[ParsedOp] = field(default_factory=list)
    literals: list[ParsedLiteral] = field(default_factory=list)
    metrics: dict[str, int | float] = field(default_factory=dict)   # unsafe_blocks, unsafe_density...
    in_test: bool = False           # the whole file is test code (e.g. under tests/)


class LanguageParser(Protocol):
    language: str
    extensions: tuple[str, ...]

    def parse(self, rel_path: str, source: str) -> ParsedFile: ...
