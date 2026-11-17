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
    # Where the name token sits (1-based line, 0-based byte column). Two parsers of the same file
    # agree on this even when they disagree on where the item starts (attributes, doc comments),
    # so it is the key that joins extractor facts onto a symbol. (0, 0) when unknown.
    name_line: int = 0
    name_col: int = 0


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
    # Set by the rust-analyzer extractor (app/graph/facts.py). `site` is the extractor's id of the
    # call site, which data-flow edges refer to; a call with a site always gets a Call node. `seq`
    # tells apart several sites at one position (calls made by one macro expansion). `attrs` are
    # typed facts for the Call node: ret_kind, recv_type, arg_count, in_macro. `aliases` are the
    # other paths the callee is known by, and `crate` the crate that defines it.
    site: int | None = None
    seq: int = 0
    attrs: tuple[tuple[str, AttrValue], ...] = ()
    aliases: tuple[str, ...] = ()
    crate: str | None = None


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
    site: int | None = None         # extractor site id, as on ParsedCall
    seq: int = 0
    attrs: tuple[tuple[str, AttrValue], ...] = ()   # base_kind for an index, ret_kind


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


@dataclass(frozen=True)
class ParsedVar:
    """A parameter, local or return value of a function, from the extractor's data-flow pass."""
    id: int                         # extractor id; flow edges refer to it
    function: str                   # qualified name of the owning function
    name: str
    kind: str                       # "param" | "local" | "ret"
    line: int
    col: int
    index: int | None = None        # parameter position, self included
    type: str | None = None         # as rust-analyzer displays it
    ty_kind: str = "unknown"        # int, bool, float, str, unit, other, ...
    type_path: str | None = None    # `::` path of the type's definition
    param_type: str | None = None   # for parameters: path of the declared parameter type
    guards: tuple[str, ...] = ()    # checks applied to it anywhere in the function


@dataclass(frozen=True)
class ParsedFlow:
    """A data-flow edge between two variables or call sites, by extractor id."""
    source: tuple[str, int]         # ("v", var id) or ("s", site id)
    target: tuple[str, int]
    kind: str                       # "flow" | "pass" | "ret"
    via: str                        # assign, arg:<i>, recv, macro, mut, out, match, for, closure, return, dispatch


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
    # Data flow (extractor only): variables of this file's functions, and the flow edges that
    # start in this file.
    vars: list[ParsedVar] = field(default_factory=list)
    flows: list[ParsedFlow] = field(default_factory=list)
    # (trait fn, impl fn) qualified names: a call resolved to the trait method may run the impl.
    dispatch: list[tuple[str, str]] = field(default_factory=list)


class LanguageParser(Protocol):
    language: str
    extensions: tuple[str, ...]

    def parse(self, rel_path: str, source: str) -> ParsedFile: ...
