"""Language-agnostic parse output. Each language parser produces ParsedFile; the builder
turns a list of them into a CodeGraph. Adding a language = implementing LanguageParser."""
from dataclasses import dataclass, field
from typing import Protocol


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


@dataclass
class ParsedFile:
    path: str                       # relative to project root, posix separators
    module: str                     # dotted module name
    language: str
    loc: int
    symbols: list[ParsedSymbol] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)                # dotted module names
    calls: list[tuple[str, str]] = field(default_factory=list)      # (caller qualified name, callee as written)
    inherits: list[tuple[str, str]] = field(default_factory=list)   # (class qualified name, base as written)
    # (resolution scope, type as written, trait as written); both sides are resolved by the builder
    # because an impl may live in a different file from its type.
    implements: list[tuple[str, str, str]] = field(default_factory=list)


class LanguageParser(Protocol):
    language: str
    extensions: tuple[str, ...]

    def parse(self, rel_path: str, source: str) -> ParsedFile: ...
