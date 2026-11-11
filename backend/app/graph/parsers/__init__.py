from pathlib import Path

from app.graph.parsers.base import (
    LanguageParser,
    ParsedCall,
    ParsedFile,
    ParsedImpl,
    ParsedLiteral,
    ParsedOp,
    ParsedRef,
    ParsedSymbol,
    ParsedUnsafe,
)
from app.graph.parsers.python import PythonParser
from app.graph.parsers.rust import RustParser

# Register additional languages here.
PARSERS: list[LanguageParser] = [PythonParser(), RustParser()]

_BY_EXTENSION: dict[str, LanguageParser] = {ext: p for p in PARSERS for ext in p.extensions}


def parser_for(path: Path) -> LanguageParser | None:
    return _BY_EXTENSION.get(path.suffix.lower())


__all__ = ["PARSERS", "LanguageParser", "ParsedCall", "ParsedFile", "ParsedImpl", "ParsedLiteral", "ParsedOp",
           "ParsedRef", "ParsedSymbol", "ParsedUnsafe", "parser_for"]
