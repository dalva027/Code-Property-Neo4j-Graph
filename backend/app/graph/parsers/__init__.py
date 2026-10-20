from pathlib import Path

from app.graph.parsers.base import LanguageParser, ParsedFile, ParsedSymbol
from app.graph.parsers.python import PythonParser

# Register additional languages here (e.g. a tree-sitter based TypeScript parser).
PARSERS: list[LanguageParser] = [PythonParser()]

_BY_EXTENSION: dict[str, LanguageParser] = {ext: p for p in PARSERS for ext in p.extensions}


def parser_for(path: Path) -> LanguageParser | None:
    return _BY_EXTENSION.get(path.suffix.lower())


__all__ = ["LanguageParser", "ParsedFile", "ParsedSymbol", "PARSERS", "parser_for"]
