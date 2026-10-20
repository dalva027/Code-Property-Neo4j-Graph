"""Python parser built on the standard-library `ast` module."""
import ast

from app.graph.parsers.base import ParsedFile, ParsedSymbol

_BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _dotted(node: ast.expr) -> str | None:
    """Render `a.b.c`-style expressions; None for anything more exotic."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return None


def _complexity(fn: ast.AST) -> int:
    """Cyclomatic complexity of one function body, not descending into nested scopes."""
    score = 1
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, _SCOPES):
            continue
        if isinstance(node, _BRANCHES):
            score += 1
        elif isinstance(node, ast.comprehension):
            score += 1 + len(node.ifs)
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        elif isinstance(node, ast.match_case):
            score += 1
        stack.extend(ast.iter_child_nodes(node))
    return score


class _Visitor(ast.NodeVisitor):
    def __init__(self, parsed: ParsedFile, is_package: bool):
        self.parsed = parsed
        self.scope: list[str] = [parsed.module]
        self.package = parsed.module if is_package else parsed.module.rpartition(".")[0]

    @property
    def current(self) -> str:
        return self.scope[-1]

    def _parent(self) -> str | None:
        return self.current if len(self.scope) > 1 else None

    # -- imports --------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.parsed.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        target = self._resolve_relative(node.module, node.level)
        if target:
            # `from pkg import x` may import a submodule; record both candidates and let the
            # builder keep whichever resolves to a real file.
            self.parsed.imports.append(target)
            self.parsed.imports.extend(f"{target}.{alias.name}" for alias in node.names)
        self.generic_visit(node)

    def _resolve_relative(self, module: str | None, level: int) -> str | None:
        if level == 0:
            return module
        parts = self.package.split(".") if self.package else []
        if level - 1 > len(parts):
            return None
        base = parts[: len(parts) - (level - 1)]
        if module:
            base.append(module)
        return ".".join(base) or None

    # -- definitions ----------------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qname = f"{self.current}.{node.name}"
        self.parsed.symbols.append(
            ParsedSymbol(
                kind="class",
                name=node.name,
                qualified_name=qname,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                parent=self._parent(),
                metrics={
                    "methods": sum(isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) for b in node.body),
                    "loc": (node.end_lineno or node.lineno) - node.lineno + 1,
                },
            )
        )
        for base in node.bases:
            if name := _dotted(base):
                self.parsed.inherits.append((qname, name))
        self.scope.append(qname)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qname = f"{self.current}.{node.name}"
        self.parsed.symbols.append(
            ParsedSymbol(
                kind="function",
                name=node.name,
                qualified_name=qname,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                parent=self._parent(),
                metrics={
                    "complexity": _complexity(node),
                    "loc": (node.end_lineno or node.lineno) - node.lineno + 1,
                    "parameters": len(node.args.args) + len(node.args.kwonlyargs),
                    "decorators": len(node.decorator_list),
                },
            )
        )
        self.scope.append(qname)
        self.generic_visit(node)
        self.scope.pop()

    # -- references -----------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        # Module-level calls (scope depth 1) are not attributed to a symbol.
        if len(self.scope) > 1 and (callee := _dotted(node.func)):
            self.parsed.calls.append((self.current, callee))
        self.generic_visit(node)


class PythonParser:
    language = "python"
    extensions = (".py",)

    def parse(self, rel_path: str, source: str) -> ParsedFile:
        tree = ast.parse(source, filename=rel_path)
        stem = rel_path[: -len(".py")].replace("/", ".")
        is_package = stem.endswith("__init__")
        module = stem.removesuffix(".__init__") if stem.endswith(".__init__") else stem
        parsed = ParsedFile(path=rel_path, module=module, language=self.language,
                            loc=source.count("\n") + 1)
        _Visitor(parsed, is_package).visit(tree)
        return parsed
