"""Builder/parser tests run without Neo4j."""
import textwrap
from pathlib import Path

import pytest

from app.graph.builder import GraphBuilder
from app.graph.parsers.python import PythonParser
from app.models.graph import EdgeKind, NodeKind


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text(textwrap.dedent("""
        from pkg.b import helper

        class Base:
            def run(self):
                return self.step()

            def step(self):
                return helper()

        class Child(Base):
            pass

        def orphan():
            return 1
    """))
    (pkg / "b.py").write_text(textwrap.dedent("""
        from pkg import a

        def helper():
            return a
    """))
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.py").write_text("x = 1")
    return tmp_path


def test_builds_nodes_and_edges(sample_repo: Path):
    graph = GraphBuilder().build(sample_repo, "p1")

    ids = {n.id for n in graph.nodes}
    assert {"p1:pkg/a.py", "p1:pkg/b.py", "p1:pkg/__init__.py"} <= ids
    assert "p1:pkg.a.Base.run" in ids
    assert not any("ignored" in i for i in ids)

    edges = {(e.source, e.target, e.kind) for e in graph.edges}
    assert ("p1:pkg/a.py", "p1:pkg.a.Base", EdgeKind.contains) in edges
    assert ("p1:pkg.a.Base", "p1:pkg.a.Base.run", EdgeKind.contains) in edges
    assert ("p1:pkg.a.Base.run", "p1:pkg.a.Base.step", EdgeKind.calls) in edges      # self.method
    assert ("p1:pkg.a.Base.step", "p1:pkg.b.helper", EdgeKind.calls) in edges         # imported name
    assert ("p1:pkg.a.Child", "p1:pkg.a.Base", EdgeKind.inherits) in edges
    assert ("p1:pkg/a.py", "p1:pkg/b.py", EdgeKind.imports) in edges
    assert ("p1:pkg/b.py", "p1:pkg/a.py", EdgeKind.imports) in edges                  # the cycle


def test_class_metrics(sample_repo: Path):
    graph = GraphBuilder().build(sample_repo, "p1")
    base = next(n for n in graph.nodes if n.id == "p1:pkg.a.Base")
    assert base.kind == NodeKind.class_
    assert base.metrics["methods"] == 2


def test_complexity_metric():
    parsed = PythonParser().parse("m.py", textwrap.dedent("""
        def f(x):
            if x and x > 1:
                for i in range(x):
                    if i % 2:
                        return i
            return [i for i in range(3) if i]
    """))
    fn = next(s for s in parsed.symbols if s.name == "f")
    assert fn.metrics["complexity"] == 7


def test_relative_imports_resolve_against_package():
    parsed = PythonParser().parse("pkg/sub/mod.py", "from ..core import thing\nfrom . import sibling\n")
    assert "pkg.core" in parsed.imports
    assert "pkg.sub.sibling" in parsed.imports


def test_a_file_too_deep_to_walk_is_skipped_not_fatal(tmp_path: Path):
    """One pathological file (generated code, a huge expression) must not fail the whole scan."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.rs").write_text("pub fn fine() -> u32 { 1 }\n")
    (tmp_path / "src" / "deep.rs").write_text("fn f(a: u32) -> u32 { " + " + ".join(["a"] * 3000) + " }\n")
    builder = GraphBuilder()
    graph = builder.build(tmp_path, "p")
    assert {n.file for n in graph.nodes if n.kind == "file"} == {"src/ok.rs"}
    assert builder.warnings == ["src/deep.rs was skipped: its expressions nest too deeply to parse"]
