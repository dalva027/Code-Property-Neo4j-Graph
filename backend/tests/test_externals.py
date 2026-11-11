"""External callees, macros and CALLS edge properties; no Neo4j needed."""
import textwrap
from pathlib import Path

from app.analyzers.base import Analyzer
from app.graph.builder import GraphBuilder
from app.graph.parsers.rust import RustParser
from app.graph.repository import _node_from_props, _node_props
from app.models.analysis import Category, Confidence, Severity
from app.models.graph import EdgeKind, GraphNode, NodeKind


def calls(source: str, path: str = "src/lib.rs"):
    return RustParser().parse(path, textwrap.dedent(source)).calls


def test_external_paths():
    found = {c.callee: c.external for c in calls("""
        use std::mem;
        use std::process::Command;
        mod inner;
        enum E { A(u8) }
        fn f(x: Option<u8>) {
            mem::transmute::<u8, i8>(1);
            Command::new("ls").arg("-l");
            Vec::new();
            drop(x);
            x.unwrap();
            Some(1);
            E::A(1);
            inner::go();
            crate::x::y();
            local();
        }
    """)}
    assert found["std.mem.transmute"] == "std::mem::transmute"
    assert found["std.process.Command.new"] == "std::process::Command::new"
    assert found["_.arg"] == "?::arg"
    assert found["Vec.new"] == "std::vec::Vec::new"
    assert found["drop"] == "std::mem::drop"
    assert found["_.unwrap"] == "?::unwrap"
    # Constructors, local types, local modules, this crate and bare names have nothing external.
    assert found["Some"] is None and found["E.A"] is None and found["inner.go"] is None
    assert found["crate.x.y"] is None and found["local"] is None


def test_macros_and_calls_inside_them():
    found = calls("""
        use log::info;
        macro_rules! here { () => {} }
        fn f() {
            let v = vec![0u8; size()];
            println!("{} {}", g(1), self_check().is_ok());
            info!("x {}", h());
            tokio::select! { _ = a() => {} }
            here!();
        }
    """)
    macros = {c.external: c.line for c in found if c.is_macro}
    assert macros == {"std::vec!": 5, "std::println!": 6, "log::info!": 7, "tokio::select!": 8}
    plain = {c.callee: c.line for c in found if not c.is_macro}
    assert plain == {"size": 5, "g": 6, "self_check": 6, "_.is_ok": 6, "h": 7}   # select! is not re-parsed


def test_multiline_macro_lines():
    found = calls("""
        fn f() {
            assert_eq!(
                one(),
                two(),
            );
        }
    """)
    assert {c.callee: c.line for c in found if not c.is_macro} == {"one": 4, "two": 5}


def test_builder_creates_external_nodes_and_call_props(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(textwrap.dedent("""
        pub fn run(x: Option<u8>) -> u8 {
            helper();
            helper();
            println!("{}", helper());
            x.unwrap()
        }
        fn helper() -> u8 { std::process::exit(1) }
    """))
    graph = GraphBuilder().build(tmp_path, "p1")
    nodes = {n.id: n for n in graph.nodes}
    edges = {(e.source, e.target, e.kind): e for e in graph.edges}

    unwrap = nodes["p1:?::unwrap"]
    assert unwrap.kind == NodeKind.external and unwrap.name == "unwrap"
    assert unwrap.attrs == {"path": "?::unwrap", "is_macro": False}
    assert nodes["p1:std::process::exit"].attrs["crate"] == "std"
    assert nodes["p1:std::println!"].subkind == "macro"

    to_helper = edges[("p1:crate.run", "p1:crate.helper", EdgeKind.calls)]
    assert to_helper.props == {"count": 3, "line": 3}                     # two calls + one inside println!
    assert ("p1:crate.helper", "p1:std::process::exit", EdgeKind.calls) in edges
    assert sum(n.kind in ("class", "function") for n in graph.nodes) == 2


def test_python_unresolved_calls_are_still_dropped(tmp_path: Path):
    (tmp_path / "m.py").write_text("def f():\n    print(len([]))\n")
    graph = GraphBuilder().build(tmp_path, "p1")
    assert not any(n.kind == NodeKind.external for n in graph.nodes)


def test_node_props_round_trip_keeps_attrs_apart_from_metrics():
    node = GraphNode(id="p:x", kind=NodeKind.external, name="x", qualified_name="a::x", language="rust",
                     subkind="external", metrics={"loc": 3}, attrs={"path": "a::x", "is_macro": False,
                                                                     "tags": ["a", "b"]})
    back = _node_from_props({k: v for k, v in _node_props(node, "p").items() if v is not None})
    assert back.metrics == {"loc": 3}
    assert back.attrs == {"path": "a::x", "is_macro": False, "tags": ["a", "b"]}


def test_findings_carry_v2_fields():
    class Demo(Analyzer):
        rule = "demo"
        severity = Severity.warning
        category = Category.unsafe
        cwe = ("CWE-119",)
        languages = ("rust",)

        async def run(self, repo, project_id):
            return []

    demo = Demo()
    f = demo.finding("p", "msg", evidence=["p:a", "p:b"], confidence=Confidence.medium)
    assert (f.category, f.cwe, f.evidence, f.confidence, f.rule_version) == (
        Category.unsafe, ["CWE-119"], ["p:a", "p:b"], Confidence.medium, "1")
    assert demo.applies_to({"rust", "python"}) and not demo.applies_to({"python"})
    assert demo.info().languages == ["rust"]
