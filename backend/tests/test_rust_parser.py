"""Rust parser tests; like the builder tests they run without Neo4j."""
import textwrap
from pathlib import Path

import pytest

from app.graph.builder import GraphBuilder
from app.graph.parsers import parser_for
from app.graph.parsers.rust import RustParser, module_names
from app.models.graph import EdgeKind


def parse(path: str, source: str):
    return RustParser().parse(path, textwrap.dedent(source))


def symbols(parsed):
    return {s.qualified_name: s for s in parsed.symbols}


@pytest.mark.parametrize(("path", "expected"), [
    ("src/lib.rs", ("crate", "crate")),
    ("src/main.rs", ("crate.main", "crate")),
    ("src/a.rs", ("crate.a", "crate")),
    ("src/a/mod.rs", ("crate.a", "crate")),
    ("src/a/b.rs", ("crate.a.b", "crate")),
    ("crates/my-crate/src/lib.rs", ("my_crate", "my_crate")),
    ("crates/my-crate/src/x.rs", ("my_crate.x", "my_crate")),
    ("tests/it.rs", ("tests.it", "tests.it")),
])
def test_module_names(path, expected):
    assert module_names(path) == expected


def test_registered_for_rs_files():
    assert isinstance(parser_for(Path("src/lib.rs")), RustParser)


def test_items_subkinds_and_parents():
    parsed = parse("src/shapes.rs", """
        pub struct Circle { r: f64 }
        struct Pair(i32, i32);
        enum Shape { Circle(Circle), Empty }
        pub trait Area: Clone { fn area(&self) -> f64; fn twice(&self) -> f64 { self.area() * 2.0 } }

        impl Circle {
            pub fn new(r: f64) -> Self { Circle { r } }
            fn grow(&mut self, by: f64) { self.r += by; }
        }
        impl Area for Circle { fn area(&self) -> f64 { 3.14 * self.r * self.r } }
        impl From<f64> for Circle { fn from(r: f64) -> Self { Self::new(r) } }
        impl From<i32> for Circle { fn from(r: i32) -> Self { Self::new(r as f64) } }

        pub fn helper() {}
        mod inner { fn nested() {} }
    """)
    syms = symbols(parsed)
    by_subkind = {q: s.subkind for q, s in syms.items()}

    assert by_subkind["crate.shapes.Circle"] == "struct"
    assert by_subkind["crate.shapes.Shape"] == "enum"
    assert by_subkind["crate.shapes.Area"] == "trait"
    assert by_subkind["crate.shapes.Area.area"] == "trait fn"
    assert by_subkind["crate.shapes.Circle.new"] == "method"
    assert by_subkind["crate.shapes.Circle.<Area>.area"] == "trait impl fn"
    assert by_subkind["crate.shapes.helper"] == "fn"
    assert "crate.shapes.Circle.<From>.from~2" in syms                  # duplicate names stay distinct
    assert "crate.shapes.inner.nested" in syms

    assert syms["crate.shapes.Circle.new"].parent == "crate.shapes.Circle"
    assert syms["crate.shapes.Circle.<Area>.area"].parent == "crate.shapes.Circle"
    assert syms["crate.shapes.Area.twice"].parent == "crate.shapes.Area"
    assert syms["crate.shapes.inner.nested"].parent is None            # inline mods are not nodes

    assert syms["crate.shapes.Circle"].metrics == {"loc": 1, "methods": 5, "fields": 1}
    assert syms["crate.shapes.Pair"].metrics["fields"] == 2
    assert syms["crate.shapes.Shape"].metrics["variants"] == 2
    assert syms["crate.shapes.Area"].metrics["methods"] == 2
    assert syms["crate.shapes.Circle.grow"].metrics["parameters"] == 2

    assert ("crate.shapes.Area", "Clone") in parsed.inherits
    assert ("crate.shapes.Circle", "Circle", "Area") in parsed.implements


def test_path_rewriting_in_calls():
    parsed = parse("src/a/b.rs", """
        use crate::db::{connect, pool::Pool as P};
        use super::sibling;

        struct T;
        impl T {
            fn new() -> Self { T }
            fn run(&self) {
                connect();
                P::get();
                sibling::go();
                self::local();
                crate::x::y::<u8>();
                Self::new();
                self.step();
                other.thing().step();
            }
        }
        fn local() {}
    """)
    callees = [callee for caller, callee in parsed.calls if caller == "crate.a.b.T.run"]
    assert callees == [
        "crate.db.connect", "crate.db.pool.Pool.get", "crate.a.sibling.go", "crate.a.b.local",
        "crate.x.y", "crate.a.b.T.new", "self.step", "_.step", "_.thing",
    ]


def test_use_trees_become_import_candidates():
    parsed = parse("src/a.rs", "use crate::m::{self, n::Item, glob::*};\nuse std::fmt;\n")
    assert {"crate.m", "crate.m.n.Item", "crate.m.n", "crate.m.glob"} <= set(parsed.imports)
    assert "std.fmt" in parsed.imports                                  # dropped later by the builder


def test_complexity_and_entry_attributes():
    parsed = parse("src/lib.rs", """
        #[inline]
        fn f(x: i32, y: Option<i32>) -> i32 {
            if x > 0 && x < 10 {
                for i in 0..x {
                    while i > 2 { break; }
                }
            } else if let Some(v) = y {
                return v;
            }
            let g = |z: i32| if z > 0 { 1 } else { 0 };
            match x { 1 => 1, 2 | 3 => 2, _ => 3 }
        }

        #[test]
        fn checks() {}
    """)
    syms = symbols(parsed)
    # 1 + if + && + for + while + else-if + 3 match arms; the closure's `if` is not counted
    assert syms["crate.f"].metrics["complexity"] == 9
    assert syms["crate.f"].metrics["decorators"] == 0                   # #[inline] is not an entry point
    assert syms["crate.checks"].metrics["decorators"] == 1


@pytest.fixture
def crate_repo(tmp_path: Path) -> Path:
    src = tmp_path / "shop" / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text("pub mod model;\npub mod ops;\n")
    (src / "model.rs").write_text(textwrap.dedent("""
        pub trait Named { fn name(&self) -> String; }
        pub trait Labeled: Named { fn label(&self) -> String { self.name() } }
        pub struct Item;
    """))
    (src / "ops.rs").write_text(textwrap.dedent("""
        use crate::model::{Item, Named};

        impl Named for Item { fn name(&self) -> String { describe() } }

        pub fn describe() -> String { String::new() }
        pub fn make() -> Item { build_item() }
        fn build_item() -> Item { Item }
    """))
    (tmp_path / "shop" / "target").mkdir()
    (tmp_path / "shop" / "target" / "gen.rs").write_text("fn generated() {}")
    return tmp_path


def test_builder_end_to_end(crate_repo: Path):
    graph = GraphBuilder().build(crate_repo, "p1")
    ids = {n.id for n in graph.nodes}
    assert not any("generated" in i for i in ids)

    nodes = {n.id: n for n in graph.nodes}
    assert nodes["p1:shop.model.Item"].subkind == "struct"
    assert nodes["p1:shop.model.Item"].language == "rust"

    edges = {(e.source, e.target, e.kind) for e in graph.edges}
    assert ("p1:shop/src/ops.rs", "p1:shop/src/model.rs", EdgeKind.imports) in edges
    assert ("p1:shop.ops.make", "p1:shop.ops.build_item", EdgeKind.calls) in edges
    assert ("p1:shop.ops.Item.<Named>.name", "p1:shop.ops.describe", EdgeKind.calls) in edges
    # impl in ops.rs, type and trait in model.rs
    assert ("p1:shop.model.Item", "p1:shop.model.Named", EdgeKind.implements) in edges
    assert ("p1:shop.model.Labeled", "p1:shop.model.Named", EdgeKind.inherits) in edges
