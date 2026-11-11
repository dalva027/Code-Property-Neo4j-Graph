"""Phase 2 facts: unsafe spans, entry kinds, references, operations, literals, and the nodes the
builder makes of them. No Neo4j needed."""
import json
import textwrap
from pathlib import Path

from app.analyzers.panics import strongly_connected
from app.graph.builder import GraphBuilder
from app.graph.parsers.rust import RustParser
from app.models.graph import EdgeKind, NodeKind
from app.rules import PatternEntry, load_catalogue


def parse(source: str, path: str = "src/main.rs"):
    return RustParser().parse(path, textwrap.dedent(source))


def symbols(parsed):
    return {s.qualified_name: s for s in parsed.symbols}


def test_function_attrs_and_entry_kinds():
    syms = symbols(parse("""
        #[no_mangle]
        pub unsafe extern "C" fn export(p: *const u8, n: usize) -> i32 { 0 }
        pub(crate) async fn worker() {}
        #[tokio::main]
        async fn main() {}
        #[get("/")]
        async fn index() -> String { String::new() }
        #[cfg(test)]
        mod tests {
            #[test]
            fn t() {}
            fn helper() {}
        }
        extern "C" { fn strlen(s: *const i8) -> usize; }
        pub trait Shape { fn area(&self) -> f64; }
        fn plain(depth: usize) {}
    """))
    export = syms["crate.main.export"]
    assert export.attrs["visibility"] == "pub" and export.attrs["abi"] == "C"
    assert export.attrs["is_unsafe"] and export.attrs["no_mangle"] and export.attrs["entry_kind"] == "ffi"
    assert export.metrics["raw_pointer_params"] == 1
    params = json.loads(export.attrs["params"])
    assert params[0] == {"index": 0, "name": "p", "type": "*const u8", "raw_pointer": True}

    assert syms["crate.main.worker"].attrs["visibility"] == "pub(crate)"
    assert syms["crate.main.worker"].attrs["is_async"]
    assert syms["crate.main.main"].attrs["entry_kind"] == "main"
    assert syms["crate.main.index"].attrs["entry_kind"] == "handler"
    assert syms["crate.main.tests.t"].attrs["entry_kind"] == "test"
    assert syms["crate.main.tests.helper"].attrs["in_test"] and "entry_kind" in syms["crate.main.tests.helper"].attrs
    assert syms["crate.main.strlen"].subkind == "foreign fn" and syms["crate.main.strlen"].attrs["abi"] == "C"
    assert syms["crate.main.Shape.area"].attrs["visibility"] == "pub"     # inherited from the trait
    assert syms["crate.main.plain"].attrs["depth_guard"]


def test_unsafe_spans_and_safety_comments():
    parsed = parse("""
        struct T(*mut u8);
        // SAFETY: T is only ever used from one thread.
        unsafe impl Send for T {}
        unsafe impl Sync for T {}
        unsafe trait Marker {}

        /// Doubles the value.
        ///
        /// # Safety
        /// `p` must be valid.
        pub unsafe fn documented(p: *mut u8) { *p *= 2; }

        pub unsafe fn undocumented(p: *mut u8) { *p = 0; }

        fn f(p: *mut u8) {
            // SAFETY: p comes from Box::into_raw above.
            unsafe { *p = 1; }
            let x = unsafe { *p };  // SAFETY: trailing comments count too
            #[allow(clippy::undocumented_unsafe_blocks)]
            unsafe { *p = 2; }
        }
    """)
    spans = {(u.kind, u.line_start): u for u in parsed.unsafes}
    assert spans[("impl", 4)].has_safety_comment and spans[("impl", 4)].trait == "Send"
    assert not spans[("impl", 5)].has_safety_comment and spans[("impl", 5)].target_type == "T"
    assert spans[("trait", 6)].trait == "Marker"
    assert spans[("fn", 12)].has_safety_comment and spans[("fn", 12)].container == "crate.main.documented"
    assert not spans[("fn", 14)].has_safety_comment
    assert spans[("block", 18)].has_safety_comment
    assert spans[("block", 19)].has_safety_comment
    assert not spans[("block", 21)].has_safety_comment
    assert parsed.metrics["unsafe_blocks"] == 3 and parsed.metrics["unsafe_fns"] == 2
    assert parsed.metrics["unsafe_impls"] == 2 and parsed.metrics["unsafe_traits"] == 1
    impls = {(i.trait, i.is_unsafe, i.trait_external) for i in parsed.implements}
    assert ("Send", True, "std::marker::Send") in impls


def test_calls_inside_unsafe_literal_args_and_chained_lines():
    parsed = parse("""
        use std::ptr;
        fn f(p: *mut u8, out: &mut [u8; 32]) {
            unsafe { ptr::write(p, 1); }
            ptr::null_mut::<u8>();
            let c = Client::builder()
                .danger_accept_invalid_certs(true)
                .build();
            pbkdf2_hmac(b"pw", b"salt", 1_000, out);
            seed([0u8; 32], -5, 'c', "s");
        }
    """)
    calls = {c.external or c.callee: c for c in parsed.calls}
    assert calls["std::ptr::write"].in_unsafe and calls["std::ptr::write"].literal_args == ((1, "int", "1"),)
    assert not calls["std::ptr::null_mut"].in_unsafe
    assert calls["?::danger_accept_invalid_certs"].line == 7          # the method's line, not the chain's
    assert calls["?::danger_accept_invalid_certs"].literal_args == ((0, "bool", "true"),)
    assert calls["?::build"].line == 8
    assert calls["pbkdf2_hmac"].literal_args == ((0, "str", "pw"), (1, "str", "salt"), (2, "int", "1_000"))
    assert calls["seed"].literal_args == ((0, "array", "[0u8; 32]"), (1, "int", "-5"), (2, "char", "'c'"),
                                          (3, "str", "s"))


def test_certainly_external_paths_are_not_resolvable():
    parsed = parse("""
        use smallvec::SmallVec;
        use crate::models::Product;
        mod inner { pub fn go() {} }
        struct Local;
        impl Local { fn with_capacity(n: usize) -> Self { Local } }
        fn f() {
            Vec::with_capacity(4);
            SmallVec::<[u8; 4]>::new();
            Product::new();
            inner::go();
            Local::with_capacity(1);
            serde_json::from_str("1");
            Glob::new();
            v.push(1);
        }
    """)
    flags = {c.callee: c.resolvable for c in parsed.calls}
    assert not flags["Vec.with_capacity"]                 # prelude type
    assert not flags["smallvec.SmallVec.new"]             # `use`d external crate
    assert flags["crate.models.Product.new"]              # anchored into this crate
    assert flags["inner.go"] and flags["Local.with_capacity"]       # a type of this file
    assert not flags["serde_json.from_str"]               # unknown lowercase head: a dependency
    assert flags["Glob.new"]                              # capitalised unknown head: maybe a glob import
    assert flags["_.push"]


def test_references_ops_and_literals():
    parsed = parse("""
        use axum::routing::get;
        use openssl::ssl::SslVerifyMode;
        async fn handler() {}
        fn worker() {}
        fn f(v: &mut Vec<u8>, i: usize, cb: fn()) {
            let app = Router::new().route("/", get(handler));
            std::thread::spawn(worker);
            builder.set_verify(SslVerifyMode::NONE);
            call(cb, v);
            let y = v[i] + v[0];
            v[i + 1] = 3;
            unsafe { let z = i * 2 + 1; }
            let password = "hunter2";
            const KEY: &str = "AKIAIOSFODNN7EXAMPLE";
            let session_token = Some("abc".to_string());
            cfg.api_key = String::from("xyz");
            builder.password("pw");
            let plain = "not a secret";
            let _ = call("secret looking value");
        }
    """)
    refs = {(r.ref, r.via, r.resolvable) for r in parsed.refs}
    assert ("handler", "get", True) in refs                      # unanchored: resolved lexically by the builder
    assert ("worker", "spawn", True) in refs
    assert any(r.ref == "openssl.ssl.SslVerifyMode.NONE" and not r.resolvable
               and r.external == "openssl::ssl::SslVerifyMode::NONE" for r in parsed.refs)
    assert not any(r.ref in ("cb", "v") for r in parsed.refs)      # locals and params are not references

    ops = [(o.op, o.line, o.detail, o.in_unsafe) for o in parsed.ops]
    assert ("index", 11, "i", False) in ops and ("index", 12, "i + 1", False) in ops
    assert not any(o.op == "index" and o.detail == "0" for o in parsed.ops)
    assert ("arith", 13, "*", True) in ops and ("arith", 13, "+", True) in ops

    lits = {(lit.binding, lit.length): lit for lit in parsed.literals}
    assert set(lits) == {("password", 7), ("KEY", 20), ("session_token", 3), ("api_key", 3), ("password", 2)}
    assert lits[("KEY", 20)].pattern == "aws_access_key_id" and lits[("KEY", 20)].preview == "AKIA…"
    assert lits[("password", 7)].sha256 and 0 < lits[("password", 7)].entropy < 3
    assert lits[("session_token", 3)].preview == "***"            # short values are fully masked
    assert "pw" not in {lit.preview for lit in parsed.literals}   # `.password("pw")`: the method is the binding
    assert "not a secret" not in {lit.preview for lit in parsed.literals}


def test_builder_makes_unsafe_call_literal_nodes_and_entry_kinds(tmp_path: Path):
    src = tmp_path / "app" / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text(textwrap.dedent("""
        pub mod web;
        pub fn api() -> u32 { helper() }
        fn helper() -> u32 { let v = vec![1]; v[0] }
    """))
    (src / "web.rs").write_text(textwrap.dedent("""
        use axum::routing::get;
        use axum::extract::Json;
        async fn index() -> &'static str { "hi" }
        async fn create(Json(body): Json<String>) {}
        pub fn router() { Router::new().route("/", get(index)); }
        pub fn raw(p: *mut u8) {
            // SAFETY: test
            unsafe { std::ptr::write(p, 1); }
            let secret_key = "AKIAIOSFODNN7EXAMPLE";
            let n = p as usize; let x = [1u8][n];
        }
        fn rec() { rec() }
    """))
    graph = GraphBuilder().build(tmp_path, "p")
    nodes = {n.id: n for n in graph.nodes}
    edges = {(e.source, e.target, e.kind): e for e in graph.edges}

    assert nodes["p:app.api"].attrs["entry_kind"] == "pub_api"
    assert "entry_kind" not in nodes["p:app.helper"].attrs
    assert nodes["p:app.web.index"].attrs["entry_kind"] == "handler"          # passed to get()
    assert nodes["p:app.web.create"].attrs["entry_kind"] == "handler"         # takes an extractor
    assert edges[("p:app.web.router", "p:app.web.index", EdgeKind.references)].props["via"] == "get"

    unsafe_nodes = [n for n in graph.nodes if n.kind == NodeKind.unsafe]
    assert len(unsafe_nodes) == 1 and unsafe_nodes[0].attrs["has_safety_comment"]
    assert ("p:app.web.raw", unsafe_nodes[0].id, EdgeKind.contains) in edges
    assert edges[("p:app.web.raw", "p:std::ptr::write", EdgeKind.calls)].props["unsafe"] is True

    calls = [n for n in graph.nodes if n.kind == NodeKind.call]
    kinds = {(n.subkind, n.attrs["callee_path"]) for n in calls}
    assert ("call", "std::ptr::write") in kinds and ("index", "ops::index") in kinds
    write_site = next(n for n in calls if n.attrs["callee_path"] == "std::ptr::write")
    assert write_site.attrs["in_unsafe"] and (write_site.id, "p:std::ptr::write", EdgeKind.targets) in edges
    assert not any(n.subkind == "index" and n.file == "src/lib.rs" for n in calls)   # v[0] is literal

    literal = next(n for n in graph.nodes if n.kind == NodeKind.literal)
    assert literal.attrs["pattern"] == "aws_access_key_id" and literal.attrs["binding"] == "secret_key"
    assert ("p:app.web.raw", literal.id, EdgeKind.has_literal) in edges
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps([n.model_dump() for n in graph.nodes])

    assert ("p:app.web.rec", "p:app.web.rec", EdgeKind.calls) in edges        # self-calls are kept
    assert nodes["p:app/src/web.rs"].metrics["unsafe_blocks"] == 1


def test_strongly_connected_components():
    edges = {"a": {"b"}, "b": {"a", "c"}, "c": {"c"}, "d": {"a"}, "e": {"f"}, "f": set()}
    assert strongly_connected(set("abcdef"), edges) == [["c"], ["a", "b"]]


def test_catalogue_matcher_and_kinds():
    matcher = load_catalogue().matcher()
    assert {m.group for m in matcher.match("?::unwrap")} == {"panic"}
    assert matcher.matches("md5::Md5::new", "weak_crypto") and matcher.matches("md5::compute")
    assert not matcher.matches("?::len")
    assert matcher.match("pbkdf2::pbkdf2_hmac")[0].entry.min == {2: 100000}
    assert PatternEntry(path="md5", kind="crate").matches("md5::digest::Digest::new")
    assert not PatternEntry(path="md5", kind="crate").matches("?::md5")
