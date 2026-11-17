"""The rust-analyzer extractor's code facts, joined onto the tree-sitter parse (app/graph/facts.py).

The facts under tests/fixtures/*.code-facts.json were produced by `codegraph-extract code` and are
committed, so these tests need neither the binary nor Neo4j: they overlay the fixture onto a fresh
tree-sitter parse and look at the graph the builder assembles. `test_fixture_is_current` re-runs
the extractor when it is available and fails if a fixture no longer matches the binary.

Regenerate a fixture after changing the extractor (from the repository root):

    scripts/codegraph-extract-docker code --manifest-path $PWD/backend/tests/fixtures/flows/Cargo.toml
"""
import json
from collections import defaultdict, deque
from pathlib import Path

import pytest

from app.config import settings
from app.graph import facts
from app.graph.builder import GraphBuilder
from app.graph.extractor import extractor_path
from app.models.graph import FLOW_EDGE_KINDS, CodeGraph, EdgeKind, GraphNode, NodeKind
from app.rules import load_catalogue

FIXTURES = Path(__file__).parent / "fixtures"
REPOS = Path(__file__).resolve().parents[2] / "repos"
CASES = {"flows": FIXTURES / "flows", "sample-rust": REPOS / "sample-rust"}


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.code-facts.json").read_text(encoding="utf-8"))


def build(name: str, monkeypatch: pytest.MonkeyPatch) -> tuple[CodeGraph, GraphBuilder]:
    """The graph of a fixture project, with the committed facts standing in for the extractor."""
    monkeypatch.setattr(settings, "code_facts", "auto")
    monkeypatch.setattr(facts, "extractor_path", lambda: "codegraph-extract")
    monkeypatch.setattr(facts, "run_code_extractor", lambda manifest, root, ignored=None: load(name))
    builder = GraphBuilder()
    return builder.build(CASES[name], "p"), builder


class Flow:
    """Reachability over FLOWS_TO / PASSES / RETURNS_TO, the way the taint rules walk it."""

    def __init__(self, graph: CodeGraph):
        self.nodes = {n.id: n for n in graph.nodes}
        self.out: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for e in graph.edges:
            if e.kind in FLOW_EDGE_KINDS:
                self.out[e.source].append((e.target, str(e.props.get("via", ""))))
        self.sources = [n.id for n in graph.nodes
                        if n.kind == NodeKind.call and n.attrs.get("callee_path") == "std::env::args"]
        sink = next(n for n in graph.nodes if n.kind == NodeKind.var and n.qualified_name == "crate.sink#command")
        # What each function hands to `sink`: the nodes with a PASSES edge into its parameter.
        self.handed: dict[str, list[str]] = defaultdict(list)
        for e in graph.edges:
            if e.kind == EdgeKind.passes and e.target == sink.id:
                self.handed[self.nodes[e.source].qualified_name.split("#")[0]].append(e.source)

    def path(self, target: str) -> list[tuple[GraphNode, str]] | None:
        """Shortest path from `std::env::args()` to `target` as (node, via it was reached by)."""
        prev: dict[str, tuple[str | None, str]] = {s: (None, "") for s in self.sources}
        queue = deque(self.sources)
        while queue:
            node = queue.popleft()
            if node == target:
                steps = []
                at: str | None = node
                while at is not None:
                    steps.append((self.nodes[at], prev[at][1]))
                    at = prev[at][0]
                return steps[::-1]
            for nxt, via in self.out[node]:
                if nxt not in prev:
                    prev[nxt] = (node, via)
                    queue.append(nxt)
        return None

    def into_sink(self, function: str) -> list[tuple[GraphNode, str]] | None:
        paths = [p for n in self.handed.get(f"crate.{function}", []) if (p := self.path(n)) is not None]
        return min(paths, key=len) if paths else None


@pytest.fixture
def flows(monkeypatch: pytest.MonkeyPatch) -> Flow:
    graph, _ = build("flows", monkeypatch)
    return Flow(graph)


# -- week 1: the extractor sees the same items as tree-sitter ------------------------------------
@pytest.mark.parametrize("name", sorted(CASES))
def test_symbols_equal_tree_sitter(name: str):
    """Golden test of the plan: the extractor's item list equals the tree-sitter symbol set."""
    root = CASES[name]
    parsed = GraphBuilder()._parse_tree(root)
    kinds = {"function": "fn"}
    ours = {(pf.path, kinds.get(s.kind, s.subkind), s.name, s.name_line, s.name_col)
            for pf in parsed if pf.language == "rust" for s in pf.symbols}
    theirs = {(f["path"], s["kind"], s["name"], s["line"], s["col"])
              for f in load(name)["files"] for s in f["symbols"]}
    assert theirs == ours
    assert len(ours) > 10


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_function_is_joined(name: str, monkeypatch: pytest.MonkeyPatch):
    _, builder = build(name, monkeypatch)
    stats = builder.code_facts
    assert stats is not None and stats.unmatched == 0
    assert stats.functions == len(load(name)["fns"]) and stats.analyzed > 0
    assert stats.resolved_method_calls == stats.method_calls > 0
    assert not stats.warnings


# -- week 2: resolved calls, real receiver types, macro-internal calls -----------------------------
def test_calls_are_resolved_and_typed(monkeypatch: pytest.MonkeyPatch):
    graph, _ = build("flows", monkeypatch)
    externals = {str(n.attrs["path"]) for n in graph.nodes if n.kind == NodeKind.external}
    assert not [p for p in externals if p.startswith("?::")], "every receiver type is known"
    assert {"std::process::Command::new", "std::env::args", "std::option::Option::unwrap_or_default",
            "str::trim", "std::format!"} <= externals
    # A method on `&dyn Runner` resolves to the trait method, and the impl hangs off it.
    by_name = {n.qualified_name: n.id for n in graph.nodes if n.kind == NodeKind.function}
    calls = {(e.source, e.target) for e in graph.edges if e.kind == EdgeKind.calls}
    assert (by_name["crate.dispatch"], by_name["crate.Runner.run"]) in calls
    assert any(e.kind == EdgeKind.references and e.props.get("via") == "dispatch"
               and e.source == by_name["crate.Runner.run"] and e.target == by_name["crate.Shell.<Runner>.run"]
               for e in graph.edges)


def test_macro_internal_calls_are_in_the_graph(monkeypatch: pytest.MonkeyPatch):
    """`run!(&a)` expands to `sink(&a)`: tree-sitter cannot see that call, the extractor reports it."""
    graph, _ = build("flows", monkeypatch)
    by_name = {n.qualified_name: n.id for n in graph.nodes if n.kind == NodeKind.function}
    assert any(e.kind == EdgeKind.calls and e.source == by_name["crate.through_macro"]
               and e.target == by_name["crate.sink"] for e in graph.edges)
    sites = [n for n in graph.nodes if n.kind == NodeKind.call and n.attrs.get("in_macro")]
    assert any(n.qualified_name.startswith("crate.through_macro#") and n.attrs["callee_path"] == "crate.sink"
               for n in sites)

    monkeypatch.setattr(settings, "code_facts", "off")
    plain = GraphBuilder().build(CASES["flows"], "p")
    names = {n.qualified_name: n.id for n in plain.nodes if n.kind == NodeKind.function}
    assert not any(e.kind == EdgeKind.calls and e.source == names["crate.through_macro"]
                   and e.target == names["crate.sink"] for e in plain.edges)
    assert not any(n.kind == NodeKind.var for n in plain.nodes), "no data flow without the extractor"


# -- weeks 3-4: data flow, one construct per function ------------------------------------------------
@pytest.mark.parametrize("function", [
    "let_chain", "method_chain", "through_format", "through_format_args", "struct_literal", "closure_param",
    "one_call", "two_calls", "through_macro", "guarded", "through_try",
])
def test_source_reaches_sink(function: str, flows: Flow):
    assert flows.into_sink(function), f"no flow from the source to sink() in {function}"


def test_no_flow_without_a_source(flows: Flow):
    assert flows.into_sink("untainted") is None                 # a literal argument carries nothing


def test_interprocedural_edges(flows: Flow):
    """An argument PASSES to the callee's parameter and the callee's result RETURNS_TO the site."""
    def named(prefix: str) -> list[str]:
        return [n.id for n in flows.nodes.values() if n.qualified_name.startswith(prefix)]

    def step(sources: list[str], target_name: str) -> list[str]:
        return [via for s in sources for t, via in flows.out[s] if flows.nodes[t].qualified_name == target_name]

    # two_calls: source() -> pass_two(value) -> pass_one(value) -> back out through both returns.
    assert step(named("crate.two_calls#call@"), "crate.pass_two#value") == ["arg:0"]
    assert step(named("crate.pass_two#value"), "crate.pass_one#value") == ["arg:0"]
    assert step(named("crate.pass_one#value"), "crate.pass_one#<return>") == ["return"]
    returned = [flows.nodes[t] for s in named("crate.pass_one#<return>") for t, _ in flows.out[s]]
    assert {n.qualified_name.split("#")[0] for n in returned} == {"crate.pass_two", "crate.one_call"}
    assert all(n.kind == NodeKind.call for n in returned), "a return value flows to the call sites"

    path = flows.into_sink("two_calls")
    assert path is not None
    names = [node.qualified_name for node, _ in path]
    assert "crate.source#<return>" in names, "the source is inside a helper: its return value carries it out"
    assert "crate.pass_two#<return>" in names


def test_trait_dispatch_reaches_the_impl(flows: Flow):
    impl_param = next(n for n in flows.nodes.values() if n.qualified_name == "crate.Shell.<Runner>.run#command")
    path = flows.path(impl_param.id)
    assert path is not None
    assert "dispatch" in [via for _, via in path], "trait method parameter -> impl parameter"


def test_out_parameter_is_written_by_the_call(flows: Flow):
    """`stdin().read_line(&mut line)`: the call writes into `line`, whatever it returns."""
    line = next(n for n in flows.nodes.values() if n.qualified_name == "crate.out_param#line")
    call = next(n for n in flows.nodes.values() if n.kind == NodeKind.call
                and str(n.attrs.get("callee_path", "")).endswith("::read_line"))
    assert (line.id, "out") in flows.out[call.id]
    assert call.attrs.get("writes_out") is True and call.attrs.get("ret_kind") == "int"


def test_what_blocks_a_text_rule_is_on_the_path(flows: Flow):
    # A number cannot carry a command: `count: u32` sits between the source and the sink.
    path = flows.into_sink("through_try")
    assert path is not None and any(node.attrs.get("ty_kind") == "int" for node, _ in path)
    # A check is recorded as a guard on the variable, wherever in the function it happens.
    guarded = next(n for n in flows.nodes.values() if n.qualified_name == "crate.guarded#a")
    assert "starts_with" in guarded.attrs["guards"]
    # A struct literal is a site of its own, entered through a named field.
    path = flows.into_sink("struct_literal")
    assert path is not None
    assert [via for node, via in path if node.subkind == "struct"] == ["field:name"]


def test_vars_are_typed_and_declared(monkeypatch: pytest.MonkeyPatch):
    graph, _ = build("flows", monkeypatch)
    by_id = {n.id: n for n in graph.nodes}
    declared = {e.target: by_id[e.source].qualified_name for e in graph.edges if e.kind == EdgeKind.declares}
    variables = [n for n in graph.nodes if n.kind == NodeKind.var]
    assert variables and all(v.id in declared for v in variables)
    count = next(v for v in variables if v.qualified_name == "crate.through_try#count")
    assert count.subkind == "local" and count.attrs["type"] == "u32" and count.attrs["ty_kind"] == "int"
    command = next(v for v in variables if v.qualified_name == "crate.sink#command")
    assert command.subkind == "param" and command.metrics["index"] == 0 and command.attrs["type_path"] == "str"


# -- the loader's own decisions -------------------------------------------------------------------------
def test_catalogue_name_wins_among_candidates():
    matcher = load_catalogue().matcher()
    candidates = ["axum::http::HeaderValue::from_maybe_shared_unchecked",
                  "http::header::value::HeaderValue::from_maybe_shared_unchecked",
                  "http::HeaderValue::from_maybe_shared_unchecked"]
    assert facts._choose(candidates, matcher) == "http::HeaderValue::from_maybe_shared_unchecked"
    assert facts._choose(["a::b::c", "a::c"], matcher) == "a::b::c"      # nothing matches: the first
    assert facts._choose([], matcher) is None


def test_fallback_without_the_binary(monkeypatch: pytest.MonkeyPatch):
    """No extractor: a warning for the scan notes, and the plain tree-sitter graph."""
    monkeypatch.setattr(settings, "code_facts", "auto")
    monkeypatch.setattr(facts, "extractor_path", lambda: None)
    builder = GraphBuilder()
    graph = builder.build(CASES["flows"], "p")
    assert builder.code_facts is not None and "code facts skipped" in builder.code_facts.warnings[0]
    assert not any(n.kind == NodeKind.var for n in graph.nodes)
    assert any(str(n.attrs.get("path", "")).startswith("?::") for n in graph.nodes if n.kind == NodeKind.external)

    monkeypatch.setattr(settings, "code_facts", "off")
    builder = GraphBuilder()
    builder.build(CASES["flows"], "p")
    assert builder.code_facts is None


def test_failed_run_falls_back(monkeypatch: pytest.MonkeyPatch):
    def boom(manifest: Path, root: Path, ignored: set[str] | None = None) -> dict:
        raise facts.ExtractorUnavailable("cargo metadata failed")

    monkeypatch.setattr(settings, "code_facts", "auto")
    monkeypatch.setattr(facts, "extractor_path", lambda: "codegraph-extract")
    monkeypatch.setattr(facts, "run_code_extractor", boom)
    builder = GraphBuilder()
    graph = builder.build(CASES["flows"], "p")
    assert builder.code_facts is not None
    assert builder.code_facts.warnings == ["code facts skipped for Cargo.toml: cargo metadata failed"]
    assert any(n.kind == NodeKind.function for n in graph.nodes)


def test_a_failed_workspace_is_not_retried_per_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """When the workspace root cannot be loaded, its members would fail the same way, one costly
    run each. An unrelated crate next to it is still tried."""
    for crate in ("ws", "ws/a", "ws/b", "other"):
        (tmp_path / crate / "src").mkdir(parents=True)
        (tmp_path / crate / "Cargo.toml").write_text("[package]\nname = 'x'\nversion = '0.1.0'\n")
        (tmp_path / crate / "src" / "lib.rs").write_text("pub fn f() {}\n")
    tried: list[str] = []

    def boom(manifest: Path, root: Path, ignored: set[str] | None = None) -> dict:
        tried.append(manifest.parent.relative_to(root).as_posix())
        raise facts.ExtractorUnavailable("out of memory")

    monkeypatch.setattr(settings, "code_facts", "auto")
    monkeypatch.setattr(facts, "extractor_path", lambda: "codegraph-extract")
    monkeypatch.setattr(facts, "run_code_extractor", boom)
    builder = GraphBuilder()
    builder.build(tmp_path, "p")
    assert tried == ["other", "ws"]
    assert builder.code_facts is not None and len(builder.code_facts.warnings) == 2


def test_cache_reuses_facts_for_unchanged_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "crate"
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text("[package]\nname = 'x'\nversion = '0.1.0'\n")
    (root / "src" / "lib.rs").write_text("pub fn f() {}\n")
    runs: list[list[str]] = []

    def fake(args: list[str], timeout: int) -> str:
        runs.append(args)
        return "codegraph-extract 0.2.0" if args == ["--version"] else json.dumps(
            {"schema_version": facts.CODE_SCHEMA_VERSION, "files": [], "fns": [], "sites": []})

    monkeypatch.setattr(settings, "code_facts_cache", str(tmp_path / "cache"))
    monkeypatch.setattr(facts, "run_extractor_cli", fake)
    monkeypatch.setattr(facts, "extractor_path", lambda: "codegraph-extract")
    facts._extractor_version.cache_clear()
    first = facts.run_code_extractor(root / "Cargo.toml", root)
    again = facts.run_code_extractor(root / "Cargo.toml", root)
    assert first == again and [r[0] for r in runs] == ["--version", "code"]

    (root / "src" / "lib.rs").write_text("pub fn g() {}\n")            # a source changed: run again
    facts.run_code_extractor(root / "Cargo.toml", root)
    assert [r[0] for r in runs] == ["--version", "code", "code"]
    facts._extractor_version.cache_clear()


def test_wrong_schema_is_refused():
    with pytest.raises(facts.ExtractorUnavailable, match="schema"):
        facts._checked({"schema_version": 999})


@pytest.mark.extractor
@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture_is_current(name: str, monkeypatch: pytest.MonkeyPatch):
    """With the extractor installed: the committed fixture is what the binary produces today."""
    if extractor_path() is None or not facts.enabled():
        pytest.skip(f"{settings.codegraph_extractor} not found; set CODEGRAPH_EXTRACTOR")
    monkeypatch.setattr(settings, "code_facts_cache", "")
    root = CASES[name].resolve()
    fresh = facts.run_code_extractor(root / "Cargo.toml", root)
    committed = load(name)
    for volatile in ("root", "manifest", "stats", "tool"):
        fresh.pop(volatile, None)
        committed.pop(volatile, None)
    assert fresh == committed, f"regenerate tests/fixtures/{name}.code-facts.json (see this module's docstring)"
