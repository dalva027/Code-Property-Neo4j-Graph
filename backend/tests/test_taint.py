"""The pieces of the taint rules that need no database: rule registration, sink conditions and
which sources a rule about numbers may start from. The rules themselves are exercised end to end
by the ground-truth harness on repos/vuln-samples/taint."""
from app.analyzers import REGISTRY, flow, taint
from app.models.analysis import Category, Severity
from app.rules import PatternEntry, load_catalogue


def test_one_rule_per_catalogue_id():
    rules = {r.spec.id: r for r in taint.RULES}
    assert set(rules) == {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "P3", "P4"}
    catalogue = load_catalogue()
    assert set(rules) <= set(catalogue.sinks), "every taint rule has sinks in the catalogue"
    registered = {a.rule: a for a in REGISTRY}
    for cls in rules.values():
        rule = registered[cls.rule]
        assert rule.languages == ("rust",) and rule.cwe and rule.description
        assert rule.category == (Category.panic if cls.spec.id.startswith("P") else Category.injection)
    assert registered["command-injection"].severity == Severity.critical
    assert registered["overflow-candidate"].spec.per_function


def test_sink_vias():
    assert taint.sink_vias(PatternEntry(path="a::b", args=[0, 2])) == ["arg:0", "arg:2"]
    assert taint.sink_vias(PatternEntry(path="a::b", args=[1], receiver=True)) == ["arg:1", "recv"]
    assert taint.sink_vias(PatternEntry(path="std::write!", template="x")) == ["macro"]
    assert "recv" in taint.sink_vias(PatternEntry(path="a::b")) and "arg:3" in taint.sink_vias(PatternEntry(path="a::b"))


def test_when_reads_fixed_arguments():
    location = '[[0,"path","header::LOCATION"]]'
    assert taint._when({0: "(?i)location"}, location)
    assert taint._when({0: "(?i)location"}, '[[0,"str","Location"],[1,"str","/"]]')
    assert not taint._when({0: "(?i)location"}, '[[0,"path","header::CONTENT_TYPE"]]')
    assert not taint._when({0: "(?i)location"}, "[]") and not taint._when({0: "x"}, None)
    assert not taint._when({0: "x"}, "not json")


def test_which_library_parameters_start_a_numeric_rule():
    def param(what: str, kind: str) -> flow.Source:
        return flow.Source("id", "pub_api", what, "pub_api", "crate.f", 1, kind)

    assert not param("data", "slice").structured            # a buffer: numbers decoded from it count
    assert not param("text", "str").structured
    assert not param("reader", "generic").structured
    assert param("width", "u32").structured                 # the caller's number is the caller's to check
    assert param("config", "mycrate::Config").structured
    assert param("self", "generic").structured              # `self` of a trait method is not raw data
    # Sources that are input by construction are never left out, and never weak.
    argv = flow.Source("id", "call", "std::env::args", "env", "crate.main", 1)
    assert not argv.structured and not argv.trusted_caller
    assert flow.Source("id", "call", "std::io::Read::read", "reader", "crate.f", 1).trusted_caller
    assert param("data", "slice").trusted_caller
