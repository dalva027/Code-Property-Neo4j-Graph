"""The rule catalogue loads, validates and expands; no Neo4j needed."""
from pathlib import Path

import pytest

from app.rules import (
    CatalogueError,
    PatternEntry,
    expand_braces,
    load_catalogue,
    load_catalogue_from,
)


def test_shipped_catalogue_loads():
    cat = load_catalogue()
    assert cat.version and len(cat.digest) == 64
    assert {"T1", "T2", "T3", "T4", "T5", "T6", "T7", "P4"} <= set(cat.sinks)
    assert "std::fs::read_to_string" in {e.path for e in cat.sinks["T3"]}     # brace group expanded
    assert cat.secrets is not None and "aws_access_key_id" in cat.secrets.formats


def test_brace_expansion():
    assert expand_braces("std::fs::{read, write}") == ["std::fs::read", "std::fs::write"]
    assert expand_braces("a::{b,c}::{d,e}") == ["a::b::d", "a::b::e", "a::c::d", "a::c::e"]
    assert expand_braces("std::mem::drop") == ["std::mem::drop"]


@pytest.mark.parametrize(("pattern", "path", "hit"), [
    ("std::mem::transmute", "std::mem::transmute", True),
    ("std::mem::transmute", "core::mem::transmute", False),
    ("tokio::fs::*", "tokio::fs::read", True),
    ("tokio::fs::*", "tokio::fs::File::open", False),
    ("?::unwrap", "?::unwrap", True),
    ("?::unwrap", "std::option::Option::unwrap", True),
    ("std::vec!", "std::vec!", True),
])
def test_pattern_matching(pattern: str, path: str, hit: bool):
    assert PatternEntry(path=pattern).matches(path) is hit


def test_invalid_entries_are_rejected(tmp_path: Path):
    (tmp_path / "catalogue.yaml").write_text("version: '1'\nfiles: [sinks.yaml]\n")
    (tmp_path / "sinks.yaml").write_text("sinks:\n  T1:\n    - {path: 'not a path'}\n")
    with pytest.raises(CatalogueError, match="not a Rust path"):
        load_catalogue_from(tmp_path)

    (tmp_path / "sinks.yaml").write_text("sinks:\n  command-injection:\n    - {path: 'a::b'}\n")
    with pytest.raises(CatalogueError, match="rule ids"):
        load_catalogue_from(tmp_path)


def test_digest_changes_with_content(tmp_path: Path):
    (tmp_path / "catalogue.yaml").write_text("version: '1'\nfiles: [sinks.yaml]\n")
    (tmp_path / "sinks.yaml").write_text("sinks:\n  T1:\n    - {path: 'a::b'}\n")
    first = load_catalogue_from(tmp_path).digest
    (tmp_path / "sinks.yaml").write_text("sinks:\n  T1:\n    - {path: 'a::c'}\n")
    assert load_catalogue_from(tmp_path).digest != first


# -- phase 3: guards, templates and conditions ---------------------------------------------------
def test_guards_are_checks_not_paths():
    cat = load_catalogue()
    assert {"starts_with", "match"} <= set(cat.guards("T3"))
    assert cat.guards("T5") == ["cmp"]
    assert cat.guards("T2") and not cat.guards("nope")
    matcher = cat.matcher()
    # A guard names a check on a variable: it must not make `x.starts_with(..)` a sanitizer call.
    assert not matcher.matches("str::starts_with", "sanitizers")
    assert [m.group for m in matcher.match("usize::min", "sanitizers")] == ["T5", "P3", "P4"]


def test_typed_paths_match_under_any_of_their_names():
    matcher = load_catalogue().matcher()
    assert {m.group for m in matcher.match("std::option::Option::unwrap", "dangerous_ops")} == {"panic"}
    assert matcher.matches("pointer::add", "dangerous_ops")             # `?::add`, by last segment
    assert {m.group for m in matcher.match("std::net::TcpStream::read", "sources")} == {"network"}
    assert {m.group for m in matcher.match("std::io::Read::read", "sources")} == {"reader"}
    assert {m.group for m in matcher.match("std::fs::File::read", "sources")} == {"files"}
    assert {m.group for m in matcher.match("axum::extract::Query", "sources")} == {"axum"}


def test_template_and_when_are_validated(tmp_path: Path):
    (tmp_path / "catalogue.yaml").write_text("version: '1'\nfiles: [sinks.yaml]\n")
    (tmp_path / "sinks.yaml").write_text("sinks:\n  T6:\n    - {path: 'std::write!', template: '(unclosed'}\n")
    with pytest.raises(CatalogueError):
        load_catalogue_from(tmp_path)
    (tmp_path / "sinks.yaml").write_text("sinks:\n  T6:\n    - {path: 'a::b', args: [1], when: {0: '(?i)location'}}\n")
    entry = load_catalogue_from(tmp_path).sinks["T6"][0]
    assert entry.when == {0: "(?i)location"} and entry.args == [1]


def test_header_templates():
    """T6 takes a hand-written Location header, T7 any other hand-written header line."""
    import re

    cat = load_catalogue()
    t6 = next(e.template for e in cat.sinks["T6"] if e.template)
    t7 = next(e.template for e in cat.sinks["T7"] if e.template)
    location = r'"HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n"'
    header = r'"HTTP/1.1 200 OK\r\nX-Request-Id: {}\r\n\r\n"'
    split = '"{header}: "'
    assert re.search(t6, location) and not re.search(t7, location)
    assert re.search(t7, header) and not re.search(t6, header)
    assert re.search(t7, split)
    assert not re.search(t7, r'"{} {} {}\r\n"') and not re.search(t7, '"listening on {addr}"')
