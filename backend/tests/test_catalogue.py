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
