"""Shared test setup.

Unit tests describe the graph the tree-sitter parser builds, so they must not change with the
machine they run on: with `CODEGRAPH_EXTRACTOR` set, `GraphBuilder` would otherwise run
rust-analyzer inside them and resolve calls they expect to stay lexical. Every test therefore runs
with code facts off, except the ones marked `extractor`: the ground-truth harness, which scores
whichever mode the environment configures, and the check that the committed fixtures match the
binary. Tests that overlay committed facts switch the setting on themselves.
"""
import pytest

from app.config import settings


@pytest.fixture(autouse=True)
def _code_facts_off(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("extractor") is None:
        monkeypatch.setattr(settings, "code_facts", "off")
