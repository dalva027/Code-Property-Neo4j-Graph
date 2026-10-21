"""Repo browsing is filesystem-only; no Neo4j needed."""
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.config import settings
from app.models.analysis import Project
from app.services.repos import list_repo_dirs


@pytest.fixture
def repos_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "alpha" / "pkg").mkdir(parents=True)
    (tmp_path / "alpha" / "pkg" / "a.py").write_text("x = 1")
    (tmp_path / "alpha" / "README.md").write_text("docs")
    (tmp_path / "alpha" / ".git").mkdir()
    (tmp_path / "alpha" / "node_modules").mkdir()
    (tmp_path / "alpha" / "node_modules" / "dep.py").write_text("ignored = True")
    (tmp_path / "beta").mkdir()
    (tmp_path / "beta" / "main.py").write_text("y = 2")
    (tmp_path / "Empty").mkdir()
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "loose.py").write_text("not a dir")
    monkeypatch.setattr(settings, "repos_root", str(tmp_path))
    return tmp_path


def test_lists_only_browsable_directories(repos_root: Path):
    dirs = list_repo_dirs()

    assert [d.name for d in dirs] == ["alpha", "beta", "Empty"]       # hidden dir and loose file skipped
    alpha, beta, empty = dirs
    assert alpha.path == "alpha"
    assert alpha.source_files == 1                                     # node_modules/dep.py not counted
    assert alpha.has_subdirs is True                                   # pkg/; .git and node_modules don't count
    assert alpha.is_git is True
    assert beta.has_subdirs is False and beta.is_git is False
    assert empty.source_files == 0
    assert all(d.project_id is None for d in dirs)


def test_lists_a_nested_directory(repos_root: Path):
    dirs = list_repo_dirs("alpha")
    assert [d.path for d in dirs] == ["alpha/pkg"]
    assert dirs[0].name == "pkg"


def test_marks_directories_that_are_already_projects(repos_root: Path):
    root = (repos_root / "beta").resolve().as_posix()
    older = Project(id="old1", name="beta-old", root=root, created_at=datetime(2024, 1, 1, tzinfo=UTC))
    newer = Project(id="new1", name="beta", root=root, created_at=datetime(2025, 1, 1, tzinfo=UTC))

    by_name = {d.name: d for d in list_repo_dirs(projects=[newer, older])}   # newest first, like the DB

    assert by_name["beta"].project_id == "new1"
    assert by_name["beta"].project_name == "beta"
    assert by_name["alpha"].project_id is None


def test_rejects_paths_that_escape_or_do_not_exist(repos_root: Path):
    with pytest.raises(HTTPException) as escaped:
        list_repo_dirs("..")
    assert escaped.value.status_code == 400

    with pytest.raises(HTTPException) as missing:
        list_repo_dirs("missing")
    assert missing.value.status_code == 404
