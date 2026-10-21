"""Browse the directories under REPOS_ROOT so the UI can offer them as scan targets.

Pure filesystem work, no database: project matching is done against whatever
`Project`s the caller passes in, which keeps this unit-testable without Neo4j.
"""
import os
from collections.abc import Iterable
from pathlib import Path

from fastapi import HTTPException

from app.config import settings
from app.graph.builder import IGNORED_DIRS
from app.graph.parsers import parser_for
from app.models.analysis import Project, RepoDir
from app.services.ingest import resolve_repo_path


def _browsable(entry: os.DirEntry) -> bool:
    """Directories worth showing: real folders that are neither hidden nor build/VCS noise."""
    return (
        entry.is_dir(follow_symlinks=True)
        and not entry.name.startswith(".")
        and entry.name not in IGNORED_DIRS
    )


def _count_source_files(root: Path) -> int:
    """Mirror GraphBuilder's walk so the count matches what a scan will actually parse."""
    count = 0
    for _, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        count += sum(1 for f in filenames if parser_for(Path(f)) is not None)
    return count


def _has_browsable_subdirs(path: Path) -> bool:
    with os.scandir(path) as it:
        return any(_browsable(e) for e in it)


def list_repo_dirs(relative: str = "", projects: Iterable[Project] = ()) -> list[RepoDir]:
    """Immediate subdirectories of REPOS_ROOT/<relative>, alphabetical.

    `projects` should be newest-first (as `GraphRepository.list_projects` returns them); when
    several projects point at the same directory the newest one is reported.
    """
    root = Path(settings.repos_root).resolve()
    if not root.is_dir():
        # Spell this out: the generic "'' is not a directory" from resolve_repo_path is baffling here.
        raise HTTPException(503, f"REPOS_ROOT {root.as_posix()} does not exist; check the REPOS_ROOT setting")
    base = resolve_repo_path(relative)

    by_root: dict[str, Project] = {}
    for project in projects:
        by_root.setdefault(project.root, project)

    dirs: list[RepoDir] = []
    with os.scandir(base) as it:
        for entry in sorted(it, key=lambda e: e.name.lower()):
            if not _browsable(entry):
                continue
            path = Path(entry.path)
            project = by_root.get(path.resolve().as_posix())
            dirs.append(
                RepoDir(
                    name=entry.name,
                    path=path.relative_to(root).as_posix(),
                    source_files=_count_source_files(path),
                    has_subdirs=_has_browsable_subdirs(path),
                    is_git=(path / ".git").exists(),
                    project_id=project.id if project else None,
                    project_name=project.name if project else None,
                )
            )
    return dirs
