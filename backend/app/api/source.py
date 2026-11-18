"""Slices of the scanned source files, for the UI's source panel.

Only files the project's graph knows are served (scanned source files, and the Cargo.lock and
Cargo.toml files in the project), read from the project's directory under REPOS_ROOT, which the API
mounts read-only. A path that is absolute, climbs out with `..`, or resolves outside the project
through a symlink is refused.
"""
import asyncio
import re
from pathlib import Path, PurePosixPath

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import RepoDep
from app.models.views import SourceFlag, SourceSlice
from app.services.ingest import require_ready

router = APIRouter(prefix="/projects/{project_id}", tags=["source"])

CARGO_FILES = {"Cargo.toml", "Cargo.lock"}
MAX_LINES = 5000                    # per request; the UI asks for a window around the line it shows
MAX_BYTES = 8 * 1024 * 1024
# A comment that justifies an unsafe operation: `// SAFETY: ...`, `/* Safety ... */`, `/// # Safety`.
_SAFETY_COMMENT = re.compile(r"(//|/\*|^\s*\*).*\bsafety\b", re.IGNORECASE)


def _read_lines(target: Path) -> list[str]:
    if target.stat().st_size > MAX_BYTES:
        raise HTTPException(413, f"file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    return target.read_text(encoding="utf-8", errors="replace").splitlines()


@router.get("/source", response_model=SourceSlice)
async def get_source(
    project_id: str, repo: RepoDep,
    path: str = Query(..., description="file path relative to the project root, as nodes and findings give it"),
    start: int = Query(1, ge=1, description="first line, 1-based"),
    end: int | None = Query(None, ge=1, description=f"last line, inclusive; at most {MAX_LINES} lines are served"),
):
    """Lines `start..end` of one file of the project, with the findings and unsafe spans that touch
    them and the lines that carry a SAFETY comment."""
    project = await repo.get_project(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    require_ready(project)
    relative = PurePosixPath(path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise HTTPException(400, "path must be relative to the project root")
    language = await repo.source_language(project_id, relative.as_posix())
    if language is None and relative.name in CARGO_FILES:
        language = "toml"                     # a manifest the dependency scan did not record
    if language is None:
        raise HTTPException(404, f"{path!r} is not a file of this project")
    root = Path(project.root).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise HTTPException(400, "path resolves outside the project")
    if not target.is_file():
        raise HTTPException(404, f"{path!r} is no longer on disk; rescan the project")

    lines = await asyncio.to_thread(_read_lines, target)
    total = len(lines)
    if end is not None and end < start:
        raise HTTPException(400, "end must not be before start")
    if start > max(total, 1):
        raise HTTPException(400, f"the file has {total} lines")
    last = min(total, end or total, start + MAX_LINES - 1)
    served = lines[start - 1:last]
    flags = await repo.source_flags(project_id, relative.as_posix(), start, max(last, start))
    if language == "rust":
        flags += [SourceFlag(line=n, line_end=n, kind="safety")
                  for n, text in enumerate(served, start) if _SAFETY_COMMENT.search(text)]
    return SourceSlice(path=relative.as_posix(), language=language, start=start, end=last, total_lines=total,
                       lines=served, flags=flags)
