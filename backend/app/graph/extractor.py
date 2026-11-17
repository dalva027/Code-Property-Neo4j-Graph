"""Locating and running `codegraph-extract`, shared by the dependency scan and the code facts."""
import os
import shutil
import subprocess
from pathlib import Path

from app.config import settings


class ExtractorUnavailable(RuntimeError):
    """The extractor binary is not installed or could not produce facts."""


def extractor_path() -> str | None:
    configured = settings.codegraph_extractor
    if os.sep in configured or "/" in configured:
        return configured if Path(configured).is_file() else None
    return shutil.which(configured)


def run(args: list[str], timeout: int) -> str:
    """Run the extractor with `args` and return its stdout; any failure is ExtractorUnavailable."""
    binary = extractor_path()
    if binary is None:
        raise ExtractorUnavailable(f"{settings.codegraph_extractor} not found")
    try:
        done = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExtractorUnavailable(f"running {binary}: {exc}") from exc
    if done.returncode != 0:
        raise ExtractorUnavailable(f"{binary} exited {done.returncode}: {done.stderr.strip()[-500:]}")
    return done.stdout
