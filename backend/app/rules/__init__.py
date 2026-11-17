"""The rule catalogue: sources, sinks, sanitizers and patterns the security analyzers read.

The data lives in the YAML files next to this module; `catalogue.yaml` lists them and carries the
catalogue version. `load_catalogue()` validates everything once and caches the result, so a broken
catalogue fails at startup rather than in the middle of an analysis run.
"""
import hashlib
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

CATALOGUE_DIR = Path(__file__).parent
MANIFEST = "catalogue.yaml"

_SEGMENT = r"(?:[A-Za-z_][A-Za-z0-9_]*|\*)"
_PATH = re.compile(rf"^(?:\?|{_SEGMENT})(?:::{_SEGMENT})*!?$")
_BRACES = re.compile(r"\{([^{}]+)\}")
_RULE_ID = re.compile(r"^[UPTDC][0-9]+$")


class CatalogueError(ValueError):
    """The catalogue files are missing, malformed or inconsistent."""


def expand_braces(path: str) -> list[str]:
    """`std::fs::{read,write}` -> ["std::fs::read", "std::fs::write"]; nested groups are not supported."""
    match = _BRACES.search(path)
    if match is None:
        return [path]
    head, tail = path[:match.start()], path[match.end():]
    return [p for name in match.group(1).split(",") for p in expand_braces(f"{head}{name.strip()}{tail}")]


def _compile(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"not a regular expression: {pattern!r} ({exc})") from exc


class PatternEntry(BaseModel):
    path: str
    # call: a function/method path; type: a type or constant path (used as a parameter type, an
    # implemented trait or a value); derive: a derive macro; crate: any item of that crate;
    # guard: a check on a variable rather than a call on the data path. The last segment names the
    # check: a bool-returning method (`?::starts_with`) or `ops::cmp`, `ops::eq`, `ops::match`.
    kind: Literal["call", "type", "derive", "crate", "guard"] = "call"
    args: list[int] | None = None         # 0-based argument positions that matter, receiver excluded
    receiver: bool = False                # the receiver itself carries the data
    # Smallest acceptable literal value per argument index, e.g. {2: 100000} for PBKDF2 rounds.
    min: dict[int, int] | None = None
    # For a format-like macro (`std::write!`): a regular expression the format string must match,
    # e.g. a `Location:` header. The call is only a sink when it does.
    template: str | None = None
    # Conditions on other arguments: {index: regular expression} over the argument when it is a
    # literal or a constant passed by name, e.g. {0: "(?i)location"} for `.header(LOCATION, v)`.
    when: dict[int, str] | None = None
    note: str | None = None

    @field_validator("path")
    @classmethod
    def _valid_path(cls, value: str) -> str:
        if not _PATH.match(value):
            raise ValueError(f"not a Rust path pattern: {value!r}")
        return value

    @field_validator("template")
    @classmethod
    def _valid_template(cls, value: str | None) -> str | None:
        if value is not None:
            _compile(value)
        return value

    @field_validator("when")
    @classmethod
    def _valid_when(cls, value: dict[int, str] | None) -> dict[int, str] | None:
        for pattern in (value or {}).values():
            _compile(pattern)
        return value

    @property
    def is_macro(self) -> bool:
        return self.path.endswith("!")

    @property
    def last(self) -> str:
        return self.path.rsplit("::", 1)[-1]

    def matches(self, path: str) -> bool:
        """Does a called path match? `*` stands for exactly one segment; `?::m` matches any receiver;
        a `crate` entry matches every path into that crate."""
        want, got = self.path.split("::"), path.split("::")
        if self.kind == "crate":
            return got[0] == want[0] and got[0] != "?"
        if want[0] == "?":
            return len(got) >= 1 and got[-1] == want[-1]
        return len(want) == len(got) and all(w in ("*", g) for w, g in zip(want, got, strict=True))


class Match(BaseModel):
    section: str                          # sources | sinks | sanitizers | dangerous_ops | weak_crypto
    group: str                            # the key inside the section, e.g. "memory" or "T1"
    entry: PatternEntry


class PathMatcher:
    """Every catalogue entry at once, indexed by last path segment so a lookup is cheap."""

    def __init__(self, catalogue: "Catalogue"):
        self._by_last: dict[str, list[Match]] = {}
        self._open: list[Match] = []      # entries whose last segment is `*` or that match a crate
        for section in ("sources", "sinks", "sanitizers", "dangerous_ops", "weak_crypto"):
            for group, entries in getattr(catalogue, section).items():
                for entry in entries:
                    if entry.kind == "guard":
                        continue                  # a check on a variable, not a path anything calls
                    match = Match(section=section, group=group, entry=entry)
                    last = entry.path.split("::")[-1]
                    if entry.kind == "crate" or last == "*":
                        self._open.append(match)
                    else:
                        self._by_last.setdefault(last, []).append(match)

    def match(self, path: str, section: str | None = None) -> list[Match]:
        last = path.split("::")[-1]
        candidates = self._by_last.get(last, []) + self._open
        return [m for m in candidates if (section is None or m.section == section) and m.entry.matches(path)]

    def matches(self, path: str, section: str | None = None) -> bool:
        return bool(self.match(path, section))


class SecretPatterns(BaseModel):
    identifiers: list[str]
    formats: dict[str, str]
    min_entropy: float = Field(gt=0)
    min_length: int = Field(gt=0)
    # Variable names for the flow forms of the crypto rules: a password being hashed (C1, C2) and
    # key material an RNG's output ends up in (C3).
    passwords: list[str] = Field(default_factory=list)
    key_material: list[str] = Field(default_factory=list)

    @field_validator("identifiers", "passwords", "key_material")
    @classmethod
    def _compile_identifiers(cls, value: list[str]) -> list[str]:
        for pattern in value:
            re.compile(pattern)
        return value

    @field_validator("formats")
    @classmethod
    def _compile_formats(cls, value: dict[str, str]) -> dict[str, str]:
        for pattern in value.values():
            re.compile(pattern)
        return value


class Catalogue(BaseModel):
    version: str
    digest: str
    sources: dict[str, list[PatternEntry]] = Field(default_factory=dict)
    sinks: dict[str, list[PatternEntry]] = Field(default_factory=dict)
    sanitizers: dict[str, list[PatternEntry]] = Field(default_factory=dict)
    dangerous_ops: dict[str, list[PatternEntry]] = Field(default_factory=dict)
    weak_crypto: dict[str, list[PatternEntry]] = Field(default_factory=dict)
    secrets: SecretPatterns | None = None

    @field_validator("sinks", "sanitizers")
    @classmethod
    def _keyed_by_rule(cls, value: dict[str, list[PatternEntry]]) -> dict[str, list[PatternEntry]]:
        bad = [key for key in value if not _RULE_ID.match(key)]
        if bad:
            raise ValueError(f"keys must be rule ids such as T1 or U3, got {bad}")
        return value

    def matcher(self) -> PathMatcher:
        return PathMatcher(self)

    def guards(self, rule_id: str) -> list[str]:
        """Names of the checks that sanitize a variable for one rule (`starts_with`, `cmp`, ...)."""
        return sorted({e.last for e in self.sanitizers.get(rule_id, []) if e.kind == "guard"})


_SECTIONS = ("sources", "sinks", "sanitizers", "dangerous_ops", "weak_crypto", "secrets")


def _expand_section(groups: dict) -> dict:
    """Expand brace groups in every entry path of a {group: [entries]} section."""
    out: dict[str, list[dict]] = {}
    for group, entries in (groups or {}).items():
        expanded: list[dict] = []
        for entry in entries or []:
            if not isinstance(entry, dict) or "path" not in entry:
                raise CatalogueError(f"entry in {group!r} needs a path: {entry!r}")
            expanded.extend({**entry, "path": p} for p in expand_braces(str(entry["path"])))
        out[group] = expanded
    return out


def load_catalogue_from(directory: Path) -> Catalogue:
    manifest_path = directory / MANIFEST
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogueError(f"cannot read {manifest_path}: {exc}") from exc

    digest = hashlib.sha256()
    data: dict = {"version": str(manifest.get("version", ""))}
    if not data["version"]:
        raise CatalogueError(f"{manifest_path} has no version")
    for name in [MANIFEST, *sorted(manifest.get("files", []))]:
        path = directory / name
        try:
            raw = path.read_bytes()
            content = yaml.safe_load(raw) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise CatalogueError(f"cannot read {path}: {exc}") from exc
        digest.update(name.encode() + b"\0" + raw + b"\0")
        if name == MANIFEST:
            continue
        for section, value in content.items():
            if section not in _SECTIONS:
                raise CatalogueError(f"{name}: unknown section {section!r}")
            if section in data:
                raise CatalogueError(f"{name}: section {section!r} is defined twice")
            data[section] = value if section == "secrets" else _expand_section(value)

    data["digest"] = digest.hexdigest()
    try:
        return Catalogue(**data)
    except ValidationError as exc:
        raise CatalogueError(str(exc)) from exc


@lru_cache(maxsize=1)
def load_catalogue() -> Catalogue:
    return load_catalogue_from(CATALOGUE_DIR)


__all__ = ["Catalogue", "CatalogueError", "Match", "PathMatcher", "PatternEntry", "SecretPatterns",
           "expand_braces", "load_catalogue", "load_catalogue_from"]
