"""Importing the rule modules runs their @register decorators."""
from app.analyzers import (  # noqa: F401
    complexity,
    coupling,
    crypto,
    dead_code,
    dependencies,
    panics,
    taint,
    unsafe_code,
)
from app.analyzers.base import REGISTRY, Analyzer

__all__ = ["REGISTRY", "Analyzer"]
