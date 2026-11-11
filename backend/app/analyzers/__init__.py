"""Importing the rule modules runs their @register decorators."""
from app.analyzers import complexity, coupling, crypto, dead_code, dependencies, panics, unsafe_code  # noqa: F401
from app.analyzers.base import REGISTRY, Analyzer

__all__ = ["REGISTRY", "Analyzer"]
