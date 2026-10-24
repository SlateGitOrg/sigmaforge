"""Backend registry."""

from __future__ import annotations

from typing import Any

from sigmaforge.backends.base import Backend, Query
from sigmaforge.backends.eql import EqlBackend
from sigmaforge.backends.kql import KqlBackend
from sigmaforge.backends.splunk import SplunkBackend
from sigmaforge.backends.sqlite import SQLiteBackend
from sigmaforge.errors import SigmaForgeError

BACKENDS: dict[str, type[Backend]] = {
    "splunk": SplunkBackend,
    "eql": EqlBackend,
    "kql": KqlBackend,
    "sql": SQLiteBackend,
}
ALIASES = {"spl": "splunk", "elastic": "eql", "sentinel": "kql", "sqlite": "sql"}


def resolve_backend_name(name: str) -> str:
    key = ALIASES.get(name.lower(), name.lower())
    if key not in BACKENDS:
        raise SigmaForgeError(f"unknown backend {name!r} (known: {', '.join(BACKENDS)})")
    return key


def get_backend(name: str, **options: Any) -> Backend:
    """Instantiate a backend by name or alias; ``options`` go to its constructor."""
    cls = BACKENDS[resolve_backend_name(name)]
    return cls(**options)


__all__ = [
    "ALIASES",
    "BACKENDS",
    "Backend",
    "EqlBackend",
    "KqlBackend",
    "Query",
    "SQLiteBackend",
    "SplunkBackend",
    "get_backend",
    "resolve_backend_name",
]
