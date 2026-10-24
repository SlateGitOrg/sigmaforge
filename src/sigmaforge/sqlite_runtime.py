"""Load JSON events into SQLite and run queries produced by the SQL backend.

The table is deliberately untyped (no declared column types, hence no type affinity): a string
``"4688"`` and an integer ``4688`` stay distinct, exactly as in the source events. Nested
objects are flattened to dotted column names (``process.name``), and each cell holds exactly what
the evaluator's :func:`~sigmaforge.evaluator.lookup` resolves for that column, so an event with
both a literal ``"a.b"`` key and a nested ``{"a": {"b": ...}}`` stores the literal key's value,
as the evaluator does. Lists are stored as JSON text; the reference evaluator matches list
*elements*, so rules over list-valued fields can disagree between the two (documented limitation;
the differential generators avoid lists).

SQLite identifiers are case-insensitive (ASCII only) while event fields are case-sensitive, so
two columns that differ only by ASCII case (``Image`` and ``image``, from the events or from the
rule's fields passed as ``extra_columns``) cannot both exist: :func:`load_events` raises
:class:`~sigmaforge.errors.EventDataError` instead of letting one silently stand in for the
other. A field named like the reserved row-index column is dropped.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sigmaforge.backends.sqlite import quote_ident
from sigmaforge.errors import EventDataError
from sigmaforge.evaluator import MISSING, lookup, value_text

ROW_COLUMN = "__sigmaforge_row"


def _regexp(pattern: str, value: Any) -> int | None:
    if value is None:
        return None
    text = value_text(value)
    if text is None:
        return 0
    return 1 if re.search(pattern, text) else 0


def _cidr_match(network: str, value: Any) -> int | None:
    if value is None:
        return None
    text = value_text(value)
    if text is None:
        return 0
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return 0
    net = ipaddress.ip_network(network)
    return 1 if address.version == net.version and address in net else 0


def connect(database: str = ":memory:") -> sqlite3.Connection:
    """Open SQLite with the ``REGEXP`` operator and ``sigma_cidr_match`` registered."""
    conn = sqlite3.connect(database)
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    conn.create_function("sigma_cidr_match", 2, _cidr_match, deterministic=True)
    return conn


def flatten(event: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in event.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            out.update(flatten(value, f"{name}."))
        else:
            out[name] = value
    return out


def _storage_value(value: Any) -> Any:
    if value is MISSING or isinstance(value, Mapping):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None or isinstance(value, str | int | float):
        return value
    return json.dumps(value, sort_keys=True)


def identifier_key(name: str) -> str:
    """How SQLite compares identifiers: case-insensitive for ASCII letters only."""
    return "".join(c.lower() if c.isascii() else c for c in name)


def load_events(
    conn: sqlite3.Connection,
    events: Sequence[Mapping[str, Any]],
    table: str = "events",
    extra_columns: Iterable[str] = (),
) -> list[str]:
    """Create ``table`` holding ``events``; returns the field columns in creation order.

    Raises :class:`~sigmaforge.errors.EventDataError` when two column names differ only by
    ASCII case, which SQLite cannot represent as distinct columns.
    """
    columns: dict[str, str] = {}  # identifier_key -> first spelling seen
    reserved = identifier_key(ROW_COLUMN)
    for name in [*(n for e in events for n in flatten(e)), *extra_columns]:
        key = identifier_key(name)
        if key == reserved:
            continue
        seen = columns.setdefault(key, name)
        if seen != name:
            raise EventDataError(
                f"fields {seen!r} and {name!r} differ only by case; SQLite column names are "
                "case-insensitive, so they cannot be loaded side by side"
            )
    names = list(columns.values())
    col_sql = "".join(f", {quote_ident(c)}" for c in names)
    conn.execute(f"DROP TABLE IF EXISTS {quote_ident(table)}")
    conn.execute(f"CREATE TABLE {quote_ident(table)} ({quote_ident(ROW_COLUMN)} INTEGER{col_sql})")
    placeholders = ", ".join("?" for _ in range(len(names) + 1))
    conn.executemany(
        f"INSERT INTO {quote_ident(table)} VALUES ({placeholders})",
        [[i, *(_storage_value(lookup(e, c)) for c in names)] for i, e in enumerate(events)],
    )
    return names


def run_query(conn: sqlite3.Connection, query: str) -> list[int]:
    """Run a backend query and return the matching event indices, ascending."""
    sql = f"SELECT {quote_ident(ROW_COLUMN)} FROM ({query}) ORDER BY 1"
    return [int(row[0]) for row in conn.execute(sql)]
