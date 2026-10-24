"""Load JSON events into SQLite and run queries produced by the SQL backend.

The table is deliberately untyped (no declared column types, hence no type affinity): a string
``"4688"`` and an integer ``4688`` stay distinct, exactly as in the source events. Nested
objects are flattened to dotted column names (``process.name``). Lists are stored as JSON text;
the reference evaluator matches list *elements*, so rules over list-valued fields can disagree
between the two (documented limitation; the differential generators avoid lists).
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sigmaforge.backends.sqlite import quote_ident
from sigmaforge.evaluator import value_text

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
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None or isinstance(value, str | int | float):
        return value
    return json.dumps(value, sort_keys=True)


def load_events(
    conn: sqlite3.Connection,
    events: Sequence[Mapping[str, Any]],
    table: str = "events",
    extra_columns: Iterable[str] = (),
) -> list[str]:
    """Create ``table`` holding ``events``; returns the field columns in creation order."""
    flat = [flatten(e) for e in events]
    columns: dict[str, None] = {}
    for row in flat:
        for name in row:
            columns.setdefault(name, None)
    for name in extra_columns:
        columns.setdefault(name, None)
    columns.pop(ROW_COLUMN, None)
    names = list(columns)
    col_sql = "".join(f", {quote_ident(c)}" for c in names)
    conn.execute(f"DROP TABLE IF EXISTS {quote_ident(table)}")
    conn.execute(f"CREATE TABLE {quote_ident(table)} ({quote_ident(ROW_COLUMN)} INTEGER{col_sql})")
    placeholders = ", ".join("?" for _ in range(len(names) + 1))
    conn.executemany(
        f"INSERT INTO {quote_ident(table)} VALUES ({placeholders})",
        [[i, *(_storage_value(row.get(c)) for c in names)] for i, row in enumerate(flat)],
    )
    return names


def run_query(conn: sqlite3.Connection, query: str) -> list[int]:
    """Run a backend query and return the matching event indices, ascending."""
    sql = f"SELECT {quote_ident(ROW_COLUMN)} FROM ({query}) ORDER BY 1"
    return [int(row[0]) for row in conn.execute(sql)]
