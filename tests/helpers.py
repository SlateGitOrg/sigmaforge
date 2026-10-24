"""Small helpers shared by the test modules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def subtree_disagreements(node: Any, events: list[dict[str, Any]], columns: list[str]) -> list[str]:
    """Compare *every* subtree of ``node`` between SQLite and the evaluator, on every event.

    One SELECT computes each subtree as its own column (``coalesce(<expr>, 0)`` turns SQL NULL
    into the "false" that Sigma semantics prescribe), so a wrong leaf is caught even when the
    rest of the rule would have masked it. Returns human-readable descriptions of mismatches.
    """
    from sigmaforge.ast import to_sexpr, walk
    from sigmaforge.backends.sqlite import SQLiteBackend
    from sigmaforge.evaluator import evaluate
    from sigmaforge.sqlite_runtime import ROW_COLUMN, connect, load_events

    backend = SQLiteBackend(keyword_columns=columns)
    subtrees = list(dict.fromkeys(walk(node)))
    select = ", ".join(f"coalesce({backend.render(t)}, 0)" for t in subtrees)
    conn = connect()
    try:
        load_events(conn, events, extra_columns=columns)
        rows = conn.execute(f'SELECT {select} FROM events ORDER BY "{ROW_COLUMN}"').fetchall()
    finally:
        conn.close()
    problems = []
    for event, row in zip(events, rows, strict=True):
        for subtree, got in zip(subtrees, row, strict=True):
            want = evaluate(subtree, event)
            if bool(got) != want:
                problems.append(f"{to_sexpr(subtree)} on {event!r}: sql={got} evaluator={want}")
    return problems
