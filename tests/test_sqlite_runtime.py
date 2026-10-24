from __future__ import annotations

import pytest

from sigmaforge.errors import EventDataError
from sigmaforge.sqlite_runtime import (
    ROW_COLUMN,
    connect,
    flatten,
    identifier_key,
    load_events,
    run_query,
)


def test_flatten_nested_events() -> None:
    assert flatten({"a": {"b": 1, "c": {"d": 2}}, "e": [1]}) == {"a.b": 1, "a.c.d": 2, "e": [1]}


def test_load_and_query_keeps_storage_classes() -> None:
    conn = connect()
    events: list[dict[str, object]] = [
        {"n": 4688},
        {"n": "4688"},
        {"b": True, "l": [1, 2]},
        {ROW_COLUMN: "clash"},
    ]
    columns = load_events(conn, events, extra_columns=["extra"])
    assert columns == ["n", "b", "l", "extra"]
    types = [r[0] for r in conn.execute('SELECT typeof("n") FROM events ORDER BY 1')]
    assert types == ["integer", "null", "null", "text"]
    assert run_query(conn, "SELECT * FROM events WHERE \"b\" = 'true'") == [2]
    assert run_query(conn, "SELECT * FROM events WHERE \"l\" = '[1, 2]'") == [2]


def test_helper_functions() -> None:
    conn = connect()
    load_events(conn, [{"ip": "10.1.1.1"}, {"ip": "fe80::1"}, {"ip": "nope"}, {"ip": 7}, {}])
    assert run_query(conn, "SELECT * FROM events WHERE sigma_cidr_match('10.0.0.0/8', ip)") == [0]
    assert run_query(conn, "SELECT * FROM events WHERE sigma_cidr_match('fe80::/10', ip)") == [1]
    assert run_query(conn, "SELECT * FROM events WHERE ip REGEXP '^[0-9]$'") == [3]
    nulls = "SELECT * FROM events WHERE coalesce(ip REGEXP 'x', -1) = -1"
    assert run_query(conn, nulls) == [4]
    blob = "SELECT * FROM events WHERE coalesce(regexp('x', x'00'), -1) = 0"
    assert run_query(conn, blob) == [0, 1, 2, 3, 4]
    blob_cidr = "SELECT * FROM events WHERE sigma_cidr_match('10.0.0.0/8', x'00') = 0"
    assert len(run_query(conn, blob_cidr)) == 5


@pytest.mark.parametrize(
    ("events", "extra"),
    [
        ([{"image": "x"}, {"Image": "x"}], []),  # two events
        ([{"image": "x", "Image": "y"}], []),  # one event
        ([{"Image": "x"}], ["image"]),  # rule field vs event field
        ([{"a": {"B": 1}}, {"a.b": 2}], []),  # through flattening
    ],
)
def test_case_only_collisions_are_rejected(
    events: list[dict[str, object]], extra: list[str]
) -> None:
    with pytest.raises(EventDataError, match="differ only by case"):
        load_events(connect(), events, extra_columns=extra)


def test_identifier_key_folds_ascii_only() -> None:
    # SQLite folds ASCII letters only, so these are distinct columns and must stay loadable.
    assert identifier_key("Image") == identifier_key("IMAGE") == "image"
    assert identifier_key("\u00c9") != identifier_key("\u00e9")
    conn = connect()
    assert load_events(conn, [{"\u00c9": 1}, {"\u00e9": 2}]) == ["\u00c9", "\u00e9"]
    assert run_query(conn, 'SELECT * FROM events WHERE "\u00e9" = 2') == [1]


def test_reserved_row_column_is_dropped_in_any_case() -> None:
    conn = connect()
    assert load_events(conn, [{ROW_COLUMN.upper(): 1, "x": 2}]) == ["x"]
    assert run_query(conn, "SELECT * FROM events") == [0]


def test_cells_hold_what_the_evaluator_looks_up() -> None:
    from sigmaforge.evaluator import MISSING, lookup

    events: list[dict[str, object]] = [
        {"a.b": "literal", "a": {"b": "nested"}},  # literal dotted key wins, as in lookup()
        {"a": {"b": "nested"}, "a.b": "literal"},  # ... whatever the key order
        {"a": {"b": "only-nested"}},
        {"a.b": {"c": 1}},  # flattens to a.b.c, which lookup() cannot reach
    ]
    conn = connect()
    columns = load_events(conn, events)
    assert columns == ["a.b", "a.b.c"]
    cells = conn.execute(f'SELECT "a.b", "a.b.c" FROM events ORDER BY "{ROW_COLUMN}"').fetchall()
    assert cells == [("literal", None), ("literal", None), ("only-nested", None), (None, None)]
    for event, row in zip(events, cells, strict=True):
        for column, got in zip(columns, row, strict=True):
            want = lookup(event, column)
            assert got == (None if want is MISSING or isinstance(want, dict) else want)
