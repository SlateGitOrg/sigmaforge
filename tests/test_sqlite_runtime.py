from __future__ import annotations

from sigmaforge.sqlite_runtime import ROW_COLUMN, connect, flatten, load_events, run_query


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
