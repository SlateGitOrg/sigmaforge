"""Backend unit tests: one construct at a time, exact output strings."""

from __future__ import annotations

from typing import Any

import pytest

from sigmaforge.ast import (
    And,
    CidrMatch,
    CmpMatch,
    Const,
    ExistsMatch,
    FieldMatch,
    KeywordMatch,
    Matcher,
    Node,
    Not,
    NullMatch,
    NumMatch,
    Or,
    RegexMatch,
    StrMatch,
)
from sigmaforge.backends import ALIASES, BACKENDS, Backend, get_backend, resolve_backend_name
from sigmaforge.compiler import CompiledRule
from sigmaforge.errors import SigmaForgeError, UnsupportedFeatureError
from sigmaforge.rule import LogSource, SigmaRule
from sigmaforge.sigmastr import SigmaString

RULE = SigmaRule(title="t", detection={}, conditions=("x",), id="id-1", source="r.yml")


def compiled(node: Node, **state: str) -> CompiledRule:
    return CompiledRule(RULE, node, LogSource(product="windows"), state)


def s(text: str, cased: bool = False) -> StrMatch:
    return StrMatch(SigmaString.parse(text), cased)


def render(backend: str, node: Node, **state: str) -> str:
    return get_backend(backend).convert(compiled(node, **state)).text


def f(name: str, matcher: Matcher) -> FieldMatch:
    return FieldMatch(name, matcher)


# --------------------------------------------------------------------------- registry


def test_registry_and_aliases() -> None:
    for alias, name in ALIASES.items():
        assert resolve_backend_name(alias.upper()) == name
    assert isinstance(get_backend("sqlite"), BACKENDS["sql"])
    with pytest.raises(SigmaForgeError, match="unknown backend"):
        get_backend("nosuch")


def test_query_metadata() -> None:
    q = get_backend("sql").convert(compiled(f("A", s("x"))))
    d = q.as_dict()
    assert d["id"] == "id-1"
    assert d["backend"] == "sql"
    assert d["source"] == "r.yml"
    assert "meta" not in d


# --------------------------------------------------------------------------- SQL


@pytest.mark.parametrize(
    ("node", "where"),
    [
        (f("A", s("x")), "\"A\" LIKE 'x' ESCAPE '\\'"),
        (f("A", s("*50%_\\\\")), "\"A\" LIKE '%50\\%\\_\\\\' ESCAPE '\\'"),
        (f("A", s("a?b")), "\"A\" LIKE 'a_b' ESCAPE '\\'"),
        (f("A", s("it's")), "\"A\" LIKE 'it''s' ESCAPE '\\'"),
        (f("A", s("*")), '"A" IS NOT NULL'),
        (f("A", s("a*[b]\\?", cased=True)), "\"A\" GLOB 'a*[[]b][?]'"),
        (f("A", RegexMatch("x+", frozenset({"s", "i"}))), "\"A\" REGEXP '(?is)x+'"),
        (f("A", CidrMatch("10.0.0.0/8")), "sigma_cidr_match('10.0.0.0/8', \"A\")"),
        (f("A", NumMatch(-3)), "CAST(\"A\" AS TEXT) = '-3'"),
        (f("A", CmpMatch("lte", 2.5)), "(typeof(\"A\") IN ('integer', 'real') AND \"A\" <= 2.5)"),
        (f("A", NullMatch()), '"A" IS NULL'),
        (f("A", ExistsMatch(True)), '"A" IS NOT NULL'),
        (f("A", ExistsMatch(False)), '"A" IS NULL'),
        (f('we"ird', s("x")), "\"we\"\"ird\" LIKE 'x' ESCAPE '\\'"),
        (Not(f("A", NullMatch())), 'NOT coalesce("A" IS NULL, 0)'),
        (
            Or((And((f("A", NullMatch()), f("B", NullMatch()))), f("C", NullMatch()))),
            '"A" IS NULL AND "B" IS NULL OR "C" IS NULL',
        ),
        (
            And((Or((f("A", NullMatch()), f("B", NullMatch()))), f("C", NullMatch()))),
            '("A" IS NULL OR "B" IS NULL) AND "C" IS NULL',
        ),
        (Const(True), "1"),
    ],
)
def test_sql(node: Node, where: str) -> None:
    assert render("sql", node) == f'SELECT * FROM "events" WHERE {where}'


def test_sql_table_state_keywords_and_errors() -> None:
    assert render("sql", f("A", NullMatch()), sql_table="t x").startswith('SELECT * FROM "t x"')
    kw = KeywordMatch(s("*x*"))
    backend = get_backend("sql", keyword_columns=["A", "B"])
    text = backend.convert(compiled(kw)).text
    assert text.endswith("(\"A\" LIKE '%x%' ESCAPE '\\' OR \"B\" LIKE '%x%' ESCAPE '\\')")
    single = get_backend("sql", keyword_columns=["A"]).convert(compiled(kw)).text
    assert single.endswith("WHERE \"A\" LIKE '%x%' ESCAPE '\\'")
    with pytest.raises(UnsupportedFeatureError) as info:
        render("sql", kw)
    assert info.value.feature == "keyword search"
    assert info.value.backend == "sql"
    with pytest.raises(UnsupportedFeatureError, match="NUL"):
        render("sql", f("A", s("a\x00")))
    with pytest.raises(UnsupportedFeatureError, match=r"not valid for Python re"):
        render("sql", f("A", RegexMatch("(?<bad")))


# --------------------------------------------------------------------------- Splunk


@pytest.mark.parametrize(
    ("node", "query"),
    [
        (f("A", s("x")), 'A="x"'),
        (f("A", s('*C:\\a"b*')), 'A="*C:\\\\a\\"b*"'),
        (f("A", s("x", cased=True)), 'A=CASE("x")'),
        (f("process.name", s("x")), 'process.name="x"'),
        (f("a b", s("x")), '"a b"="x"'),
        (f("A", CidrMatch("10.0.0.0/8")), 'A="10.0.0.0/8"'),
        (f("A", NumMatch(4)), "A=4"),
        (f("A", CmpMatch("gt", 4)), "A>4"),
        (f("A", NullMatch()), "NOT A=*"),
        (f("A", ExistsMatch(True)), "A=*"),
        (f("A", ExistsMatch(False)), "NOT A=*"),
        (KeywordMatch(s("*evil*")), '"*evil*"'),
        (KeywordMatch(s("*Evil*", cased=True)), 'CASE("*Evil*")'),
        (Or((f("A", s("x")), f("A", s("y")), f("B", s("z")))), 'A IN ("x", "y") OR B="z"'),
        (Or((f("A", s("x", True)), f("A", s("y", True)))), 'A=CASE("x") OR A=CASE("y")'),
        # SPL search: OR binds tighter than AND, so AND inside OR is parenthesised
        (
            Or((And((f("A", NumMatch(1)), f("B", NumMatch(2)))), f("C", NumMatch(3)))),
            "(A=1 AND B=2) OR C=3",
        ),
        (Not(Or((f("A", NumMatch(1)), f("B", NumMatch(2))))), "NOT (A=1 OR B=2)"),
    ],
)
def test_splunk_search_terms(node: Node, query: str) -> None:
    assert render("splunk", node) == query


@pytest.mark.parametrize(
    ("node", "query"),
    [
        (f("A", RegexMatch("a\\d", frozenset({"i"}))), '* | where match(A, "(?i)a\\\\d")'),
        (f("A", s("a?b")), '* | where match(A, "(?is)^a.b\\\\z")'),
        (f("A", StrMatch(SigmaString.literal("5*3"))), '* | where match(A, "(?is)^5\\\\*3\\\\z")'),
        (f("a.b", s("x?", cased=True)), "* | where match('a.b', \"(?s)^x.\\\\z\")"),
        (
            And((f("A", NumMatch(1)), f("B", RegexMatch("z")))),
            'A=1 | where match(B, "z")',
        ),
        (
            And((f("A", RegexMatch("y")), f("B", RegexMatch("z")))),
            '* | where match(A, "y") AND match(B, "z")',
        ),
        (
            And((Or((f("A", s("x")), f("B", RegexMatch("z")))), f("C", NumMatch(1)))),
            'C=1 | where match(A, "(?is)^x\\\\z") OR match(B, "z")',
        ),
        (
            And((Not(f("A", RegexMatch("z"))), f("C", NumMatch(1)))),
            'C=1 | where (isnull(A) OR NOT match(A, "z"))',
        ),
        (
            And(
                (
                    f("R", RegexMatch("r")),
                    Or((f("A", s("*")), f("B", CidrMatch("::1/128")), f("C", NullMatch()))),
                )
            ),
            'A=* OR B="::1/128" OR NOT C=* | where match(R, "r")',
        ),
        (
            And(
                (
                    f("R", RegexMatch("r")),
                    Or(
                        (
                            f("A", s("a?")),
                            f("B", CidrMatch("::1/128")),
                            f("C", NullMatch()),
                            f("D", NumMatch(1)),
                            f("E", CmpMatch("lt", 2)),
                            f("F", ExistsMatch(False)),
                            f("G", s("*")),
                        )
                    ),
                )
            ),
            '* | where match(R, "r") AND (match(A, "(?is)^a.\\\\z") OR cidrmatch("::1/128", B) '
            "OR isnull(C) OR D==1 OR E<2 OR isnull(F) OR isnotnull(G))",
        ),
        (KeywordMatch(RegexMatch("ev+il")), '* | where match(_raw, "ev+il")'),
        (KeywordMatch(s("*e?il*")), '* | where match(_raw, "(?is)^.*e.il.*\\\\z")'),
    ],
)
def test_splunk_where_clause(node: Node, query: str) -> None:
    assert render("splunk", node) == query


def test_splunk_prefix_state() -> None:
    text = render("splunk", f("A", RegexMatch("x")), splunk_prefix='source="S"')
    assert text == 'source="S" | where match(A, "x")'


# --------------------------------------------------------------------------- EQL


@pytest.mark.parametrize(
    ("node", "query"),
    [
        (f("A", s("x")), 'A : "x"'),
        (f("A", s("x", cased=True)), 'A == "x"'),
        (f("A", s("*x?y")), 'A like~ "*x?y"'),
        (f("A", s("*x", cased=True)), 'A like "*x"'),
        (f("A", StrMatch(SigmaString.literal("5*3"))), 'A regex~ "5\\\\*3"'),
        (f("A", StrMatch(SigmaString.parse("*a\\?"), cased=True)), 'A regex ".*a\\\\?"'),
        (f("A", s("*")), "A != null"),
        (f("A", s('a"\\\n')), 'A : "a\\"\\\\\\n"'),
        (f("we ird", s("x")), '`we ird` : "x"'),
        (f("A", RegexMatch("^a\\d+$")), 'A regex "a[0-9]+"'),
        (f("A", RegexMatch("(?i)b")), 'A regex~ ".*b.*"'),
        (f("A", RegexMatch("b", frozenset({"i"}))), 'A regex~ ".*b.*"'),
        (f("A", CidrMatch("10.0.0.0/8")), 'cidrMatch(A, "10.0.0.0/8")'),
        (f("A", NumMatch(4)), "A == 4"),
        (f("A", CmpMatch("gte", 4)), "A >= 4"),
        (f("A", NullMatch()), "A == null"),
        (f("A", ExistsMatch(True)), "A != null"),
        (f("A", ExistsMatch(False)), "A == null"),
        (Or((f("A", s("x")), f("A", s("y")))), 'A in~ ("x", "y")'),
        (Or((f("A", s("x", True)), f("A", s("y", True)))), 'A in ("x", "y")'),
        (
            Or((f("A", StrMatch(SigmaString.literal("*"))), f("A", s("y")))),
            'A regex~ "\\\\*" or A : "y"',
        ),
        (Not(And((f("A", NumMatch(1)), f("B", NumMatch(2))))), "not (A == 1 and B == 2)"),
    ],
)
def test_eql(node: Node, query: str) -> None:
    assert render("eql", node) == f"any where {query}"


def test_eql_category_and_keywords() -> None:
    assert render("eql", f("A", NumMatch(1)), eql_category="process") == "process where A == 1"
    with pytest.raises(UnsupportedFeatureError) as info:
        render("eql", KeywordMatch(s("*x*")))
    assert info.value.feature == "keyword search"


# --------------------------------------------------------------------------- KQL


@pytest.mark.parametrize(
    ("node", "query"),
    [
        (f("A", s("x")), 'A =~ "x"'),
        (f("A", s("x", cased=True)), 'A == "x"'),
        (f("A", s("*x*")), 'A contains "x"'),
        (f("A", s("*x*", cased=True)), 'A contains_cs "x"'),
        (f("A", s("x*")), 'A startswith "x"'),
        (f("A", s("*x")), 'A endswith "x"'),
        (f("A", s("*x", cased=True)), 'A endswith_cs "x"'),
        (f("A", s("a*b")), 'A matches regex "(?is)^a.*b\\\\z"'),
        (f("A", s("a?b", cased=True)), 'A matches regex "(?s)^a.b\\\\z"'),
        (f("A", s("*")), "isnotempty(A)"),
        (f("A", s('C:\\"x"')), 'A =~ "C:\\\\\\"x\\""'),
        (f("process.name", s("x")), "['process.name'] =~ \"x\""),
        (f("A", RegexMatch("a\\d", frozenset({"m", "i"}))), 'A matches regex "(?im)a\\\\d"'),
        (f("A", CidrMatch("10.0.0.0/8")), 'ipv4_is_in_range(A, "10.0.0.0/8")'),
        (f("A", CidrMatch("2001:db8::/32")), 'ipv6_is_in_range(A, "2001:db8::/32")'),
        (f("A", NumMatch(4)), "A == 4"),
        (f("A", CmpMatch("lt", 4)), "A < 4"),
        (f("A", NullMatch()), "isempty(A)"),
        (f("A", ExistsMatch(True)), "isnotempty(A)"),
        (f("A", ExistsMatch(False)), "isempty(A)"),
        (Or((f("A", s("x")), f("A", s("y")))), 'A in~ ("x", "y")'),
        (Or((f("A", s("x", True)), f("A", s("y", True)))), 'A in ("x", "y")'),
        (Not(Or((f("A", NumMatch(1)), f("B", NumMatch(2))))), "not(A == 1 or B == 2)"),
    ],
)
def test_kql(node: Node, query: str) -> None:
    assert render("kql", node, kql_table="T") == f"T\n| where {query}"


@pytest.mark.parametrize(
    ("node", "feature"),
    [
        (f("A", RegexMatch("(?<=a)b")), "regex look-around (RE2)"),
        (f("A", RegexMatch("(a)\\1")), "regex back-reference (RE2)"),
        (KeywordMatch(s("*x*")), "keyword search"),
    ],
)
def test_kql_unsupported(node: Node, feature: str) -> None:
    with pytest.raises(UnsupportedFeatureError) as info:
        render("kql", node, kql_table="T")
    assert info.value.feature == feature


def test_kql_requires_table() -> None:
    with pytest.raises(UnsupportedFeatureError, match="product=windows") as info:
        render("kql", f("A", NumMatch(1)))
    assert info.value.feature == "no KQL table for logsource"


# --------------------------------------------------------------------------- shared


@pytest.mark.parametrize("name", ["splunk", "eql", "kql"])
def test_constants_are_rejected_by_text_backends(name: str) -> None:
    with pytest.raises(UnsupportedFeatureError, match="constant"):
        render(name, Const(False), kql_table="T")


@pytest.mark.parametrize("name", list(BACKENDS))
def test_every_backend_handles_every_matcher_kind(name: str) -> None:
    matchers: list[Any] = [
        s("a"),
        s("*a*"),
        s("a*b"),
        RegexMatch("a"),
        CidrMatch("10.0.0.0/8"),
        NumMatch(1),
        CmpMatch("gt", 1),
        NullMatch(),
        ExistsMatch(True),
    ]
    node = And(tuple(f(f"F{i}", m) for i, m in enumerate(matchers)))
    backend: Backend = get_backend(name)
    text = backend.convert(compiled(node, kql_table="T")).text
    assert all(f"F{i}" in text for i in range(len(matchers)))
