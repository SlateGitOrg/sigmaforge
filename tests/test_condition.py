from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sigmaforge.condition import (
    CondAnd,
    CondExpr,
    CondNot,
    CondOr,
    CondQuantifier,
    CondRef,
    Tok,
    format_condition,
    parse_condition,
    tokenize,
)
from sigmaforge.errors import SigmaConditionError, UnsupportedFeatureError

A, B, C = CondRef("a"), CondRef("b"), CondRef("c")


def test_tokenize_kinds() -> None:
    kinds = [t.kind for t in tokenize("1 of sel* and not (x or all of them)")]
    assert kinds == [
        Tok.ONE_OF,
        Tok.IDENT,
        Tok.AND,
        Tok.NOT,
        Tok.LPAREN,
        Tok.IDENT,
        Tok.OR,
        Tok.ALL_OF,
        Tok.THEM,
        Tok.RPAREN,
        Tok.END,
    ]


@pytest.mark.parametrize(
    ("text", "tree"),
    [
        ("a", A),
        ("a and b or c", CondOr(CondAnd(A, B), C)),
        ("a or b and c", CondOr(A, CondAnd(B, C))),
        ("not a and b", CondAnd(CondNot(A), B)),
        ("not (a and b)", CondNot(CondAnd(A, B))),
        ("a and (b or c)", CondAnd(A, CondOr(B, C))),
        ("a and b and c", CondAnd(CondAnd(A, B), C)),
        ("NOT a AND b", CondAnd(CondNot(A), B)),
        ("not not a", CondNot(CondNot(A))),
        ("1 of sel*", CondQuantifier("one", "sel*")),
        ("all of them", CondQuantifier("all", None)),
        (
            "1 of them and not 1 of filter_*",
            CondAnd(CondQuantifier("one", None), CondNot(CondQuantifier("one", "filter_*"))),
        ),
        ("((a))", A),
        ("selection-1 and x.y", CondAnd(CondRef("selection-1"), CondRef("x.y"))),
    ],
)
def test_parse(text: str, tree: CondExpr) -> None:
    assert parse_condition(text) == tree


@pytest.mark.parametrize(
    ("text", "message", "column"),
    [
        ("", "empty condition", 1),
        ("a and", "unexpected end", 6),
        ("(a or b", "expected ')'", 8),
        ("a b", "unexpected 'b'", 3),
        ("a )", "unexpected ')'", 3),
        ("1 of", "expected identifier pattern", 5),
        ("1 of (a)", "expected identifier pattern", 6),
        ("sel*", "needs '1 of'", 1),
        ("a & b", "unexpected character '&'", 3),
        ("and a", "unexpected 'and'", 1),
    ],
)
def test_errors_report_position(text: str, message: str, column: int) -> None:
    with pytest.raises(SigmaConditionError, match=re.escape(message)) as info:
        parse_condition(text)
    assert info.value.position == column - 1
    assert f"column {column}" in str(info.value)


def test_aggregation_is_unsupported() -> None:
    with pytest.raises(UnsupportedFeatureError) as info:
        parse_condition("selection | count() by host > 5")
    assert info.value.feature == "aggregation"


names = st.sampled_from(["a", "b", "sel_1", "x-y"])
conditions: st.SearchStrategy[CondExpr] = st.recursive(
    st.one_of(
        names.map(CondRef),
        st.builds(CondQuantifier, st.sampled_from(["one", "all"]), st.none() | names),
    ),
    lambda inner: st.one_of(
        st.builds(CondAnd, inner, inner), st.builds(CondOr, inner, inner), st.builds(CondNot, inner)
    ),
    max_leaves=12,
)


@given(conditions)
def test_format_parse_round_trip(tree: CondExpr) -> None:
    assert parse_condition(format_condition(tree)) == tree
