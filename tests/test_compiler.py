from __future__ import annotations

from typing import Any

import pytest

from sigmaforge.ast import (
    And,
    Const,
    FieldMatch,
    KeywordMatch,
    Node,
    Not,
    NumMatch,
    Or,
    StrMatch,
    fields,
    to_sexpr,
    walk,
)
from sigmaforge.compiler import compile_detection, compile_rule, compile_search_identifier
from sigmaforge.errors import SigmaConditionError, SigmaModifierError, SigmaRuleError
from sigmaforge.optimize import simplify
from sigmaforge.rule import rule_from_dict
from sigmaforge.sigmastr import SigmaString


def eq(field: str, value: str) -> FieldMatch:
    return FieldMatch(field, StrMatch(SigmaString.parse(value)))


def rule(detection: dict[str, Any]) -> Any:
    return rule_from_dict({"title": "t", "detection": detection})


def test_mapping_is_and_list_of_mappings_is_or() -> None:
    assert compile_search_identifier({"A": "1", "B": "2"}) == And((eq("A", "1"), eq("B", "2")))
    assert compile_search_identifier([{"A": "1"}, {"B": "2"}]) == Or((eq("A", "1"), eq("B", "2")))
    assert compile_search_identifier([{"A": "1"}]) == eq("A", "1")


def test_keywords_are_substring_searches() -> None:
    node = compile_search_identifier(["evil", 42])
    assert node == Or(
        (
            KeywordMatch(StrMatch(SigmaString.parse("*evil*"))),
            KeywordMatch(StrMatch(SigmaString.parse("*42*"))),
        )
    )
    assert compile_search_identifier("x") == KeywordMatch(StrMatch(SigmaString.parse("*x*")))


@pytest.mark.parametrize(
    ("value", "error", "message"),
    [
        ({}, SigmaRuleError, "empty selection"),
        ([], SigmaRuleError, "empty search identifier list"),
        ([{"A": 1}, "kw"], SigmaRuleError, "mixes mappings"),
        (None, SigmaRuleError, "unsupported search identifier"),
        ([None], SigmaModifierError, "must be a string or integer"),
        ({1: "x"}, SigmaRuleError, "must be a string"),
    ],
)
def test_search_identifier_errors(value: Any, error: type[Exception], message: str) -> None:
    with pytest.raises(error, match=message):
        compile_search_identifier(value)


def test_quantifiers_and_them() -> None:
    det = {
        "sel_a": {"A": "1"},
        "sel_b": {"B": "2"},
        "_hidden": {"H": "3"},
        "other": {"O": "4"},
    }
    assert compile_detection(rule({**det, "condition": "1 of sel_*"})) == Or(
        (eq("A", "1"), eq("B", "2"))
    )
    assert compile_detection(rule({**det, "condition": "all of sel_*"})) == And(
        (eq("A", "1"), eq("B", "2"))
    )
    them = compile_detection(rule({**det, "condition": "all of them"}))
    assert fields(them) == ["A", "B", "O"]  # underscore identifiers are excluded from 'them'
    assert compile_detection(rule({**det, "condition": "1 of oth*"})) == eq("O", "4")
    assert compile_detection(rule({**det, "condition": "_hidden"})) == eq("H", "3")


def test_multiple_conditions_are_ored() -> None:
    det = {"a": {"A": "1"}, "b": {"B": "2"}, "condition": ["a", "b"]}
    assert compile_detection(rule(det)) == Or((eq("A", "1"), eq("B", "2")))


@pytest.mark.parametrize(
    ("condition", "message"),
    [("missing", "unknown search identifier 'missing'"), ("1 of zz*", "matches no search")],
)
def test_condition_resolution_errors(condition: str, message: str) -> None:
    with pytest.raises(SigmaConditionError, match=message):
        compile_detection(rule({"a": {"A": "1"}, "condition": condition}))


def test_error_location_names_identifier_and_key() -> None:
    with pytest.raises(SigmaModifierError) as info:
        compile_detection(rule({"sel": {"A|gt": "x"}, "condition": "sel"}))
    assert info.value.location == "detection.sel.A|gt"


def test_compile_rule_simplifies_and_records_state() -> None:
    det = {"a": {"A": "1"}, "condition": "not not a and a"}
    compiled = compile_rule(rule(det))
    assert compiled.node == eq("A", "1")
    raw = compile_rule(rule(det), optimize=False)
    assert isinstance(raw.node, And)
    assert compiled.state == {}
    assert compiled.applied == ()


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        (And((Const(True), eq("A", "1"))), eq("A", "1")),
        (And((Const(False), eq("A", "1"))), Const(False)),
        (Or((Const(True), eq("A", "1"))), Const(True)),
        (Or((Const(False), Const(False))), Const(False)),
        (And(()), Const(True)),
        (Not(Const(True)), Const(False)),
        (Not(Not(eq("A", "1"))), eq("A", "1")),
        (
            And((And((eq("A", "1"), eq("B", "2"))), eq("A", "1"), Or((eq("C", "3"),)))),
            And((eq("A", "1"), eq("B", "2"), eq("C", "3"))),
        ),
        (Or((Or((eq("A", "1"),)), And((eq("B", "2"),)))), Or((eq("A", "1"), eq("B", "2")))),
    ],
)
def test_simplify(node: Node, expected: Node) -> None:
    assert simplify(node) == expected


def test_ast_helpers() -> None:
    node = And((eq("A", "1"), Not(Or((FieldMatch("B", NumMatch(3)), eq("A", "2"))))))
    assert fields(node) == ["A", "B"]
    assert len(list(walk(node))) == 6
    text = to_sexpr(node)
    assert '(A str "1")' in text
    assert "(B num 3)" in text
    assert text.startswith("(and")
    assert to_sexpr(Const(False)) == "(false)"
    assert to_sexpr(KeywordMatch(StrMatch(SigmaString.parse("x"), cased=True))) == (
        '(keyword cased str "x")'
    )
