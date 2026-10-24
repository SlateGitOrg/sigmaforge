from __future__ import annotations

from typing import Any

import pytest

from sigmaforge.ast import (
    CidrMatch,
    CmpMatch,
    Const,
    ExistsMatch,
    FieldMatch,
    KeywordMatch,
    Matcher,
    NullMatch,
    NumMatch,
    RegexMatch,
    StrMatch,
)
from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.evaluator import Evaluator, evaluate, lookup, value_text
from sigmaforge.sigmastr import SigmaString


def s(text: str, cased: bool = False) -> StrMatch:
    return StrMatch(SigmaString.parse(text), cased)


@pytest.mark.parametrize(
    ("matcher", "value", "expected"),
    [
        (s("abc"), "ABC", True),
        (s("abc", cased=True), "ABC", False),
        (s("a*c"), "a\nxc", True),  # '*' crosses newlines
        (s("a?c"), "abbc", False),
        (s("é"), "É", False),  # non-ASCII letters do not fold
        (s("k"), "K", False),  # nor does the Kelvin sign
        (s("4688"), 4688, True),  # integers are matched through their text
        (s("true"), True, True),
        (s("*"), "", True),
        (s("x"), ["a", "X"], True),  # lists match if any element does
        (s("x"), {"nested": "x"}, False),
        (RegexMatch("b+"), "abbbc", True),  # unanchored search
        (RegexMatch("^B"), "bc", False),
        (RegexMatch("^B", frozenset({"i"})), "bc", True),
        (RegexMatch("^c", frozenset({"m"})), "a\nc", True),
        (RegexMatch("a.c", frozenset({"s"})), "a\nc", True),
        (NumMatch(5), 5, True),
        (NumMatch(5), "5", True),
        (NumMatch(5), "05", False),
        (NumMatch(1), True, False),  # booleans are not integers here
        (NumMatch(5), 5.0, False),
        (CmpMatch("gt", 5), 6, True),
        (CmpMatch("gt", 5), "6", False),  # numeric-looking text is not a number
        (CmpMatch("gte", 5), 5, True),
        (CmpMatch("lt", 5), 4.5, True),
        (CmpMatch("lte", 5), 6, False),
        (CmpMatch("lt", 5), True, False),
        (CidrMatch("10.0.0.0/8"), "10.9.8.7", True),
        (CidrMatch("10.0.0.0/8"), "11.0.0.1", False),
        (CidrMatch("10.0.0.0/8"), "::ffff:10.0.0.1", False),  # family must match
        (CidrMatch("2001:db8::/32"), "2001:db8::1", True),
        (CidrMatch("10.0.0.0/8"), "10.foo", False),
        (CidrMatch("10.0.0.0/8"), 167772161, False),  # integer text is not an IP literal
    ],
)
def test_matchers(matcher: Matcher, value: Any, expected: bool) -> None:
    assert evaluate(FieldMatch("F", matcher), {"F": value}) is expected


@pytest.mark.parametrize(
    ("matcher", "event", "expected"),
    [
        (NullMatch(), {}, True),
        (NullMatch(), {"F": None}, True),
        (NullMatch(), {"F": ""}, False),
        (ExistsMatch(True), {"F": ""}, True),
        (ExistsMatch(True), {"F": None}, False),
        (ExistsMatch(False), {}, True),
        (s("*"), {}, False),
        (s("*"), {"F": None}, False),
    ],
)
def test_presence(matcher: Matcher, event: dict[str, Any], expected: bool) -> None:
    assert evaluate(FieldMatch("F", matcher), event) is expected


def test_dotted_lookup_and_exact_keys() -> None:
    event = {"process": {"name": "cmd.exe"}, "a.b": 1}
    assert lookup(event, "process.name") == "cmd.exe"
    assert lookup(event, "a.b") == 1
    assert evaluate(FieldMatch("process.name", s("CMD.EXE")), event)
    assert not evaluate(FieldMatch("process.missing", s("*")), event)


def test_keywords_search_all_leaf_values() -> None:
    node = KeywordMatch(s("*mimi*"))
    assert evaluate(node, {"a": {"b": ["x", "has MIMIkatz"]}})
    assert not evaluate(node, {"a": None, "b": 3})
    assert evaluate(KeywordMatch(RegexMatch("\\d{3}")), {"x": 12345})


def test_value_text() -> None:
    assert value_text(False) == "false"
    assert value_text(1.5) == "1.5"
    assert value_text(None) is None
    assert value_text([1]) is None


def test_invalid_regex_is_unsupported() -> None:
    with pytest.raises(UnsupportedFeatureError, match="not valid for Python re") as info:
        evaluate(FieldMatch("F", RegexMatch("a++(?<x")), {"F": "a"})
    assert info.value.feature == "regex dialect"


def test_evaluator_wrapper_and_constants() -> None:
    ev = Evaluator(FieldMatch("F", s("x")))
    assert ev.filter([{"F": "x"}, {"F": "y"}, {}]) == [0]
    assert evaluate(Const(True), {}) is True
