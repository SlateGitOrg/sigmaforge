from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sigmaforge.sigmastr import Shape, SigmaString, Wildcard


def test_parse_wildcards_and_literals() -> None:
    s = SigmaString.parse("a*b?c")
    assert s.parts == ("a", Wildcard.ANY, "b", Wildcard.ONE, "c")


@pytest.mark.parametrize(
    ("text", "parts"),
    [
        ("\\*", ("*",)),
        ("\\?", ("?",)),
        ("\\\\", ("\\",)),
        ("C:\\Windows\\", ("C:\\Windows\\",)),  # lone backslashes stay literal
        ("\\\\*", ("\\", Wildcard.ANY)),  # escaped backslash, then a real wildcard
        ("a**b", ("a", Wildcard.ANY, "b")),  # runs of * collapse
        ("", ()),
    ],
)
def test_parse_escapes(text: str, parts: tuple[object, ...]) -> None:
    assert SigmaString.parse(text).parts == parts


@pytest.mark.parametrize(
    ("text", "shape", "core"),
    [
        ("abc", Shape.EXACT, "abc"),
        ("*abc*", Shape.CONTAINS, "abc"),
        ("abc*", Shape.STARTSWITH, "abc"),
        ("*abc", Shape.ENDSWITH, "abc"),
        ("*", Shape.ANYTHING, ""),
        ("a*b", Shape.PATTERN, ""),
        ("*a?", Shape.PATTERN, ""),
        ("", Shape.EXACT, ""),
    ],
)
def test_shape(text: str, shape: Shape, core: str) -> None:
    assert SigmaString.parse(text).shape() == (shape, core)


def test_prepend_append_do_not_duplicate_wildcards() -> None:
    s = SigmaString.parse("*x*")
    assert s.prepend_any().append_any() == s


def test_plain_text_rejects_wildcards() -> None:
    with pytest.raises(ValueError, match="wildcards"):
        SigmaString.parse("a*").plain_text()


def test_render_requires_single_char_token() -> None:
    with pytest.raises(ValueError, match="single-character"):
        SigmaString.parse("a?").render(str, "*", None)


def test_literal_keeps_metacharacters() -> None:
    s = SigmaString.literal("a*?b")
    assert s.is_plain()
    assert s.plain_text() == "a*?b"


def test_repr_and_str_round_trip() -> None:
    s = SigmaString.parse("a\\*b*c")
    assert str(s) == "a\\*b*c"
    assert "SigmaString" in repr(s)


def test_map_literals_keeps_wildcards() -> None:
    assert SigmaString.parse("ab*cd").map_literals(str.upper) == SigmaString.parse("AB*CD")


@given(st.text(alphabet="ab*?\\.", max_size=12))
def test_str_parse_round_trip(text: str) -> None:
    parsed = SigmaString.parse(text)
    assert SigmaString.parse(str(parsed)) == parsed


@given(st.text(alphabet="ab*?\\.%", max_size=8), st.text(alphabet="ab*?\\.%", max_size=8))
def test_to_regex_matches_fnmatch_semantics(pattern: str, value: str) -> None:
    """Literal text always matches itself; '*' patterns match any filling."""
    lit = SigmaString.literal(value)
    assert re.fullmatch(lit.to_regex(), value, re.DOTALL)
    parsed = SigmaString.parse(pattern)
    filled = "".join(p if isinstance(p, str) else "x" for p in parsed.parts)
    assert re.fullmatch(parsed.to_regex(), filled, re.DOTALL)
