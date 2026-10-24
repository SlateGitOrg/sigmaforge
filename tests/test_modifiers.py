from __future__ import annotations

import base64
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sigmaforge.ast import (
    And,
    CidrMatch,
    CmpMatch,
    ExistsMatch,
    FieldMatch,
    KeywordMatch,
    Node,
    NullMatch,
    NumMatch,
    Or,
    RegexMatch,
    StrMatch,
)
from sigmaforge.errors import SigmaModifierError, UnsupportedFeatureError
from sigmaforge.modifiers import FieldSpec, base64_offsets, build_item, windash_variants
from sigmaforge.sigmastr import SigmaString


def s(text: str, cased: bool = False) -> StrMatch:
    return StrMatch(SigmaString.parse(text), cased)


def test_field_spec_parse() -> None:
    assert FieldSpec.parse("Image|EndsWith") == FieldSpec("Image", ("endswith",))
    assert FieldSpec.parse("|re") == FieldSpec(None, ("re",))


@pytest.mark.parametrize(
    ("key", "value", "node"),
    [
        ("F", "a", FieldMatch("F", s("a"))),
        ("F|contains", "a", FieldMatch("F", s("*a*"))),
        ("F|startswith", "a", FieldMatch("F", s("a*"))),
        ("F|endswith", "a", FieldMatch("F", s("*a"))),
        ("F|contains", "*a", FieldMatch("F", s("*a*"))),
        ("F", ["a", "b"], Or((FieldMatch("F", s("a")), FieldMatch("F", s("b"))))),
        ("F|contains|all", ["a", "b"], And((FieldMatch("F", s("*a*")), FieldMatch("F", s("*b*"))))),
        ("F|cased", "Ab", FieldMatch("F", s("Ab", cased=True))),
        ("F|contains|cased", "Ab", FieldMatch("F", s("*Ab*", cased=True))),
        ("F", 4688, FieldMatch("F", NumMatch(4688))),
        ("F|contains", 46, FieldMatch("F", s("*46*"))),
        ("F", 1.5, FieldMatch("F", StrMatch(SigmaString.literal("1.5")))),
        ("F", True, FieldMatch("F", StrMatch(SigmaString.literal("true")))),
        ("F", None, FieldMatch("F", NullMatch())),
        ("F|exists", False, FieldMatch("F", ExistsMatch(False))),
        ("F|gte", 3, FieldMatch("F", CmpMatch("gte", 3))),
        ("F|lt", 2.5, FieldMatch("F", CmpMatch("lt", 2.5))),
        ("F|re", "a.+b", FieldMatch("F", RegexMatch("a.+b"))),
        ("F|re|i|m", "x", FieldMatch("F", RegexMatch("x", frozenset({"i", "m"})))),
        ("F|re|ignorecase|dotall", "x", FieldMatch("F", RegexMatch("x", frozenset({"i", "s"})))),
        ("F|cidr", "10.1.2.3/8", FieldMatch("F", CidrMatch("10.0.0.0/8"))),
        ("F|cidr", "2001:db8::1/32", FieldMatch("F", CidrMatch("2001:db8::/32"))),
        ("|re", "x", KeywordMatch(RegexMatch("x"))),
        ("F|base64", "abc", FieldMatch("F", StrMatch(SigmaString.literal("YWJj")))),
        ("F|wide|base64", "a", FieldMatch("F", StrMatch(SigmaString.literal("YQA=")))),
        ("F|utf16be|base64", "a", FieldMatch("F", StrMatch(SigmaString.literal("AGE=")))),
        ("F|utf16|base64", "a", FieldMatch("F", StrMatch(SigmaString.literal("//5hAA==")))),
    ],
)
def test_build_item(key: str, value: Any, node: Node) -> None:
    assert build_item(key, value) == node


def test_base64offset_matches_known_vector() -> None:
    # Worked example: base64 of '/c echo' at offsets 0, 1 and 2, edge characters trimmed.
    assert base64_offsets(b"/c echo") == ["L2MgZWNob", "9jIGVjaG", "vYyBlY2hv"]


@given(st.binary(min_size=1, max_size=12), st.binary(max_size=6), st.binary(max_size=6))
def test_base64offset_finds_value_inside_any_blob(value: bytes, pre: bytes, post: bytes) -> None:
    encoded = base64.b64encode(pre + value + post).decode()
    assert any(variant in encoded for variant in base64_offsets(value))


def test_base64offset_contains_builds_or_of_variants() -> None:
    node = build_item("F|base64offset|contains", "/c echo")
    assert node == Or(
        tuple(
            FieldMatch("F", StrMatch(SigmaString.literal(v).prepend_any().append_any()))
            for v in ["L2MgZWNob", "9jIGVjaG", "vYyBlY2hv"]
        )
    )


def test_windash_expands_word_leading_dashes_only() -> None:
    variants = [str(v) for v in windash_variants(SigmaString.parse(" -a b-c"))]
    assert variants == [" -a b-c", " /a b-c", " –a b-c", " —a b-c", " ―a b-c"]
    assert windash_variants(SigmaString.parse("abc")) == [SigmaString.parse("abc")]


def test_windash_keeps_wildcards_and_combines() -> None:
    variants = windash_variants(SigmaString.parse("* -a -b*"))
    assert len(variants) == 25
    assert SigmaString.parse("* /a —b*") in variants


def test_windash_explosion_guard() -> None:
    with pytest.raises(SigmaModifierError, match="too many"):
        windash_variants(SigmaString.parse(" -a -b -c -d -e"))


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("F|bogus", "x", "unknown modifier 'bogus'"),
        ("F", [], "empty value list"),
        ("F|contains", None, "null values cannot take modifiers"),
        ("F|exists", "yes", "'exists' takes a boolean"),
        ("F|gt", "5", "'gt' takes a number"),
        ("F|gt|contains", 5, "'gt' takes a number"),
        ("F|i", "x", "require the 're' modifier"),
        ("F|re|contains", "x", "'re' cannot be combined"),
        ("F|re", 5, "'re' needs a string"),
        ("F|cidr", "not-an-ip", "invalid CIDR"),
        ("F|cidr|contains", "10.0.0.0/8", "'cidr' takes a network string"),
        ("F|wide", "a", "must be followed by 'base64'"),
        ("F|wide|contains", "a", "cannot follow an encoding modifier"),
        ("F|base64|wide", "a", "must be followed by 'base64'"),
        ("F|wide|base64", "a?", "cannot encode a value containing wildcards"),
        ("F|wide|windash", "a", "'windash' must come before"),
        ("F|wide|wide", "a", "already-encoded"),
        ("F|wide|base64", "a*", "wildcards"),
        ("F", {"nested": 1}, "unsupported value type"),
        ("|cidr", "10.0.0.0/8", "keyword items only support"),
    ],
)
def test_modifier_errors(key: str, value: Any, message: str) -> None:
    with pytest.raises(SigmaModifierError, match=message):
        build_item(key, value)


@pytest.mark.parametrize("mod", ["expand", "fieldref"])
def test_recognised_but_unsupported(mod: str) -> None:
    with pytest.raises(UnsupportedFeatureError) as info:
        build_item(f"F|{mod}", "x")
    assert info.value.feature == f"modifier '{mod}'"
