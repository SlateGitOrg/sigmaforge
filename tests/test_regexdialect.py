from __future__ import annotations

import re

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.regexdialect import check_re2, literal_to_lucene, to_lucene, tokenize


def test_tokenizer_respects_classes_and_escapes() -> None:
    kinds = [(t.kind, t.text) for t in tokenize("[(?=]\\(?=x)")]
    assert kinds[0] == ("class", "[(?=]")
    assert kinds[1] == ("escape", "\\(")
    assert kinds[2] == ("quant", "?")


@pytest.mark.parametrize("pattern", ["[]a]", "[^]a]", "a{2}?", "a{x", "\\x41"])
def test_tokenizer_edge_cases(pattern: str) -> None:
    assert "".join(t.text for t in tokenize(pattern)) == pattern


@pytest.mark.parametrize(
    ("pattern", "message"), [("a\\", "trailing backslash"), ("[abc", "unterminated class")]
)
def test_tokenizer_errors(pattern: str, message: str) -> None:
    with pytest.raises(UnsupportedFeatureError, match=message):
        list(tokenize(pattern))


@pytest.mark.parametrize(
    ("pattern", "feature"),
    [
        ("(?=a)", "regex look-around (RE2)"),
        ("(?<!a)b", "regex look-around (RE2)"),
        ("(?>ab)", "regex atomic group (RE2)"),
        ("a*+", "regex possessive quantifier (RE2)"),
        ("(a)\\1", "regex back-reference (RE2)"),
        ("(?P<x>a)(?P=x)", "regex back-reference (RE2)"),
    ],
)
def test_re2_rejections(pattern: str, feature: str) -> None:
    with pytest.raises(UnsupportedFeatureError) as info:
        check_re2(pattern)
    assert info.value.feature == feature


@pytest.mark.parametrize("pattern", ["[(?=]", "\\(?=", "(?i)a(?:b|c)\\d+", "(?P<n>a)"])
def test_re2_accepts(pattern: str) -> None:
    check_re2(pattern)


@pytest.mark.parametrize(
    ("pattern", "flags", "expected"),
    [
        ("abc", frozenset(), (".*abc.*", False)),
        ("^a\\d+$", frozenset(), ("a[0-9]+", False)),
        ("(?i)x(?:y|z)", frozenset(), (".*x(y|z).*", True)),
        ("x", frozenset({"i"}), (".*x.*", True)),
        ("a.*?b", frozenset(), (".*a.*b.*", False)),
        ("[\\w.-]+@x", frozenset(), (".*[a-zA-Z0-9_.-]+\\@x.*", False)),
        ("a|b", frozenset(), (".*(a|b).*", False)),
        ("\\D\\W\\S", frozenset(), (".*[^0-9][^a-zA-Z0-9_][^ \\t\\n\\r\\f].*", False)),
        ("\\t\\x41#", frozenset(), (".*\tA\\#.*", False)),
        ("(?<n>a){2}", frozenset(), (".*(a){2}.*", False)),
        ("a{b", frozenset(), (".*a\\{b.*", False)),
        ("[a&<]", frozenset(), (".*[a\\&\\<].*", False)),
    ],
)
def test_to_lucene(pattern: str, flags: frozenset[str], expected: tuple[str, bool]) -> None:
    assert to_lucene(pattern, flags) == expected


@pytest.mark.parametrize(
    ("pattern", "flags", "feature"),
    [
        ("\\bx", frozenset(), "regex escape '\\b' (Lucene)"),
        ("(?=x)", frozenset(), "regex group '(?=' (Lucene)"),
        ("(?<=x)", frozenset(), "regex look-around (Lucene)"),
        ("a^b", frozenset(), "regex inner anchor (Lucene)"),
        ("^a|b", frozenset(), "regex anchored top-level alternation (Lucene)"),
        ("a++", frozenset(), "regex possessive quantifier (Lucene)"),
        ("(?s)a", frozenset(), "regex inline flags other than (?i) (Lucene)"),
        ("a", frozenset({"m"}), "regex multiline flag (Lucene)"),
        ("[[:alpha:]]", frozenset(), "regex POSIX class (Lucene)"),
        ("[\\D]", frozenset(), "regex negated shorthand in class (Lucene)"),
        ("\\xZZ", frozenset(), "regex bad hex escape (Lucene)"),
    ],
)
def test_to_lucene_rejections(pattern: str, flags: frozenset[str], feature: str) -> None:
    with pytest.raises(UnsupportedFeatureError) as info:
        to_lucene(pattern, flags)
    assert info.value.feature == feature


def test_literal_to_lucene() -> None:
    assert literal_to_lucene('a.b*"c d') == 'a\\.b\\*\\"c d'


# Patterns built from a small grammar that Lucene and Python agree on.
atoms = st.sampled_from(["a", "b", ".", "[ab]", "[^a]", "\\d", "\\.", "(a|b)", "(?:ab)"])
quantifiers = st.sampled_from(["", "", "*", "+", "?", "{1,2}", "*?"])
bodies = st.lists(st.tuples(atoms, quantifiers), min_size=1, max_size=5).map(
    lambda parts: "".join(a + q for a, q in parts)
)
patterns = st.tuples(st.booleans(), bodies, st.booleans()).map(
    lambda t: ("^" if t[0] else "") + t[1] + ("$" if t[2] else "")
)


@given(patterns, st.text(alphabet="ab1.x", max_size=8))
def test_lucene_translation_preserves_search_semantics(pattern: str, value: str) -> None:
    """Lucene full-match of the translation == Python search of the original.

    The translated syntax used here is also valid Python syntax, so Python's ``fullmatch``
    stands in for Lucene's whole-value matching.
    """
    translated, _ = to_lucene(pattern)
    original = re.search(pattern, value)
    assume(not (original and "\n" in value))
    assert bool(re.fullmatch(translated, value, re.DOTALL)) == bool(original)
