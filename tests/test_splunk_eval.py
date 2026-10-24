"""Semantics of the Splunk ``| where`` (eval) dialect and of the anchored wildcard regexes.

Neither Splunk nor KQL can run in ``make check``, so these tests check the two properties that
exact-output tests alone cannot:

* **Null safety.** A small three-valued (Kleene) interpreter evaluates the eval text the way
  Splunk does: a function of a missing field is NULL, ``NOT NULL`` is NULL, ``TRUE OR NULL`` is
  TRUE, ``FALSE AND NULL`` is FALSE, and ``where`` keeps only TRUE. Leaf atoms are mapped back
  to their AST leaves and, when the field is present, decided by the reference evaluator, so the
  test isolates the boolean/NULL structure the renderer is responsible for.
* **Newlines.** The regex emitted for wildcard leaves (``(?s)`` / ``(?is)``, anchored with
  ``\\z``) is run with Python ``re`` (``\\z`` spelled ``\\Z``, which means the same in Python)
  and must agree with the evaluator on multi-line values.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, example, given
from hypothesis import strategies as st

from sigmaforge.ast import (
    And,
    CidrMatch,
    CmpMatch,
    ExistsMatch,
    FieldMatch,
    KeywordMatch,
    Node,
    Not,
    NullMatch,
    NumMatch,
    Or,
    RegexMatch,
    StrMatch,
    walk,
)
from sigmaforge.backends import get_backend
from sigmaforge.backends.base import full_match_regex
from sigmaforge.backends.splunk import SplunkBackend, SplunkEvalRenderer, _null_safe
from sigmaforge.compiler import compile_rule
from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.evaluator import MISSING, evaluate, lookup
from sigmaforge.rule import load_rule, rule_from_dict
from sigmaforge.sigmastr import SigmaString
from tests.strategies import ALPHABET, rule_and_events
from tests.test_backends import render

ROOT = Path(__file__).resolve().parent.parent
Tri = bool | None  # Kleene truth value; None is NULL

# --------------------------------------------------------------------- a Kleene interpreter


def _absent(event: Mapping[str, Any], field: str) -> bool:
    value = lookup(event, field)
    return value is MISSING or value is None


def _null_test(field: str, present: bool) -> Callable[[Any], Tri]:
    return lambda event: _absent(event, field) != present


def _two_valued(leaf: Node) -> Callable[[Any], Tri]:
    return lambda event: evaluate(leaf, event)


def _null_on_missing(leaf: FieldMatch) -> Callable[[Any], Tri]:
    """A function of a missing field is NULL; otherwise the evaluator decides the leaf."""
    return lambda event: None if _absent(event, leaf.field) else evaluate(leaf, event)


def _atoms(node: Node, renderer: SplunkEvalRenderer) -> dict[str, Callable[[Any], Tri]]:
    """Every leaf text the renderer can emit for ``node``, with its Splunk truth value."""
    atoms: dict[str, Callable[[Any], Tri]] = {}
    for sub in walk(node):
        if isinstance(sub, FieldMatch):
            ref = renderer.field_ref(sub.field)
            atoms[f"isnull({ref})"] = _null_test(sub.field, present=False)
            atoms[f"isnotnull({ref})"] = _null_test(sub.field, present=True)
    for sub in walk(node):
        if isinstance(sub, FieldMatch):
            text = renderer.field_match(sub.field, sub.matcher)
            if text in atoms:  # the pure null tests above already model it exactly
                continue
            atoms[text] = _two_valued(sub) if _null_safe(sub.matcher) else _null_on_missing(sub)
        elif isinstance(sub, KeywordMatch):  # _raw is never missing
            atoms[renderer.keyword_match(sub.matcher)] = _two_valued(sub)
    return atoms


def _tokenize(text: str, atoms: Mapping[str, object]) -> list[str]:
    by_length = sorted(atoms, key=len, reverse=True)
    tokens: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == " ":
            i += 1
            continue
        atom = next((a for a in by_length if text.startswith(a, i)), None)
        if atom is not None:
            tokens.append(atom)
            i += len(atom)
            continue
        word = next((w for w in ("(", ")", "AND ", "OR ", "NOT ") if text.startswith(w, i)), None)
        assert word is not None, f"cannot tokenize {text[i:]!r} in {text!r}"
        tokens.append(word.strip())
        i += len(word)
    return tokens


def kleene(text: str, atoms: Mapping[str, Callable[[Any], Tri]], event: Any) -> Tri:
    """Evaluate eval-dialect ``text`` with Splunk precedence (NOT > AND > OR) and NULLs."""
    tokens = _tokenize(text, atoms)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def or_() -> Tri:
        values = [and_()]
        while peek() == "OR":
            take()
            values.append(and_())
        return True if True in values else (None if None in values else False)

    def and_() -> Tri:
        values = [not_()]
        while peek() == "AND":
            take()
            values.append(not_())
        return False if False in values else (None if None in values else True)

    def not_() -> Tri:
        if peek() == "NOT":
            take()
            value = not_()
            return None if value is None else not value
        token = take()
        if token == "(":
            value = or_()
            assert take() == ")"
            return value
        return atoms[token](event)

    result = or_()
    assert pos == len(tokens), f"trailing tokens in {text!r}"
    return result


def splunk_where_keeps(node: Node, event: Any) -> bool:
    renderer = SplunkEvalRenderer()
    return kleene(renderer.render(node), _atoms(node, renderer), event) is True


# ------------------------------------------------------------------------------- null safety

NOT_OVER_MISSING = (
    {
        "title": "not over a missing regex field",
        "detection": {
            "sel1": {"Image|endswith": "\\x.exe"},
            "filter_a": {"CommandLine|re": "foo"},
            "condition": "sel1 and not filter_a",
        },
    },
    [{"Image": "C:\\x.exe"}, {"Image": "C:\\x.exe", "CommandLine": "foo"}, {"Image": "y"}],
)


@given(rule_and_events())
@example(NOT_OVER_MISSING)
def test_where_dialect_agrees_with_evaluator_under_nulls(
    case: tuple[dict[str, Any], list[dict[str, Any]]],
) -> None:
    doc, evs = case
    node = compile_rule(rule_from_dict(doc)).node
    try:
        SplunkEvalRenderer().render(node)
    except UnsupportedFeatureError:
        assume(False)
    for event in evs:
        assert splunk_where_keeps(node, event) == evaluate(node, event), event


def test_review_probe_compiles_to_a_null_safe_where_clause() -> None:
    doc, evs = NOT_OVER_MISSING
    compiled = compile_rule(rule_from_dict(doc))
    text = SplunkBackend().convert(compiled).text
    assert text == (
        'Image="*\\\\x.exe" | where (isnull(CommandLine) OR NOT match(CommandLine, "foo"))'
    )
    assert [splunk_where_keeps(compiled.node, e) for e in evs] == [True, False, False]
    assert [evaluate(compiled.node, e) for e in evs] == [True, False, False]


def _f(name: str, matcher: Any) -> FieldMatch:
    return FieldMatch(name, matcher)


R = RegexMatch("r")


@pytest.mark.parametrize(
    ("node", "where"),
    [
        (Not(_f("A", R)), '(isnull(A) OR NOT match(A, "r"))'),
        (
            Not(And((_f("A", R), _f("B", R)))),
            '((isnull(A) OR NOT match(A, "r")) OR (isnull(B) OR NOT match(B, "r")))',
        ),
        (
            Not(Or((_f("A", R), _f("B", CidrMatch("10.0.0.0/8"))))),
            '((isnull(A) OR NOT match(A, "r")) AND (isnull(B) OR NOT cidrmatch("10.0.0.0/8", B)))',
        ),
        (Not(Not(Or((_f("A", R), _f("B", R))))), '(match(A, "r") OR match(B, "r"))'),
        (Not(_f("A", NumMatch(1))), "(isnull(A) OR NOT A==1)"),
        (Not(_f("A", CmpMatch("gt", 1))), "(isnull(A) OR NOT A>1)"),
        (Not(_f("A", NullMatch())), "NOT isnull(A)"),
        (Not(_f("A", ExistsMatch(True))), "NOT isnotnull(A)"),
        (Not(_f("A", StrMatch(SigmaString.parse("*")))), "NOT isnotnull(A)"),
        (Not(KeywordMatch(R)), 'NOT match(_raw, "r")'),
        (Not(_f("a b", R)), "(isnull('a b') OR NOT match('a b', \"r\"))"),
    ],
)
def test_negation_shapes(node: Node, where: str) -> None:
    assert SplunkEvalRenderer().render(node) == where


def test_negation_inside_a_deferred_conjunct() -> None:
    node = And((_f("C", NumMatch(1)), Or((_f("A", R), Not(_f("B", R))))))
    assert render("splunk", node) == 'C=1 | where match(A, "r") OR (isnull(B) OR NOT match(B, "r"))'


# ---------------------------------------------------------------------------------- newlines


def python_view(regex: str) -> re.Pattern[str]:
    r"""Compile an emitted full-match regex in Python: only the trailing ``\z`` is respelt."""
    assert regex.endswith(r"\z")
    # re.ASCII mirrors the evaluator, which folds ASCII letters only.
    return re.compile(regex[:-2] + r"\Z", re.ASCII)


sigma_patterns = st.text(alphabet=ALPHABET + "\n", max_size=6).map(SigmaString.parse)
multiline_values = st.text(alphabet="ab*?\\\n ", max_size=8)


@given(sigma_patterns, st.booleans(), st.lists(multiline_values, max_size=6))
@example(SigmaString.parse("a*"), False, ["a\nb", "A\n"])  # '*' must cross a newline
@example(SigmaString.parse("a"), True, ["a\n", "a"])  # no match before a trailing newline
@example(SigmaString.parse("a?b"), False, ["a\nb"])  # '?' is any character, newline included
def test_full_match_regex_agrees_with_evaluator_on_newlines(
    pattern: SigmaString, cased: bool, values: list[str]
) -> None:
    compiled = python_view(full_match_regex(pattern, cased))
    leaf = FieldMatch("F", StrMatch(pattern, cased))
    for value in values:
        assert (compiled.search(value) is not None) == evaluate(leaf, {"F": value}), value


def test_old_anchoring_was_wrong_on_these_values() -> None:
    """Pins why ``(?s)`` and ``\\z`` are needed (the pre-fix form, run the same way)."""
    old = re.compile("(?i)^" + SigmaString.parse("a*").to_regex() + "$", re.ASCII)
    assert old.search("a\nb") is None  # false negative: '.*' stopped at the newline
    old_cased = re.compile("^" + SigmaString.parse("a").to_regex() + "$")
    assert old_cased.search("a\n") is not None  # false positive: '$' before trailing newline


SCRIPT_RULE = (
    ROOT
    / "third_party/sigmahq/rules/windows/powershell/powershell_script"
    / "posh_ps_computer_discovery_get_adcomputer.yml"
)


def test_multiline_scriptblock_rule_in_the_pinned_subset() -> None:
    compiled = compile_rule(load_rule(SCRIPT_RULE), [])
    text = get_backend("splunk").convert(compiled).text
    assert text.endswith('| where match(ScriptBlockText, "(?is)^.* -Filter \\\\*.*\\\\z")')
    block = "Get-ADComputer -Filter *\n| Select Name\n"
    regex = full_match_regex(SigmaString.parse("* -Filter \\**"), cased=False)
    assert python_view(regex).search(block) is not None


@pytest.mark.parametrize(
    ("matcher", "query"),
    [
        (StrMatch(SigmaString.parse("a*b")), 'A matches regex "(?is)^a.*b\\\\z"'),
        (StrMatch(SigmaString.parse("a?"), cased=True), 'A matches regex "(?s)^a.\\\\z"'),
    ],
)
def test_kql_fallback_regex(matcher: StrMatch, query: str) -> None:
    from sigmaforge.backends.kql import KqlBackend

    assert KqlBackend().render(FieldMatch("A", matcher)) == query
