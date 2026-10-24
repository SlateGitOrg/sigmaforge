"""Splunk SPL backend.

Output shape: ``<search terms> [| where <eval expression>]``.

Plain field/value tests are emitted as search terms (fast, index-assisted). Leaves that search
syntax cannot express - regexes, ``?`` wildcards, literal ``*`` characters - go to a trailing
``| where`` clause built from eval functions (``match``, ``cidrmatch``, ``isnull``). Only
top-level AND conjuncts are split this way; a conjunct containing any non-search leaf moves to
the ``where`` clause as a whole, which keeps the boolean structure exact.

SPL search gives ``OR`` higher precedence than ``AND``, so every AND nested in an OR is
parenthesised. Negation uses ``NOT field=value`` (which also matches events lacking the field,
as Sigma requires), never ``field!=value``.
"""

from __future__ import annotations

import re

from sigmaforge.ast import (
    And,
    CidrMatch,
    CmpMatch,
    ExistsMatch,
    KeywordMatcher,
    Matcher,
    Node,
    NullMatch,
    NumMatch,
    RegexMatch,
    StrMatch,
)
from sigmaforge.backends.base import PREC_AND, PREC_NOT, Backend, TextRenderer
from sigmaforge.compiler import CompiledRule
from sigmaforge.sigmastr import Shape, SigmaString, Wildcard

CMP = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
SIMPLE_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


class NotSearchableError(Exception):
    """Internal signal: this subtree needs the eval (``| where``) dialect."""


def spl_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _flagged(pattern: str, flags: frozenset[str]) -> str:
    return f"(?{''.join(sorted(flags))}){pattern}" if flags else pattern


def wildcard_regex(pattern: SigmaString, cased: bool) -> str:
    return ("" if cased else "(?i)") + "^" + pattern.to_regex() + "$"


class SplunkEvalRenderer(TextRenderer):
    """The eval-expression dialect used after ``| where``."""

    backend_name = "splunk"
    and_token = "AND"
    or_token = "OR"
    paren_and_in_or = True

    @staticmethod
    def field_ref(name: str) -> str:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return name
        return "'" + name.replace("'", "\\'") + "'"

    def render_not(self, child: Node) -> str:
        return f"NOT ({self.render(child)})"

    def field_match(self, field: str, matcher: Matcher) -> str:
        f = self.field_ref(field)
        match matcher:
            case StrMatch(pattern, cased):
                if pattern.shape()[0] is Shape.ANYTHING:
                    return f"isnotnull({f})"
                return f"match({f}, {spl_string(wildcard_regex(pattern, cased))})"
            case RegexMatch(pattern, flags):
                return f"match({f}, {spl_string(_flagged(pattern, flags))})"
            case CidrMatch(network):
                return f"cidrmatch({spl_string(network)}, {f})"
            case NumMatch(value):
                return f"{f}=={value}"
            case CmpMatch(op, value):
                return f"{f}{CMP[op]}{value}"
            case NullMatch():
                return f"isnull({f})"
            case ExistsMatch(present):
                return f"{'isnotnull' if present else 'isnull'}({f})"

    def keyword_match(self, matcher: KeywordMatcher) -> str:
        if isinstance(matcher, StrMatch):
            return f"match(_raw, {spl_string(wildcard_regex(matcher.pattern, matcher.cased))})"
        return f"match(_raw, {spl_string(_flagged(matcher.pattern, matcher.flags))})"


class SplunkBackend(Backend):
    name = "splunk"
    description = "Splunk SPL search, with a | where clause for regex and pattern leaves"
    default_pipelines = ("splunk-windows",)
    and_token = "AND"
    or_token = "OR"
    paren_and_in_or = True

    def __init__(self) -> None:
        self.eval = SplunkEvalRenderer()

    @staticmethod
    def field_ref(name: str) -> str:
        return name if SIMPLE_FIELD.match(name) else spl_string(name)

    @staticmethod
    def search_value(pattern: SigmaString) -> str:
        if pattern.has_wildcard(Wildcard.ONE) or any(
            isinstance(p, str) and "*" in p for p in pattern.parts
        ):
            raise NotSearchableError
        return spl_string(pattern.render(lambda s: s, "*", None))

    def finalize(self, compiled: CompiledRule) -> str:
        node = compiled.node
        conjuncts = node.children if isinstance(node, And) else (node,)
        search: list[str] = []
        deferred: list[Node] = []
        for conjunct in conjuncts:
            try:
                search.append(self.render(conjunct, PREC_AND))
            except NotSearchableError:
                deferred.append(conjunct)
        prefix = compiled.state.get("splunk_prefix")
        terms = ([prefix] if prefix else []) + search
        text = " AND ".join(terms) if terms else "*"
        if deferred:
            where = deferred[0] if len(deferred) == 1 else And(tuple(deferred))
            text += f" | where {self.eval.render(where)}"
        return text

    def render_not(self, child: Node) -> str:
        return f"NOT {self.render(child, PREC_NOT)}"

    def in_list(self, field: str, values: list[str], cased: bool) -> str | None:
        if cased or any("*" in v for v in values):
            return None
        return f"{self.field_ref(field)} IN ({', '.join(spl_string(v) for v in values)})"

    def field_match(self, field: str, matcher: Matcher) -> str:
        f = self.field_ref(field)
        match matcher:
            case StrMatch(pattern, cased):
                value = self.search_value(pattern)
                return f"{f}=CASE({value})" if cased else f"{f}={value}"
            case RegexMatch():
                raise NotSearchableError
            case CidrMatch(network):
                return f"{f}={spl_string(network)}"
            case NumMatch(value):
                return f"{f}={value}"
            case CmpMatch(op, value):
                return f"{f}{CMP[op]}{value}"
            case NullMatch():
                return f"NOT {f}=*"
            case ExistsMatch(present):
                return f"{f}=*" if present else f"NOT {f}=*"

    def keyword_match(self, matcher: KeywordMatcher) -> str:
        if isinstance(matcher, RegexMatch):
            raise NotSearchableError
        value = self.search_value(matcher.pattern)
        return f"CASE({value})" if matcher.cased else value
