"""Microsoft KQL backend (Microsoft Sentinel / Defender XDR advanced hunting).

Output shape::

    <Table>
    | where <condition>

The table comes from the ``kql_table`` pipeline state (set by the ``sentinel-windows`` pipeline
per logsource); a rule whose logsource maps to no table is rejected rather than guessed.

String leaves map to KQL's native operators (``=~``, ``contains``, ``startswith``, ``endswith``
and their ``_cs``/``==`` case-sensitive twins); any other wildcard layout becomes an anchored
``matches regex`` (see :func:`~sigmaforge.backends.base.full_match_regex`: ``(?s)`` so wildcards
cross newlines). Sigma regexes run on RE2, so look-around, back-references, atomic groups and
possessive quantifiers are rejected by :func:`sigmaforge.regexdialect.check_re2`.

KQL string columns have no null: a missing string is ``""``. ``null``/``exists`` therefore use
``isempty``/``isnotempty``, which also treat an empty string as absent (documented divergence).
"""

from __future__ import annotations

import re

from sigmaforge.ast import (
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
from sigmaforge.backends.base import Backend, full_match_regex
from sigmaforge.compiler import CompiledRule
from sigmaforge.regexdialect import check_re2
from sigmaforge.sigmastr import Shape

CMP = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
SIMPLE_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRING_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}
OPERATORS = {
    Shape.EXACT: ("=~", "=="),
    Shape.CONTAINS: ("contains", "contains_cs"),
    Shape.STARTSWITH: ("startswith", "startswith_cs"),
    Shape.ENDSWITH: ("endswith", "endswith_cs"),
}


def kql_string(text: str) -> str:
    return '"' + "".join(STRING_ESCAPES.get(c, c) for c in text) + '"'


class KqlBackend(Backend):
    name = "kql"
    description = (
        "Microsoft KQL (Sentinel / Defender XDR), tables via the sentinel-windows pipeline"
    )
    default_pipelines = ("sentinel-windows",)

    @staticmethod
    def field_ref(name: str) -> str:
        if SIMPLE_FIELD.match(name):
            return name
        return "['" + name.replace("\\", "\\\\").replace("'", "\\'") + "']"

    def finalize(self, compiled: CompiledRule) -> str:
        table = compiled.state.get("kql_table")
        if not table:
            raise self.unsupported(
                "no KQL table for logsource",
                f"no KQL table is mapped for logsource '{compiled.logsource}'",
            )
        return f"{table}\n| where {self.render(compiled.node)}"

    def render_not(self, child: Node) -> str:
        return f"not({self.render(child)})"

    def in_list(self, field: str, values: list[str], cased: bool) -> str | None:
        op = "in" if cased else "in~"
        return f"{self.field_ref(field)} {op} ({', '.join(kql_string(v) for v in values)})"

    def field_match(self, field: str, matcher: Matcher) -> str:
        f = self.field_ref(field)
        match matcher:
            case StrMatch(pattern, cased):
                shape, text = pattern.shape()
                if shape is Shape.ANYTHING:
                    return f"isnotempty({f})"
                if shape in OPERATORS:
                    op = OPERATORS[shape][1 if cased else 0]
                    return f"{f} {op} {kql_string(text)}"
                return f"{f} matches regex {kql_string(full_match_regex(pattern, cased))}"
            case RegexMatch(pattern, flags):
                check_re2(pattern)
                prefix = f"(?{''.join(sorted(flags))})" if flags else ""
                return f"{f} matches regex {kql_string(prefix + pattern)}"
            case CidrMatch(network):
                func = "ipv4_is_in_range" if matcher.version == 4 else "ipv6_is_in_range"
                return f"{func}({f}, {kql_string(network)})"
            case NumMatch(value):
                return f"{f} == {value}"
            case CmpMatch(op, value):
                return f"{f} {CMP[op]} {value}"
            case NullMatch():
                return f"isempty({f})"
            case ExistsMatch(present):
                return f"{'isnotempty' if present else 'isempty'}({f})"

    def keyword_match(self, matcher: KeywordMatcher) -> str:
        raise self.unsupported(
            "keyword search", "KQL term search ('* has') does not have Sigma substring semantics"
        )
