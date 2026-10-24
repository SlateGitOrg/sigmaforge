"""Elastic EQL backend.

Output shape: ``<event category> where <condition>``; the category comes from the
``eql_category`` pipeline state (``any`` otherwise).

Operator choice per string leaf:

========================  =========================  ===========================
shape                     case-insensitive           ``cased``
========================  =========================  ===========================
exact                     ``field : "v"``            ``field == "v"``
wildcards ``*`` / ``?``   ``field like~ "p*t"``      ``field like "p*t"``
literal ``*``/``?`` text  ``field regex~ "<lucene>"``  ``field regex "<lucene>"``
========================  =========================  ===========================

EQL wildcard strings have no escape for a literal ``*`` or ``?``, hence the regex fallback.
Sigma regexes are translated to Lucene syntax by :func:`sigmaforge.regexdialect.to_lucene`.
EQL has no free-text search, so keyword detections are rejected.
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
from sigmaforge.backends.base import PREC_NOT, Backend
from sigmaforge.compiler import CompiledRule
from sigmaforge.regexdialect import literal_to_lucene, to_lucene
from sigmaforge.sigmastr import Shape, SigmaString

CMP = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
SIMPLE_FIELD = re.compile(r"^[A-Za-z_@][A-Za-z0-9_.@]*$")
STRING_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def eql_string(text: str) -> str:
    return '"' + "".join(STRING_ESCAPES.get(c, c) for c in text) + '"'


class EqlBackend(Backend):
    name = "eql"
    description = "Elastic EQL (<category> where ...), ECS field names via the ecs-windows pipeline"
    default_pipelines = ("ecs-windows",)

    @staticmethod
    def field_ref(name: str) -> str:
        return name if SIMPLE_FIELD.match(name) else "`" + name.replace("`", "``") + "`"

    def finalize(self, compiled: CompiledRule) -> str:
        category = compiled.state.get("eql_category", "any")
        return f"{category} where {self.render(compiled.node)}"

    def render_not(self, child: Node) -> str:
        return f"not {self.render(child, PREC_NOT)}"

    def in_list(self, field: str, values: list[str], cased: bool) -> str | None:
        if any(c in v for v in values for c in "*?"):
            return None
        op = "in" if cased else "in~"
        return f"{self.field_ref(field)} {op} ({', '.join(eql_string(v) for v in values)})"

    def _string(self, f: str, pattern: SigmaString, cased: bool) -> str:
        shape, text = pattern.shape()
        if shape is Shape.ANYTHING:
            return f"{f} != null"
        literal_meta = any(isinstance(p, str) and ("*" in p or "?" in p) for p in pattern.parts)
        if not literal_meta:
            if shape is Shape.EXACT:
                return f"{f} == {eql_string(text)}" if cased else f"{f} : {eql_string(text)}"
            wildcard = pattern.render(lambda s: s, "*", "?")
            return f"{f} {'like' if cased else 'like~'} {eql_string(wildcard)}"
        lucene = pattern.render(literal_to_lucene, ".*", ".")
        return f"{f} {'regex' if cased else 'regex~'} {eql_string(lucene)}"

    def field_match(self, field: str, matcher: Matcher) -> str:
        f = self.field_ref(field)
        match matcher:
            case StrMatch(pattern, cased):
                return self._string(f, pattern, cased)
            case RegexMatch(pattern, flags):
                lucene, insensitive = to_lucene(pattern, flags)
                return f"{f} {'regex~' if insensitive else 'regex'} {eql_string(lucene)}"
            case CidrMatch(network):
                return f"cidrMatch({f}, {eql_string(network)})"
            case NumMatch(value):
                return f"{f} == {value}"
            case CmpMatch(op, value):
                return f"{f} {CMP[op]} {value}"
            case NullMatch():
                return f"{f} == null"
            case ExistsMatch(present):
                return f"{f} {'!=' if present else '=='} null"

    def keyword_match(self, matcher: KeywordMatcher) -> str:
        raise self.unsupported("keyword search", "EQL has no full-text keyword search")
