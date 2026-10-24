"""SQLite SQL backend.

Target schema: one table (default ``events``, overridable with the ``sql_table`` pipeline
state) with one *untyped* column per field, so stored values keep their own storage class.
:mod:`sigmaforge.sqlite_runtime` builds exactly that table from JSON events and registers the
two helper functions the generated SQL relies on: ``regexp`` (SQLite's ``REGEXP`` operator hook)
and ``sigma_cidr_match``.

Semantics mirror :mod:`sigmaforge.evaluator`; the differential tests hold the two together:

* Case-insensitive strings use ``LIKE ... ESCAPE '\\'`` (ASCII case folding, coerces numbers
  to text); ``cased`` strings use ``GLOB`` with ``[*]``-style escaping.
* ``NULL`` from a missing column must count as *false*, including under ``NOT``. SQL's
  three-valued logic would make ``NOT (NULL LIKE 'x')`` NULL (not selected) where Sigma says
  "true", so negations are emitted as ``NOT coalesce(<expr>, 0)``. AND/OR need no wrapping:
  under the reading NULL = false, Kleene AND/OR agree with Boolean logic.
* Numeric comparisons check ``typeof`` first so ``'abc' > 5`` (true in SQLite's type ordering)
  cannot match.
"""

from __future__ import annotations

from collections.abc import Sequence

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
from sigmaforge.backends.base import Backend
from sigmaforge.compiler import CompiledRule
from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.evaluator import compile_regex
from sigmaforge.sigmastr import Shape

CMP_SQL = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def quote_str(text: str) -> str:
    if "\x00" in text:
        raise UnsupportedFeatureError("NUL character", "SQL string literals cannot hold NUL")
    return "'" + text.replace("'", "''") + "'"


def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def escape_glob(text: str) -> str:
    return "".join(f"[{c}]" if c in "*?[" else c for c in text)


def regex_with_flags(pattern: str, flags: frozenset[str]) -> str:
    return f"(?{''.join(sorted(flags))}){pattern}" if flags else pattern


class SQLiteBackend(Backend):
    name = "sql"
    description = "SQLite SQL (SELECT over a flat events table; needs sqlite_runtime helpers)"
    and_token = "AND"
    or_token = "OR"

    def __init__(self, table: str = "events", keyword_columns: Sequence[str] | None = None):
        self.table = table
        self.keyword_columns = tuple(keyword_columns or ())

    def finalize(self, compiled: CompiledRule) -> str:
        table = compiled.state.get("sql_table", self.table)
        return f"SELECT * FROM {quote_ident(table)} WHERE {self.render(compiled.node)}"

    def const(self, value: bool) -> str:
        return "1" if value else "0"

    def render_not(self, child: Node) -> str:
        return f"NOT coalesce({self.render(child)}, 0)"

    def field_match(self, field: str, matcher: Matcher) -> str:
        col = quote_ident(field)
        match matcher:
            case StrMatch(pattern, cased):
                if pattern.shape()[0] is Shape.ANYTHING:
                    return f"{col} IS NOT NULL"
                if cased:
                    return f"{col} GLOB {quote_str(pattern.render(escape_glob, '*', '?'))}"
                like = pattern.render(escape_like, "%", "_")
                return f"{col} LIKE {quote_str(like)} ESCAPE '\\'"
            case RegexMatch(pattern, flags):
                compile_regex(pattern, flags)  # raises UnsupportedFeatureError if invalid
                return f"{col} REGEXP {quote_str(regex_with_flags(pattern, flags))}"
            case CidrMatch(network):
                return f"sigma_cidr_match({quote_str(network)}, {col})"
            case NumMatch(value):
                return f"CAST({col} AS TEXT) = {quote_str(str(value))}"
            case CmpMatch(op, value):
                return f"(typeof({col}) IN ('integer', 'real') AND {col} {CMP_SQL[op]} {value!r})"
            case NullMatch():
                return f"{col} IS NULL"
            case ExistsMatch(present):
                return f"{col} IS {'NOT ' if present else ''}NULL"

    def keyword_match(self, matcher: KeywordMatcher) -> str:
        if not self.keyword_columns:
            raise self.unsupported(
                "keyword search", "keyword search needs keyword columns (--sql-keyword-columns)"
            )
        parts = [self.field_match(c, matcher) for c in self.keyword_columns]
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"
