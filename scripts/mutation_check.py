"""How strong is the differential test? Seed known bugs and count how many it catches.

Each *mutant* monkeypatches one plausible bug into the SQL backend, the SQLite runtime, the
reference evaluator or the simplifier. For every mutant the random part of the two differential
properties (SQLite result == evaluator verdict for the whole rule *and for every subtree*, and
unsimplified == simplified tree; no hand-written examples) is run with a fixed seed; the
mutant is *killed* if any of them fails.

Mutants in the front end (parser, modifiers) are deliberately absent: both sides of the
differential test consume the same AST, so such bugs are invisible to it by construction.
They are covered by the unit and golden tests instead.

Usage: uv run python scripts/mutation_check.py [--examples N] [--whole-rule-only]
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, Phase, given, settings

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.helpers import subtree_disagreements  # noqa: E402
from tests.strategies import FIELDS, rule_and_events  # noqa: E402

from sigmaforge import evaluator, optimize, sqlite_runtime  # noqa: E402
from sigmaforge.ast import And, CmpMatch, NumMatch, Or, StrMatch  # noqa: E402
from sigmaforge.backends import sqlite as sqlbackend  # noqa: E402
from sigmaforge.compiler import compile_rule  # noqa: E402
from sigmaforge.rule import rule_from_dict  # noqa: E402
from sigmaforge.sigmastr import Shape  # noqa: E402


@dataclass(frozen=True)
class Mutant:
    name: str
    description: str
    patch: Callable[[], contextlib.AbstractContextManager[None]]


@contextlib.contextmanager
def setattr_temp(obj: Any, attr: str, value: Any) -> Iterator[None]:
    old = getattr(obj, attr)
    setattr(obj, attr, value)
    try:
        yield
    finally:
        setattr(obj, attr, old)


SQL = sqlbackend.SQLiteBackend
original_field_match = SQL.field_match


def field_match_override(
    predicate: Callable[[Any], bool], render: Callable[[Any, str, Any], str]
) -> Callable[[], contextlib.AbstractContextManager[None]]:
    def patched(self: Any, field: str, matcher: Any) -> str:
        if predicate(matcher):
            return render(self, field, matcher)
        return original_field_match(self, field, matcher)

    return lambda: setattr_temp(SQL, "field_match", patched)


def _col(field: str) -> str:
    return sqlbackend.quote_ident(field)


def _naive_simplify(node: Any) -> Any:
    """Flattens any nested And/Or into its parent, regardless of kind."""
    if isinstance(node, And | Or):
        out: list[Any] = []
        for child in node.children:
            child = _naive_simplify(child)  # noqa: PLW2901
            out.extend(child.children if isinstance(child, And | Or) else [child])
        return type(node)(tuple(out))
    return node


MUTANTS = [
    Mutant(
        "not-without-coalesce",
        "NOT (expr) instead of NOT coalesce(expr, 0): NULL leaks through negation",
        lambda: setattr_temp(SQL, "render_not", lambda self, c: f"NOT ({self.render(c)})"),
    ),
    Mutant(
        "like-no-escaping",
        "LIKE metacharacters % and _ not escaped",
        lambda: setattr_temp(sqlbackend, "escape_like", lambda t: t.replace("\\", "\\\\")),
    ),
    Mutant(
        "glob-no-escaping",
        "GLOB metacharacters * ? [ not escaped for cased matches",
        lambda: setattr_temp(sqlbackend, "escape_glob", lambda t: t),
    ),
    Mutant(
        "cased-uses-like",
        "cased modifier ignored (LIKE instead of GLOB)",
        field_match_override(
            lambda m: isinstance(m, StrMatch) and m.cased,
            lambda self, f, m: original_field_match(self, f, StrMatch(m.pattern, False)),
        ),
    ),
    Mutant(
        "number-as-text-only",
        "integer equality compares text only: col = '4688' (misses INTEGER storage)",
        field_match_override(
            lambda m: isinstance(m, NumMatch),
            lambda self, f, m: f"{_col(f)} = '{m.value}'",
        ),
    ),
    Mutant(
        "compare-without-typeof",
        "gt/lt without the typeof() guard: text values compare greater than numbers",
        field_match_override(
            lambda m: isinstance(m, CmpMatch),
            lambda self, f, m: f"{_col(f)} {sqlbackend.CMP_SQL[m.op]} {m.value!r}",
        ),
    ),
    Mutant(
        "bare-wildcard-true",
        "'*' compiled to constant true instead of IS NOT NULL",
        field_match_override(
            lambda m: isinstance(m, StrMatch) and m.pattern.shape()[0] is Shape.ANYTHING,
            lambda self, f, m: "1",
        ),
    ),
    Mutant(
        "regex-flags-dropped",
        "regex i/m/s flags not passed to SQLite",
        lambda: setattr_temp(sqlbackend, "regex_with_flags", lambda p, f: p),
    ),
    Mutant(
        "keyword-first-column-only",
        "keyword search only looks at the first keyword column",
        lambda: setattr_temp(
            SQL,
            "keyword_match",
            lambda self, m: original_field_match(self, self.keyword_columns[0], m),
        ),
    ),
    Mutant(
        "cidr-ignores-family",
        "SQLite CIDR helper ignores the IP version check",
        lambda: setattr_temp(
            sqlite_runtime,
            "_cidr_match",
            lambda net, v: None if v is None else _loose_cidr(net, v),
        ),
    ),
    Mutant(
        "evaluator-unicode-casefold",
        "evaluator folds non-ASCII case (re.IGNORECASE without re.ASCII)",
        lambda: setattr_temp(evaluator, "compile_wildcard", _unicode_wildcard),
    ),
    Mutant(
        "evaluator-numeric-text",
        "evaluator treats '04688' as equal to 4688 (int() of text)",
        lambda: setattr_temp(evaluator, "_scalar_matches", _loose_num_scalar_matches),
    ),
    Mutant(
        "simplifier-flattens-mixed",
        "simplifier flattens an OR nested in an AND (and vice versa)",
        lambda: setattr_temp(optimize, "simplify", _naive_simplify),
    ),
]


def _loose_cidr(network: str, value: Any) -> int:
    import ipaddress  # noqa: PLC0415

    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return 0
    net = ipaddress.ip_network(network)
    return int(address.version != net.version or address in net)


def _unicode_wildcard(pattern: Any, cased: bool) -> Any:
    import re  # noqa: PLC0415

    return re.compile(pattern.to_regex(), re.DOTALL if cased else re.DOTALL | re.IGNORECASE)


_real_scalar_matches = evaluator._scalar_matches


def _loose_num_scalar_matches(matcher: Any, value: Any) -> bool:
    if isinstance(matcher, NumMatch) and isinstance(value, str) and value.strip().isdigit():
        return int(value) == matcher.value
    return _real_scalar_matches(matcher, value)


def property_holds(examples: int, subtrees: bool = True) -> tuple[bool, str]:
    failure: list[str] = []

    @settings(
        max_examples=examples,
        derandomize=True,
        database=None,
        deadline=None,
        phases=[Phase.generate],
        suppress_health_check=list(HealthCheck),
    )
    @given(rule_and_events())
    def prop(case: tuple[dict[str, Any], list[dict[str, Any]]]) -> None:
        doc, events = case
        compiled = compile_rule(rule_from_dict(doc), optimize=True)
        query = SQL(keyword_columns=FIELDS).convert(compiled).text
        conn = sqlite_runtime.connect()
        sqlite_runtime.load_events(conn, events, extra_columns=FIELDS)
        got = sqlite_runtime.run_query(conn, query)
        want = evaluator.Evaluator(compiled.node).filter(events)
        assert got == want
        if subtrees:
            assert subtree_disagreements(compiled.node, events, FIELDS) == []
        raw = compile_rule(rule_from_dict(doc), optimize=False)
        assert evaluator.Evaluator(raw.node).filter(events) == want

    try:
        prop()
    except Exception as exc:
        failure.append(type(exc).__name__)
    return (not failure, failure[0] if failure else "")


def main() -> None:
    parser = argparse.ArgumentParser(description="seeded-bug kill rate of the differential test")
    parser.add_argument("--examples", type=int, default=300)
    parser.add_argument(
        "--whole-rule-only",
        action="store_true",
        help="skip the per-subtree comparison (to measure what it adds)",
    )
    args = parser.parse_args()
    subtrees = not args.whole_rule_only
    # compile_rule imported simplify by name; patch through the compiler module too.
    import sigmaforge.compiler as compiler_module  # noqa: PLC0415

    ok, _ = property_holds(args.examples, subtrees)
    if not ok:
        sys.exit("baseline (no mutant) fails the property - fix that first")
    mode = "whole rule only" if args.whole_rule_only else "whole rule + every subtree"
    print(f"{args.examples} examples per mutant, fixed seed, {mode}\n")
    print("| mutant | killed | seeded bug |\n|---|---|---|")
    killed = 0
    start = time.perf_counter()
    for mutant in MUTANTS:
        with mutant.patch(), _also_patch_compiler(mutant, compiler_module):
            holds, _ = property_holds(args.examples, subtrees)
        killed += not holds
        print(f"| {mutant.name} | {'yes' if not holds else 'NO'} | {mutant.description} |")
    elapsed = time.perf_counter() - start
    print(f"\nkilled {killed}/{len(MUTANTS)} mutants in {elapsed:.1f}s")


def _also_patch_compiler(
    mutant: Mutant, compiler_module: Any
) -> contextlib.AbstractContextManager[None]:
    if mutant.name == "simplifier-flattens-mixed":
        return setattr_temp(compiler_module, "simplify", _naive_simplify)
    return contextlib.nullcontext()


if __name__ == "__main__":
    main()
