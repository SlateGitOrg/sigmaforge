"""Front end: Sigma rule -> backend-neutral expression tree.

Steps for one rule:

1. compile every search identifier of ``detection`` into a node
   (mapping = AND of items, list of mappings = OR, list of scalars = keyword OR);
2. parse each ``condition`` string and resolve identifier references and
   ``1 of`` / ``all of`` quantifiers against the compiled identifiers
   (several conditions are OR-ed, as the Sigma specification prescribes);
3. run the processing pipelines (field mapping, extra conditions, backend state);
4. simplify the tree.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sigmaforge.ast import And, KeywordMatch, Node, Not, Or, StrMatch
from sigmaforge.condition import (
    CondAnd,
    CondExpr,
    CondNot,
    CondOr,
    CondQuantifier,
    CondRef,
    parse_condition,
)
from sigmaforge.errors import (
    SigmaConditionError,
    SigmaModifierError,
    SigmaRuleError,
)
from sigmaforge.modifiers import build_item
from sigmaforge.optimize import simplify
from sigmaforge.pipeline import Pipeline, PipelineContext, apply_pipelines
from sigmaforge.rule import LogSource, SigmaRule
from sigmaforge.sigmastr import SigmaString

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompiledRule:
    """A rule after the front end and pipelines: what every backend consumes."""

    rule: SigmaRule
    node: Node
    logsource: LogSource
    state: Mapping[str, str]
    applied: tuple[str, ...] = ()


def _keyword(value: Any) -> Node:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise SigmaModifierError(f"keyword {value!r} must be a string or integer")
    pattern = SigmaString.parse(str(value)).prepend_any().append_any()
    return KeywordMatch(StrMatch(pattern))


def _mapping(value: dict[Any, Any]) -> Node:
    if not value:
        raise SigmaRuleError("empty selection mapping")
    items = []
    for key, item in value.items():
        if not isinstance(key, str):
            raise SigmaRuleError(f"field key {key!r} must be a string")
        try:
            items.append(build_item(key, item))
        except SigmaModifierError as exc:
            raise SigmaModifierError(exc.message, location=exc.location or key) from exc
    return items[0] if len(items) == 1 else And(tuple(items))


def compile_search_identifier(value: Any) -> Node:
    """Compile the value of one search identifier into a node."""
    if isinstance(value, dict):
        return _mapping(value)
    if isinstance(value, list):
        if not value:
            raise SigmaRuleError("empty search identifier list")
        if all(isinstance(v, dict) for v in value):
            nodes = [_mapping(v) for v in value]
        elif not any(isinstance(v, dict | list) for v in value):
            nodes = [_keyword(v) for v in value]
        else:
            raise SigmaRuleError("a search identifier list mixes mappings and plain values")
        return nodes[0] if len(nodes) == 1 else Or(tuple(nodes))
    if isinstance(value, str | int) and not isinstance(value, bool):
        return _keyword(value)
    raise SigmaRuleError(f"unsupported search identifier value {value!r}")


def _identifier_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(".*".join(re.escape(piece) for piece in pattern.split("*")))


def resolve_condition(expr: CondExpr, identifiers: Mapping[str, Node], text: str) -> Node:
    """Replace identifier references in a condition tree by their compiled nodes."""
    match expr:
        case CondRef(name):
            if name not in identifiers:
                raise SigmaConditionError(f"unknown search identifier {name!r}", condition=text)
            return identifiers[name]
        case CondQuantifier(quant, pattern):
            if pattern is None:
                names = [n for n in identifiers if not n.startswith("_")]
            else:
                rx = _identifier_regex(pattern)
                names = [n for n in identifiers if rx.fullmatch(n)]
            if not names:
                raise SigmaConditionError(
                    f"'{pattern or 'them'}' matches no search identifier", condition=text
                )
            children = tuple(identifiers[n] for n in names)
            if len(children) == 1:
                return children[0]
            return Or(children) if quant == "one" else And(children)
        case CondNot(child):
            return Not(resolve_condition(child, identifiers, text))
        case CondAnd(left, right):
            return And(
                (
                    resolve_condition(left, identifiers, text),
                    resolve_condition(right, identifiers, text),
                )
            )
        case CondOr(left, right):
            return Or(
                (
                    resolve_condition(left, identifiers, text),
                    resolve_condition(right, identifiers, text),
                )
            )


def compile_detection(rule: SigmaRule) -> Node:
    """Front end only (no pipelines, no simplification)."""
    identifiers: dict[str, Node] = {}
    for name, value in rule.search_identifiers.items():
        try:
            identifiers[name] = compile_search_identifier(value)
        except SigmaRuleError as exc:
            location = f"detection.{name}" + (f".{exc.location}" if exc.location else "")
            raise type(exc)(exc.message, location=location) from exc
    nodes = [resolve_condition(parse_condition(c), identifiers, c) for c in rule.conditions]
    return nodes[0] if len(nodes) == 1 else Or(tuple(nodes))


def compile_rule(
    rule: SigmaRule, pipelines: Sequence[Pipeline] = (), *, optimize: bool = True
) -> CompiledRule:
    """Compile a rule, apply ``pipelines`` and (by default) simplify the tree."""
    ctx = PipelineContext(logsource=rule.logsource, node=compile_detection(rule))
    apply_pipelines(list(pipelines), ctx)
    node = simplify(ctx.node) if optimize else ctx.node
    log.debug("compiled %s (%s)", rule.title, rule.source)
    return CompiledRule(rule, node, ctx.logsource, dict(ctx.state), tuple(ctx.applied))
