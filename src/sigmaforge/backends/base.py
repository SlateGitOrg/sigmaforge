"""Shared backend machinery: precedence-aware rendering and IN-list grouping.

A backend subclasses :class:`Backend` (or :class:`TextRenderer` for a secondary dialect) and
implements the leaf hooks (:meth:`TextRenderer.field_match`, :meth:`TextRenderer.keyword_match`)
plus the boolean tokens. Parenthesisation is computed from operator precedence, so output has
no redundant parentheses and is still unambiguous.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from sigmaforge.ast import (
    And,
    Const,
    FieldMatch,
    KeywordMatcher,
    KeywordMatch,
    Matcher,
    Node,
    Not,
    Or,
    StrMatch,
)
from sigmaforge.compiler import CompiledRule
from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.sigmastr import Shape, SigmaString

log = logging.getLogger(__name__)

PREC_OR = 1
PREC_AND = 2
PREC_NOT = 3
PREC_ATOM = 4


@dataclass(frozen=True)
class Query:
    """One compiled query plus provenance."""

    backend: str
    text: str
    title: str
    rule_id: str | None
    source: str
    pipelines_applied: tuple[str, ...] = ()
    meta: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "title": self.title,
            "id": self.rule_id,
            "source": self.source,
            "query": self.text,
            "pipelines_applied": list(self.pipelines_applied),
            **({"meta": dict(self.meta)} if self.meta else {}),
        }


class TextRenderer(ABC):
    """Renders an expression tree in one textual dialect."""

    backend_name: ClassVar[str] = "?"
    and_token: ClassVar[str] = "and"
    or_token: ClassVar[str] = "or"

    # ------------------------------------------------------------------ hooks
    @abstractmethod
    def field_match(self, field: str, matcher: Matcher) -> str: ...

    @abstractmethod
    def keyword_match(self, matcher: KeywordMatcher) -> str: ...

    @abstractmethod
    def render_not(self, child: Node) -> str: ...

    def const(self, value: bool) -> str:
        raise self.unsupported("constant expression", "rule reduces to a constant")

    def in_list(self, field: str, values: list[str], cased: bool) -> str | None:
        """Render ``field`` equal to any of ``values`` as one atom, or ``None`` to decline."""
        return None

    # ------------------------------------------------------------------ helpers
    def unsupported(self, feature: str, message: str | None = None) -> UnsupportedFeatureError:
        return UnsupportedFeatureError(feature, message, backend=self.backend_name)

    @staticmethod
    def precedence(node: Node) -> int:
        if isinstance(node, Or):
            return PREC_OR
        if isinstance(node, And):
            return PREC_AND
        if isinstance(node, Not):
            return PREC_NOT
        return PREC_ATOM

    def render(self, node: Node, parent_prec: int = 0) -> str:
        if isinstance(node, Or):
            parts = self._or_parts(node.children)
            text = f" {self.or_token} ".join(parts)
            prec = PREC_OR if len(parts) > 1 else PREC_ATOM
        elif isinstance(node, And):
            text = f" {self.and_token} ".join(self.render(c, PREC_AND) for c in node.children)
            prec = PREC_AND
        elif isinstance(node, Not):
            text = self.render_not(node.child)
            prec = PREC_NOT
        elif isinstance(node, FieldMatch):
            text, prec = self.field_match(node.field, node.matcher), PREC_ATOM
        elif isinstance(node, KeywordMatch):
            text, prec = self.keyword_match(node.matcher), PREC_ATOM
        else:
            text, prec = self.const(node.value), PREC_ATOM
        return f"({text})" if prec < parent_prec else text

    def _or_parts(self, children: tuple[Node, ...]) -> list[str]:
        """Render OR children, folding exact-match leaves on one field into IN-lists."""
        groups: dict[tuple[str, bool], list[str]] = {}
        order: list[tuple[str, bool] | Node] = []
        for child in children:
            if isinstance(child, FieldMatch) and isinstance(child.matcher, StrMatch):
                shape, text = child.matcher.pattern.shape()
                if shape is Shape.EXACT:
                    key = (child.field, child.matcher.cased)
                    if key not in groups:
                        groups[key] = []
                        order.append(key)
                    groups[key].append(text)
                    continue
            order.append(child)
        parts: list[str] = []
        for item in order:
            if isinstance(item, tuple):
                (name, cased), values = item, groups[item]
                folded = self.in_list(name, values, cased) if len(values) > 1 else None
                if folded is not None:
                    parts.append(folded)
                    continue
                parts.extend(
                    self.render(FieldMatch(name, StrMatch(SigmaString.literal(v), cased)), PREC_OR)
                    for v in values
                )
            else:
                parts.append(self.render(item, PREC_OR))
        return parts


class Backend(TextRenderer):
    """A complete query target."""

    name: ClassVar[str] = "?"
    description: ClassVar[str] = ""
    default_pipelines: ClassVar[tuple[str, ...]] = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.backend_name = cls.name

    def convert(self, compiled: CompiledRule) -> Query:
        """Render a compiled rule; raises :class:`UnsupportedFeatureError` when it cannot."""
        text = self.finalize(compiled)
        return Query(
            backend=self.name,
            text=text,
            title=compiled.rule.title,
            rule_id=compiled.rule.id,
            source=compiled.rule.source,
            pipelines_applied=compiled.applied,
        )

    def finalize(self, compiled: CompiledRule) -> str:
        """Wrap the rendered expression into a complete query (table, index, ...)."""
        return self.render(compiled.node)
