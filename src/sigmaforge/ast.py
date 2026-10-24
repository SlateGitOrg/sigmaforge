"""The compiled detection expression tree.

A rule's ``detection`` block plus its ``condition`` compile into a tree of boolean nodes whose
leaves test one field (or, for keywords, any field) with a *matcher*. The tree is
backend-neutral: every backend and the reference evaluator consume exactly this structure, which
is what makes differential testing between them meaningful.

All nodes are frozen dataclasses, so trees are hashable, comparable and safe to share.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Literal

from sigmaforge.sigmastr import SigmaString

# --------------------------------------------------------------------------- matchers


@dataclass(frozen=True, slots=True)
class StrMatch:
    """Wildcard string match; case-insensitive (ASCII) unless ``cased``."""

    pattern: SigmaString
    cased: bool = False


@dataclass(frozen=True, slots=True)
class RegexMatch:
    """Unanchored regular-expression search. ``flags`` is a subset of ``{"i", "m", "s"}``."""

    pattern: str
    flags: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class CidrMatch:
    """The field holds an IP address inside ``network`` (normalised, e.g. ``10.0.0.0/8``)."""

    network: str

    @property
    def version(self) -> int:
        return ipaddress.ip_network(self.network).version


@dataclass(frozen=True, slots=True)
class NumMatch:
    """Integer equality. Matches an integer field value or its exact decimal text."""

    value: int


CompareOp = Literal["gt", "gte", "lt", "lte"]


@dataclass(frozen=True, slots=True)
class CmpMatch:
    """Numeric ordering comparison against a numeric field value."""

    op: CompareOp
    value: int | float


@dataclass(frozen=True, slots=True)
class NullMatch:
    """The field is absent or null."""


@dataclass(frozen=True, slots=True)
class ExistsMatch:
    """``|exists: true`` / ``|exists: false``."""

    present: bool


Matcher = StrMatch | RegexMatch | CidrMatch | NumMatch | CmpMatch | NullMatch | ExistsMatch
KeywordMatcher = StrMatch | RegexMatch

# --------------------------------------------------------------------------- nodes


@dataclass(frozen=True, slots=True)
class FieldMatch:
    """Leaf: ``matcher`` applied to the value of ``field``."""

    field: str
    matcher: Matcher


@dataclass(frozen=True, slots=True)
class KeywordMatch:
    """Leaf: ``matcher`` applied to every field value; true if any matches."""

    matcher: KeywordMatcher


@dataclass(frozen=True, slots=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Or:
    children: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Not:
    child: Node


@dataclass(frozen=True, slots=True)
class Const:
    """Constant truth value. Only produced by optimisation of degenerate trees."""

    value: bool


Node = FieldMatch | KeywordMatch | And | Or | Not | Const
Leaf = FieldMatch | KeywordMatch


# --------------------------------------------------------------------------- traversal


def walk(node: Node) -> Iterator[Node]:
    """Pre-order traversal."""
    stack: list[Node] = [node]
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, And | Or):
            stack.extend(reversed(current.children))
        elif isinstance(current, Not):
            stack.append(current.child)


def leaves(node: Node) -> Iterator[Leaf]:
    for n in walk(node):
        if isinstance(n, FieldMatch | KeywordMatch):
            yield n


def fields(node: Node) -> list[str]:
    """Distinct field names referenced by the tree, in first-seen order."""
    seen: dict[str, None] = {}
    for leaf in leaves(node):
        if isinstance(leaf, FieldMatch):
            seen.setdefault(leaf.field, None)
    return list(seen)


def transform_leaves(node: Node, fn: Callable[[Leaf], Node]) -> Node:
    """Rebuild the tree, replacing every leaf by ``fn(leaf)``."""
    if isinstance(node, FieldMatch | KeywordMatch):
        return fn(node)
    if isinstance(node, And):
        return And(tuple(transform_leaves(c, fn) for c in node.children))
    if isinstance(node, Or):
        return Or(tuple(transform_leaves(c, fn) for c in node.children))
    if isinstance(node, Not):
        return Not(transform_leaves(node.child, fn))
    return node


# --------------------------------------------------------------------------- printing


def describe_matcher(m: Matcher) -> str:
    match m:
        case StrMatch(pattern, cased):
            return f'{"cased " if cased else ""}str "{pattern}"'
        case RegexMatch(pattern, flags):
            suffix = f" /{''.join(sorted(flags))}" if flags else ""
            return f"re {pattern!r}{suffix}"
        case CidrMatch(network):
            return f"cidr {network}"
        case NumMatch(value):
            return f"num {value}"
        case CmpMatch(op, value):
            return f"{op} {value}"
        case NullMatch():
            return "null"
        case ExistsMatch(present):
            return "exists" if present else "missing"


def to_sexpr(node: Node, indent: int = 0) -> str:
    """Readable, indented S-expression form used by ``sigmaforge ast`` and golden tests."""
    pad = "  " * indent
    match node:
        case FieldMatch(name, matcher):
            return f"{pad}({name} {describe_matcher(matcher)})"
        case KeywordMatch(matcher):
            return f"{pad}(keyword {describe_matcher(matcher)})"
        case Const(value):
            return f"{pad}({'true' if value else 'false'})"
        case Not(child):
            return f"{pad}(not\n{to_sexpr(child, indent + 1)})"
        case And(children) | Or(children):
            op = "and" if isinstance(node, And) else "or"
            inner = "\n".join(to_sexpr(c, indent + 1) for c in children)
            return f"{pad}({op}\n{inner})"
