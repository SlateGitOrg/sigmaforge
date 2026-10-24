"""Reference in-memory evaluator: the executable definition of what a compiled rule means.

Backends are judged against this module, so its semantics are deliberately explicit:

* **Field lookup.** An exact key wins; otherwise a dotted name walks nested mappings
  (``process.name`` finds ``{"process": {"name": ...}}``). A list value matches if any element
  matches.
* **Text view.** Strings are themselves, integers their decimal text, booleans ``true`` /
  ``false``; ``None`` and missing fields have no text and match nothing except
  ``null``/``exists: false``.
* **Strings.** Wildcard patterns match the *whole* text. Matching is case-insensitive for ASCII
  letters only (the portable common ground: SQLite ``LIKE``, Splunk and KQL all fold ASCII);
  ``cased`` makes it exact.
* **Regex.** Python ``re.search`` (unanchored) with the ``i``/``m``/``s`` flags.
* **Numbers.** ``NumMatch(n)`` matches an integer equal to ``n`` or the exact text ``str(n)``;
  ``gt``/``lt``... only compare real numeric values, never numeric-looking strings.
* **CIDR.** The text must parse as an IP address of the network's family and lie inside it.
* **Keywords.** True if the pattern matches any leaf value anywhere in the event.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from sigmaforge.ast import (
    And,
    CidrMatch,
    CmpMatch,
    Const,
    ExistsMatch,
    FieldMatch,
    KeywordMatch,
    Matcher,
    Node,
    Not,
    NullMatch,
    NumMatch,
    Or,
    RegexMatch,
    StrMatch,
)
from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.sigmastr import SigmaString

_MISSING = object()


def value_text(value: Any) -> str | None:
    """The text view of a scalar event value (see module docstring)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int | float):
        return str(value)
    return None


def lookup(event: Mapping[str, Any], field: str) -> Any:
    """Resolve ``field`` in ``event``; returns the sentinel ``_MISSING`` when absent."""
    if field in event:
        return event[field]
    current: Any = event
    for part in field.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def iter_leaf_values(value: Any) -> Iterator[Any]:
    if isinstance(value, Mapping):
        for item in value.values():
            yield from iter_leaf_values(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from iter_leaf_values(item)
    else:
        yield value


@functools.lru_cache(maxsize=4096)
def compile_wildcard(pattern: SigmaString, cased: bool) -> re.Pattern[str]:
    flags = re.DOTALL if cased else re.DOTALL | re.IGNORECASE | re.ASCII
    return re.compile(pattern.to_regex(), flags)


@functools.lru_cache(maxsize=4096)
def compile_regex(pattern: str, flags: frozenset[str]) -> re.Pattern[str]:
    value = 0
    if "i" in flags:
        value |= re.IGNORECASE
    if "m" in flags:
        value |= re.MULTILINE
    if "s" in flags:
        value |= re.DOTALL
    try:
        return re.compile(pattern, value)
    except re.error as exc:
        raise UnsupportedFeatureError(
            "regex dialect", f"regex {pattern!r} is not valid for Python re: {exc}"
        ) from exc


def _scalar_matches(matcher: Matcher, value: Any) -> bool:
    if isinstance(value, list | tuple):
        return any(_scalar_matches(matcher, item) for item in value)
    text = value_text(value)
    match matcher:
        case StrMatch(pattern, cased):
            return text is not None and compile_wildcard(pattern, cased).fullmatch(text) is not None
        case RegexMatch(pattern, flags):
            return text is not None and compile_regex(pattern, flags).search(text) is not None
        case NumMatch(number):
            if isinstance(value, bool):
                return False
            if isinstance(value, int):
                return value == number
            return isinstance(value, str) and value == str(number)
        case CmpMatch(op, number):
            if isinstance(value, bool) or not isinstance(value, int | float):
                return False
            return {
                "gt": value > number,
                "gte": value >= number,
                "lt": value < number,
                "lte": value <= number,
            }[op]
        case CidrMatch(network):
            if text is None:
                return False
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                return False
            net = ipaddress.ip_network(network)
            return address.version == net.version and address in net
        case NullMatch() | ExistsMatch():  # pragma: no cover - handled by the caller
            raise AssertionError("presence matchers are evaluated on the raw lookup")


def field_matches(event: Mapping[str, Any], field: str, matcher: Matcher) -> bool:
    raw = lookup(event, field)
    if isinstance(matcher, NullMatch):
        return raw is _MISSING or raw is None
    if isinstance(matcher, ExistsMatch):
        present = raw is not _MISSING and raw is not None
        return present == matcher.present
    if raw is _MISSING or raw is None:
        return False
    return _scalar_matches(matcher, raw)


def evaluate(node: Node, event: Mapping[str, Any]) -> bool:
    """True if ``event`` satisfies the expression tree."""
    match node:
        case FieldMatch(field, matcher):
            return field_matches(event, field, matcher)
        case KeywordMatch(matcher):
            return any(
                v is not None and _scalar_matches(matcher, v) for v in iter_leaf_values(event)
            )
        case And(children):
            return all(evaluate(c, event) for c in children)
        case Or(children):
            return any(evaluate(c, event) for c in children)
        case Not(child):
            return not evaluate(child, event)
        case Const(value):
            return value


class Evaluator:
    """Convenience wrapper binding one expression tree."""

    def __init__(self, node: Node) -> None:
        self.node = node

    def matches(self, event: Mapping[str, Any]) -> bool:
        return evaluate(self.node, event)

    def filter(self, events: Sequence[Mapping[str, Any]]) -> list[int]:
        """Indices of matching events."""
        return [i for i, e in enumerate(events) if self.matches(e)]
