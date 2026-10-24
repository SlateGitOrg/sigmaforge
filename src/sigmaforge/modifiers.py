"""Value modifiers: turn one detection item (``Field|mod1|mod2: values``) into AST nodes.

Modifiers are applied left to right to every value. A value can expand into several
*alternatives* (``windash``, ``base64offset``), which are OR-ed. Several values for one field
are OR-ed too, unless the ``all`` modifier asks for AND.

Supported: ``contains startswith endswith all re i m s cidr cased exists gt gte lt lte
base64 base64offset wide utf16le utf16be utf16 windash``. ``expand`` and ``fieldref`` are
recognised and rejected with :class:`UnsupportedFeatureError` so the compile report can count
them; anything else is a :class:`SigmaModifierError`.
"""

from __future__ import annotations

import base64
import ipaddress
import itertools
import re
from dataclasses import dataclass
from typing import Any

from sigmaforge.ast import (
    And,
    CidrMatch,
    CmpMatch,
    CompareOp,
    ExistsMatch,
    FieldMatch,
    KeywordMatch,
    Matcher,
    Node,
    NullMatch,
    NumMatch,
    Or,
    RegexMatch,
    StrMatch,
)
from sigmaforge.errors import SigmaModifierError, UnsupportedFeatureError
from sigmaforge.sigmastr import SigmaString, Wildcard

STRING_MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "windash", "base64", "base64offset"}
    | {"wide", "utf16le", "utf16be", "utf16"}
)
REGEX_FLAGS = {"i": "i", "ignorecase": "i", "m": "m", "multiline": "m", "s": "s", "dotall": "s"}
COMPARE_OPS: dict[str, CompareOp] = {"gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte"}
UNSUPPORTED = {
    "expand": "placeholder expansion ('expand') needs a placeholder pipeline",
    "fieldref": "field-to-field comparison ('fieldref')",
}
KNOWN = (
    STRING_MODIFIERS
    | set(REGEX_FLAGS)
    | set(COMPARE_OPS)
    | {"all", "re", "cidr", "cased", "exists"}
    | set(UNSUPPORTED)
)

# Characters ``windash`` substitutes for a leading '-' or '/': hyphen, slash, en dash, em dash,
# horizontal bar (the set used by SigmaHQ's specification).
WINDASH_CHARS = ("-", "/", "\u2013", "\u2014", "\u2015")
WINDASH_RE = re.compile(r"\B[-/]\b")
MAX_WINDASH_VARIANTS = 625  # 5 ** 4; more dashes than that is almost certainly a mistake


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """Parsed ``Field|mod|mod`` key. ``field`` is ``None`` for key-less (keyword) items."""

    field: str | None
    modifiers: tuple[str, ...]

    @classmethod
    def parse(cls, key: str) -> FieldSpec:
        name, *mods = key.split("|")
        return cls(name or None, tuple(m.strip().lower() for m in mods))


def _encode(value: SigmaString | bytes, encoding: str, mod: str) -> bytes:
    if isinstance(value, bytes):
        raise SigmaModifierError(f"'{mod}' cannot be applied to an already-encoded value")
    if not value.is_plain():
        raise SigmaModifierError(f"'{mod}' cannot encode a value containing wildcards")
    return value.plain_text().encode(encoding)


def _to_bytes(value: SigmaString | bytes, mod: str) -> bytes:
    if isinstance(value, bytes):
        return value
    return _encode(value, "utf-8", mod)


def base64_offsets(data: bytes) -> list[str]:
    """The three base64 renderings of ``data`` at offsets 0, 1 and 2 inside a larger blob.

    Characters influenced by unknown neighbouring bytes are trimmed so each variant can be
    searched for with ``contains``.
    """
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for i in range(3):
        encoded = base64.b64encode(i * b" " + data).decode("ascii")
        out.append(encoded[start[i] : end[(len(data) + i) % 3]])
    return out


def windash_variants(value: SigmaString) -> list[SigmaString]:
    """Expand every word-leading '-' or '/' into each Windows dash character."""
    pieces: list[list[str | Wildcard]] = []  # literal fragments between dash positions
    current: list[str | Wildcard] = []
    dash_count = 0
    for part in value.parts:
        if not isinstance(part, str):
            current.append(part)
            continue
        last = 0
        for m in WINDASH_RE.finditer(part):
            current.append(part[last : m.start()])
            pieces.append(current)
            current = []
            dash_count += 1
            last = m.end()
        current.append(part[last:])
    pieces.append(current)
    if dash_count == 0:
        return [value]
    if len(WINDASH_CHARS) ** dash_count > MAX_WINDASH_VARIANTS:
        raise SigmaModifierError(f"'windash' would expand {value} into too many variants")
    variants = []
    for combo in itertools.product(WINDASH_CHARS, repeat=dash_count):
        parts: list[str | Wildcard] = list(pieces[0])
        for dash, piece in zip(combo, pieces[1:], strict=True):
            parts.append(dash)
            parts.extend(piece)
        variants.append(SigmaString.from_parts(parts))
    return variants


def _scalar_to_sigma(raw: Any) -> SigmaString | int | float | bool | None:
    if raw is None or isinstance(raw, bool | int | float):
        return raw
    if isinstance(raw, str):
        return SigmaString.parse(raw)
    raise SigmaModifierError(f"unsupported value type {type(raw).__name__}: {raw!r}")


Alternative = SigmaString | bytes


def build_item(key: str, raw_values: Any) -> Node:
    """Compile one detection item into an AST node."""
    spec = FieldSpec.parse(key)
    values = raw_values if isinstance(raw_values, list) else [raw_values]
    if not values:
        raise SigmaModifierError(f"'{key}' has an empty value list")
    for mod in spec.modifiers:
        if mod in UNSUPPORTED:
            raise UnsupportedFeatureError(f"modifier '{mod}'", UNSUPPORTED[mod])
        if mod not in KNOWN:
            raise SigmaModifierError(f"unknown modifier '{mod}' in '{key}'")
    try:
        nodes = [_build_value(spec, v) for v in values]
    except SigmaModifierError as exc:
        raise SigmaModifierError(exc.message, location=key) from exc
    if len(nodes) == 1:
        return nodes[0]
    return And(tuple(nodes)) if "all" in spec.modifiers else Or(tuple(nodes))


def _leaf(spec: FieldSpec, matcher: Matcher) -> Node:
    if spec.field is None:
        if not isinstance(matcher, StrMatch | RegexMatch):
            raise SigmaModifierError("keyword items only support string and regex values")
        return KeywordMatch(matcher)
    return FieldMatch(spec.field, matcher)


def _build_value(spec: FieldSpec, raw: Any) -> Node:
    mods = spec.modifiers
    value = _scalar_to_sigma(raw)

    if "exists" in mods:
        if not isinstance(value, bool) or len(mods) != 1:
            raise SigmaModifierError("'exists' takes a boolean and no other modifiers")
        return _leaf(spec, ExistsMatch(value))
    if value is None:
        if mods:
            raise SigmaModifierError("null values cannot take modifiers")
        return _leaf(spec, NullMatch())
    if isinstance(value, bool):
        # Booleans compare as their lowercase text (see DECISIONS.md).
        value = SigmaString.literal("true" if value else "false")

    compare = [m for m in mods if m in COMPARE_OPS]
    if compare:
        if len(mods) != 1 or not isinstance(value, int | float):
            raise SigmaModifierError(f"'{compare[0]}' takes a number and no other modifiers")
        return _leaf(spec, CmpMatch(COMPARE_OPS[compare[0]], value))

    if "re" in mods:
        return _leaf(spec, _regex_matcher(mods, raw))
    if any(m in REGEX_FLAGS for m in mods):
        raise SigmaModifierError("regex flags ('i', 'm', 's') require the 're' modifier")

    if "cidr" in mods:
        if set(mods) - {"cidr", "all"} or not isinstance(raw, str):
            raise SigmaModifierError("'cidr' takes a network string and no other modifiers")
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise SigmaModifierError(f"invalid CIDR network {raw!r}") from exc
        return _leaf(spec, CidrMatch(str(network)))

    cased = "cased" in mods
    if isinstance(value, int | float) and not any(m in STRING_MODIFIERS for m in mods):
        if isinstance(value, float):
            return _leaf(spec, StrMatch(SigmaString.literal(repr(value)), cased))
        return _leaf(spec, NumMatch(value))
    if isinstance(value, int | float):
        value = SigmaString.literal(str(value))

    alternatives: list[Alternative] = [value]
    for mod in mods:
        alternatives = [out for alt in alternatives for out in _apply_string_modifier(mod, alt)]
    matchers: list[Node] = []
    for alt in alternatives:
        if isinstance(alt, bytes):
            raise SigmaModifierError("encoded value must be followed by 'base64' or 'base64offset'")
        matchers.append(_leaf(spec, StrMatch(alt, cased)))
    return matchers[0] if len(matchers) == 1 else Or(tuple(matchers))


def _apply_string_modifier(mod: str, value: Alternative) -> list[Alternative]:
    if mod in ("all", "cased"):
        return [value]
    if mod in ("contains", "startswith", "endswith"):
        if isinstance(value, bytes):
            raise SigmaModifierError(f"'{mod}' cannot follow an encoding modifier without base64")
        if mod == "contains":
            return [value.prepend_any().append_any()]
        return [value.append_any() if mod == "startswith" else value.prepend_any()]
    if mod == "windash":
        if isinstance(value, bytes):
            raise SigmaModifierError("'windash' must come before encoding modifiers")
        return list(windash_variants(value))
    if mod in ("wide", "utf16le"):
        return [_encode(value, "utf-16-le", mod)]
    if mod == "utf16be":
        return [_encode(value, "utf-16-be", mod)]
    if mod == "utf16":
        return [b"\xff\xfe" + _encode(value, "utf-16-le", mod)]
    if mod == "base64":
        return [SigmaString.literal(base64.b64encode(_to_bytes(value, mod)).decode("ascii"))]
    if mod == "base64offset":
        return [SigmaString.literal(v) for v in base64_offsets(_to_bytes(value, mod))]
    raise SigmaModifierError(f"modifier '{mod}' cannot be combined here")  # pragma: no cover


def _regex_matcher(mods: tuple[str, ...], raw: Any) -> RegexMatch:
    extra = set(mods) - {"re", "all"} - set(REGEX_FLAGS)
    if extra:
        raise SigmaModifierError(f"'re' cannot be combined with {sorted(extra)}")
    if not isinstance(raw, str):
        raise SigmaModifierError("'re' needs a string pattern")
    # The pattern is deliberately not compiled here: Sigma regexes are PCRE-flavoured and each
    # backend validates against its own engine (Python ``re`` for the evaluator/SQLite, RE2 for
    # KQL, Lucene for EQL), so one engine's verdict must not reject the rule for all of them.
    flags = frozenset(REGEX_FLAGS[m] for m in mods if m in REGEX_FLAGS)
    return RegexMatch(raw, flags)
