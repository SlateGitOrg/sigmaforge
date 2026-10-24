"""Regular-expression dialect handling.

Sigma ``|re`` values are PCRE-flavoured and *unanchored* (search semantics). Targets differ:

* Splunk ``match()`` and Python ``re``: PCRE-like, unanchored - passed through.
* KQL ``matches regex``: RE2 - no look-around, back-references, possessive quantifiers or atomic
  groups. :func:`check_re2` rejects those.
* EQL ``regex``/``regex~``: Lucene ``RegExp`` - always matches the *whole* value, has no
  anchors, no ``(?...)`` groups, treats ``\\n`` as a plain ``n`` and reserves ``# @ & < > ~``.
  :func:`to_lucene` translates the common subset and rejects the rest.

Both functions run on a small tokenizer that understands escapes, character classes and group
openers, so a ``(?=`` inside ``[...]`` or after a backslash is not mistaken for look-ahead.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from sigmaforge.errors import UnsupportedFeatureError

LUCENE_RESERVED = set('"#@&<>~')
CLASS_SHORTHANDS = {"d": "0-9", "w": "a-zA-Z0-9_", "s": " \\t\\n\\r\\f"}
CONTROL_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v"}
_GROUP_RE = re.compile(r"\((?:\?(?:P?<[A-Za-z_]\w*>|<=|<!|[=!:>]|[imsx]+\)|P=\w+\)))?")


@dataclass(frozen=True, slots=True)
class RxToken:
    kind: str  # escape | class | group | anchor_start | anchor_end | quant | lazy | literal
    text: str


def tokenize(pattern: str) -> Iterator[RxToken]:
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                raise UnsupportedFeatureError("regex syntax", f"trailing backslash in {pattern!r}")
            if pattern[i + 1] == "x" and i + 4 <= n:
                yield RxToken("escape", pattern[i : i + 4])
                i += 4
                continue
            yield RxToken("escape", pattern[i : i + 2])
            i += 2
        elif ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            if j >= n:
                raise UnsupportedFeatureError("regex syntax", f"unterminated class in {pattern!r}")
            yield RxToken("class", pattern[i : j + 1])
            i = j + 1
        elif ch == "(":
            m = _GROUP_RE.match(pattern, i)
            text = m.group() if m else "("
            if text == "(" and pattern.startswith("(?", i):
                text = "(?"  # unknown extension group; consumers reject it
            yield RxToken("group", text)
            i += len(text)
        elif ch == "^":
            yield RxToken("anchor_start", ch)
            i += 1
        elif ch == "$":
            yield RxToken("anchor_end", ch)
            i += 1
        elif ch in "*+?":
            yield RxToken("quant", ch)
            i += 1
            if i < n and pattern[i] in "?+":
                yield RxToken("lazy" if pattern[i] == "?" else "possessive", pattern[i])
                i += 1
        elif ch == "{":
            m = re.match(r"\{\d+(?:,\d*)?\}", pattern[i:])
            if m:
                yield RxToken("quant", m.group())
                i += len(m.group())
                if i < n and pattern[i] in "?+":
                    yield RxToken("lazy" if pattern[i] == "?" else "possessive", pattern[i])
                    i += 1
            else:
                yield RxToken("literal", ch)
                i += 1
        else:
            yield RxToken("literal", ch)
            i += 1


def check_re2(pattern: str) -> None:
    """Raise :class:`UnsupportedFeatureError` if ``pattern`` uses constructs RE2 lacks."""
    for tok in tokenize(pattern):
        if tok.kind == "group" and tok.text in ("(?=", "(?!", "(?<=", "(?<!"):
            raise UnsupportedFeatureError("regex look-around (RE2)", f"look-around in {pattern!r}")
        if tok.kind == "group" and tok.text in ("(?>",):
            raise UnsupportedFeatureError("regex atomic group (RE2)", f"atomic group {pattern!r}")
        if tok.kind == "possessive":
            raise UnsupportedFeatureError(
                "regex possessive quantifier (RE2)", f"possessive quantifier in {pattern!r}"
            )
        if tok.kind == "escape" and tok.text[1] in "123456789":
            raise UnsupportedFeatureError(
                "regex back-reference (RE2)", f"back-reference in {pattern!r}"
            )
        if tok.kind == "group" and tok.text.startswith("(?P="):
            raise UnsupportedFeatureError(
                "regex back-reference (RE2)", f"back-reference in {pattern!r}"
            )


def _lucene_unsupported(what: str, pattern: str) -> UnsupportedFeatureError:
    return UnsupportedFeatureError(f"regex {what} (Lucene)", f"{what} in {pattern!r}")


def _lucene_escape_char(ch: str) -> str:
    if ch.isalnum() or ch in " _-,:;'%/=!":
        return ch
    return "\\" + ch


def _translate_escape(text: str, pattern: str, in_class: bool) -> str:
    code = text[1:]
    if code in CLASS_SHORTHANDS:
        return CLASS_SHORTHANDS[code] if in_class else f"[{CLASS_SHORTHANDS[code]}]"
    if code in ("D", "W", "S"):
        if in_class:
            raise _lucene_unsupported("negated shorthand in class", pattern)
        return f"[^{CLASS_SHORTHANDS[code.lower()]}]"
    if code in CONTROL_ESCAPES:
        return CONTROL_ESCAPES[code]
    if code.startswith("x") and len(code) == 3:
        try:
            return _lucene_escape_char(chr(int(code[1:], 16)))
        except ValueError as exc:
            raise _lucene_unsupported("bad hex escape", pattern) from exc
    if code.isalnum():
        raise _lucene_unsupported(f"escape '\\{code}'", pattern)
    return "\\" + code


def _translate_class(text: str, pattern: str) -> str:
    if "[:" in text:
        raise _lucene_unsupported("POSIX class", pattern)
    out = ["["]
    body = text[1:-1]
    i = 0
    if body.startswith("^"):
        out.append("^")
        i = 1
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            end = i + 4 if body[i + 1] == "x" else i + 2
            out.append(_translate_escape(body[i:end], pattern, in_class=True))
            i = end
            continue
        out.append("\\" + ch if ch in LUCENE_RESERVED or ch == "[" else ch)
        i += 1
    out.append("]")
    return "".join(out)


def _has_top_level_alternation(tokens: list[RxToken]) -> bool:
    depth = 0
    for tok in tokens:
        if tok.kind == "group":
            depth += 1
        elif tok.kind == "literal" and tok.text == ")":
            depth -= 1
        elif tok.kind == "literal" and tok.text == "|" and depth == 0:
            return True
    return False


def to_lucene(pattern: str, flags: frozenset[str] = frozenset()) -> tuple[str, bool]:
    """Translate an unanchored PCRE pattern to a Lucene whole-value regex.

    Returns ``(regex, case_insensitive)``. Raises :class:`UnsupportedFeatureError` for
    constructs without a faithful Lucene equivalent.
    """
    tokens = list(tokenize(pattern))
    insensitive = "i" in flags
    if tokens and tokens[0].kind == "group" and re.fullmatch(r"\(\?[imsx]+\)", tokens[0].text):
        letters = set(tokens[0].text[2:-1])
        if letters - {"i"}:
            raise _lucene_unsupported("inline flags other than (?i)", pattern)
        insensitive = True
        tokens = tokens[1:]
    if "m" in flags:
        raise _lucene_unsupported("multiline flag", pattern)
    anchored_start = bool(tokens) and tokens[0].kind == "anchor_start"
    anchored_end = bool(tokens) and tokens[-1].kind == "anchor_end"
    body = tokens[1 if anchored_start else 0 : len(tokens) - 1 if anchored_end else len(tokens)]
    alternation = _has_top_level_alternation(body)
    if alternation and (anchored_start or anchored_end):
        raise _lucene_unsupported("anchored top-level alternation", pattern)
    out: list[str] = []
    for tok in body:
        match tok.kind:
            case "escape":
                out.append(_translate_escape(tok.text, pattern, in_class=False))
            case "class":
                out.append(_translate_class(tok.text, pattern))
            case "group":
                if tok.text == "(" or tok.text == "(?:" or tok.text.startswith(("(?<", "(?P<")):
                    if tok.text in ("(?<=", "(?<!"):
                        raise _lucene_unsupported("look-around", pattern)
                    out.append("(")
                else:
                    raise _lucene_unsupported(f"group '{tok.text}'", pattern)
            case "anchor_start" | "anchor_end":
                raise _lucene_unsupported("inner anchor", pattern)
            case "quant":
                out.append(tok.text)
            case "lazy":
                pass  # laziness never changes whether a whole-value match exists
            case "possessive":
                raise _lucene_unsupported("possessive quantifier", pattern)
            case _:
                ch = tok.text
                out.append("\\" + ch if ch in LUCENE_RESERVED or ch in "{}" else ch)
    regex = "".join(out)
    if alternation:
        regex = f"({regex})"
    if not anchored_start:
        regex = ".*" + regex
    if not anchored_end:
        regex = regex + ".*"
    return regex, insensitive


def literal_to_lucene(text: str) -> str:
    """Escape ``text`` so Lucene matches it literally."""
    return "".join(_lucene_escape_char(c) for c in text)
