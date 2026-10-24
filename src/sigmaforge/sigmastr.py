"""Sigma string values with wildcards.

Sigma string values use ``*`` (any run of characters, including none) and ``?`` (exactly one
character) as wildcards. A backslash escapes a wildcard or another backslash; a backslash in
front of any other character is a literal backslash (this keeps Windows paths readable:
``C:\\Windows\\cmd.exe`` needs no doubling).

:class:`SigmaString` stores the parsed form as a tuple of parts, each either a literal ``str``
or a :class:`Wildcard`. Backends never see raw Sigma syntax; they ask the string to render
itself with their own escaping and wildcard tokens.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass


class Wildcard(enum.Enum):
    """A wildcard token inside a Sigma string."""

    ANY = "*"
    ONE = "?"


Part = str | Wildcard


class Shape(enum.Enum):
    """Coarse classification that backends use to pick a native string operator."""

    EXACT = "exact"  # no wildcards
    CONTAINS = "contains"  # *literal*
    STARTSWITH = "startswith"  # literal*
    ENDSWITH = "endswith"  # *literal
    ANYTHING = "anything"  # just "*"
    PATTERN = "pattern"  # any other wildcard layout


def _normalise(parts: Iterator[Part] | list[Part] | tuple[Part, ...]) -> tuple[Part, ...]:
    """Merge adjacent literals, drop empty literals and collapse runs of ``*``."""
    out: list[Part] = []
    for part in parts:
        if isinstance(part, str):
            if not part:
                continue
            if out and isinstance(out[-1], str):
                out[-1] = out[-1] + part
                continue
        elif part is Wildcard.ANY and out and out[-1] is Wildcard.ANY:
            continue
        out.append(part)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class SigmaString:
    """An immutable, parsed Sigma string."""

    parts: tuple[Part, ...]

    # ------------------------------------------------------------------ construction
    @classmethod
    def parse(cls, text: str) -> SigmaString:
        """Parse Sigma syntax (wildcards and backslash escapes)."""
        parts: list[Part] = []
        buf: list[str] = []
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text) and text[i + 1] in "*?\\":
                buf.append(text[i + 1])
                i += 2
                continue
            if ch in "*?":
                if buf:
                    parts.append("".join(buf))
                    buf = []
                parts.append(Wildcard.ANY if ch == "*" else Wildcard.ONE)
            else:
                buf.append(ch)
            i += 1
        if buf:
            parts.append("".join(buf))
        return cls(_normalise(parts))

    @classmethod
    def literal(cls, text: str) -> SigmaString:
        """A string with no wildcards at all, whatever characters it contains."""
        return cls(_normalise([text]))

    @classmethod
    def from_parts(cls, parts: list[Part] | tuple[Part, ...]) -> SigmaString:
        return cls(_normalise(parts))

    # ------------------------------------------------------------------ queries
    def is_plain(self) -> bool:
        """True when the string contains no wildcards."""
        return all(isinstance(p, str) for p in self.parts)

    def has_wildcard(self, wildcard: Wildcard) -> bool:
        return wildcard in self.parts

    def plain_text(self) -> str:
        """The literal text of a wildcard-free string."""
        if not self.is_plain():
            raise ValueError(f"{self} contains wildcards")
        return "".join(p for p in self.parts if isinstance(p, str))

    def shape(self) -> tuple[Shape, str]:
        """Classify the string and return the literal core for simple shapes.

        For ``PATTERN`` the returned text is empty; callers must use :meth:`render` or
        :meth:`to_regex` instead.
        """
        p = self.parts
        if not p:
            return Shape.EXACT, ""
        if p == (Wildcard.ANY,):
            return Shape.ANYTHING, ""
        if self.is_plain():
            return Shape.EXACT, self.plain_text()
        if len(p) == 3 and p[0] is Wildcard.ANY and p[2] is Wildcard.ANY and isinstance(p[1], str):
            return Shape.CONTAINS, p[1]
        if len(p) == 2 and isinstance(p[0], str) and p[1] is Wildcard.ANY:
            return Shape.STARTSWITH, p[0]
        if len(p) == 2 and p[0] is Wildcard.ANY and isinstance(p[1], str):
            return Shape.ENDSWITH, p[1]
        return Shape.PATTERN, ""

    # ------------------------------------------------------------------ transformation
    def prepend_any(self) -> SigmaString:
        return SigmaString(_normalise((Wildcard.ANY, *self.parts)))

    def append_any(self) -> SigmaString:
        return SigmaString(_normalise((*self.parts, Wildcard.ANY)))

    def map_literals(self, fn: Callable[[str], str]) -> SigmaString:
        """Apply ``fn`` to every literal run, leaving wildcards in place."""
        return SigmaString(_normalise([fn(p) if isinstance(p, str) else p for p in self.parts]))

    # ------------------------------------------------------------------ rendering
    def render(
        self,
        escape: Callable[[str], str],
        any_token: str,
        one_token: str | None,
    ) -> str:
        """Render for a backend: literals through ``escape``, wildcards as given tokens.

        ``one_token=None`` means the target has no single-character wildcard; callers must
        check :meth:`has_wildcard` first, and we raise if they forgot.
        """
        out: list[str] = []
        for part in self.parts:
            if isinstance(part, str):
                out.append(escape(part))
            elif part is Wildcard.ANY:
                out.append(any_token)
            else:
                if one_token is None:
                    raise ValueError("target has no single-character wildcard")
                out.append(one_token)
        return "".join(out)

    def to_regex(self) -> str:
        """A Python/PCRE/RE2-compatible regex that must match the *whole* value."""
        return self.render(re.escape, ".*", ".")

    def __str__(self) -> str:
        def esc(text: str) -> str:
            return text.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")

        return self.render(esc, "*", "?")

    def __repr__(self) -> str:
        return f"SigmaString({str(self)!r})"
