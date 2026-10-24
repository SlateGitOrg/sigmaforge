"""Lexer and recursive-descent parser for Sigma ``condition`` expressions.

Grammar (keywords are case-insensitive)::

    condition  := or_expr [ "|" aggregation ]       # aggregations are rejected
    or_expr    := and_expr ( "or" and_expr )*
    and_expr   := not_expr ( "and" not_expr )*
    not_expr   := "not" not_expr | primary
    primary    := "(" or_expr ")" | quantifier | IDENT
    quantifier := ( "1" | "all" ) "of" ( IDENT_PATTERN | "them" )

``IDENT_PATTERN`` may contain ``*`` wildcards (``selection_*``). Precedence is the usual
``not`` > ``and`` > ``or``; both binary operators are left-associative. The parser produces a
small condition tree that :mod:`sigmaforge.compiler` later resolves against the rule's search
identifiers.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Literal

from sigmaforge.errors import SigmaConditionError, UnsupportedFeatureError


class Tok(enum.Enum):
    LPAREN = "("
    RPAREN = ")"
    AND = "and"
    OR = "or"
    NOT = "not"
    ONE_OF = "1 of"
    ALL_OF = "all of"
    THEM = "them"
    IDENT = "identifier"
    PIPE = "|"
    END = "end of condition"


@dataclass(frozen=True, slots=True)
class Token:
    kind: Tok
    text: str
    pos: int


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<pipe>\|)
  | (?P<oneof>1\s+of\b)
  | (?P<allof>all\s+of\b)
  | (?P<word>[A-Za-z0-9_*\-.]+)
    """,
    re.VERBOSE | re.IGNORECASE,
)
_KEYWORDS = {"and": Tok.AND, "or": Tok.OR, "not": Tok.NOT, "them": Tok.THEM}


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            raise SigmaConditionError(
                f"unexpected character {text[pos]!r}", condition=text, position=pos
            )
        kind = m.lastgroup
        value = m.group()
        if kind == "lparen":
            tokens.append(Token(Tok.LPAREN, value, pos))
        elif kind == "rparen":
            tokens.append(Token(Tok.RPAREN, value, pos))
        elif kind == "pipe":
            # Everything after '|' is an aggregation expression; the parser rejects it as a
            # whole, so its own syntax (count(), >, by ...) is never tokenized.
            tokens.append(Token(Tok.PIPE, value, pos))
            break
        elif kind == "oneof":
            tokens.append(Token(Tok.ONE_OF, value, pos))
        elif kind == "allof":
            tokens.append(Token(Tok.ALL_OF, value, pos))
        elif kind == "word":
            tokens.append(Token(_KEYWORDS.get(value.lower(), Tok.IDENT), value, pos))
        pos = m.end()
    tokens.append(Token(Tok.END, "", len(text)))
    return tokens


# --------------------------------------------------------------------------- condition tree


@dataclass(frozen=True, slots=True)
class CondRef:
    name: str


@dataclass(frozen=True, slots=True)
class CondQuantifier:
    """``1 of <pattern>`` / ``all of <pattern>``; ``pattern=None`` means ``them``."""

    quantifier: Literal["one", "all"]
    pattern: str | None


@dataclass(frozen=True, slots=True)
class CondAnd:
    left: CondExpr
    right: CondExpr


@dataclass(frozen=True, slots=True)
class CondOr:
    left: CondExpr
    right: CondExpr


@dataclass(frozen=True, slots=True)
class CondNot:
    child: CondExpr


CondExpr = CondRef | CondQuantifier | CondAnd | CondOr | CondNot


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = tokenize(text)
        self.i = 0

    @property
    def cur(self) -> Token:
        return self.tokens[self.i]

    def advance(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def error(self, message: str, tok: Token | None = None) -> SigmaConditionError:
        tok = tok or self.cur
        return SigmaConditionError(message, condition=self.text, position=tok.pos)

    def parse(self) -> CondExpr:
        if self.cur.kind is Tok.END:
            raise self.error("empty condition")
        expr = self.or_expr()
        tail = self.cur
        if tail.kind is Tok.PIPE:
            raise UnsupportedFeatureError(
                "aggregation", f"aggregation expressions ('| ...') are not supported: {self.text!r}"
            )
        if tail.kind is not Tok.END:
            raise self.error(f"unexpected {tail.text!r}")
        return expr

    def or_expr(self) -> CondExpr:
        left = self.and_expr()
        while self.cur.kind is Tok.OR:
            self.advance()
            left = CondOr(left, self.and_expr())
        return left

    def and_expr(self) -> CondExpr:
        left = self.not_expr()
        while self.cur.kind is Tok.AND:
            self.advance()
            left = CondAnd(left, self.not_expr())
        return left

    def not_expr(self) -> CondExpr:
        if self.cur.kind is Tok.NOT:
            self.advance()
            return CondNot(self.not_expr())
        return self.primary()

    def primary(self) -> CondExpr:
        tok = self.cur
        if tok.kind is Tok.LPAREN:
            self.advance()
            expr = self.or_expr()
            if self.cur.kind is not Tok.RPAREN:
                raise self.error(f"expected ')' to close '(' at column {tok.pos + 1}")
            self.advance()
            return expr
        if tok.kind in (Tok.ONE_OF, Tok.ALL_OF):
            self.advance()
            target = self.cur
            quant: Literal["one", "all"] = "one" if tok.kind is Tok.ONE_OF else "all"
            if target.kind is Tok.THEM:
                self.advance()
                return CondQuantifier(quant, None)
            if target.kind is Tok.IDENT:
                self.advance()
                return CondQuantifier(quant, target.text)
            raise self.error(f"expected identifier pattern or 'them' after {tok.text!r}", target)
        if tok.kind is Tok.IDENT:
            self.advance()
            if "*" in tok.text:
                raise self.error(f"wildcard identifier {tok.text!r} needs '1 of' or 'all of'", tok)
            return CondRef(tok.text)
        if tok.kind is Tok.END:
            raise self.error("unexpected end of condition")
        raise self.error(f"unexpected {tok.text!r}")


def parse_condition(text: str) -> CondExpr:
    """Parse one condition string into a condition tree."""
    return _Parser(text).parse()


def format_condition(expr: CondExpr) -> str:
    """Fully parenthesised text that :func:`parse_condition` maps back to ``expr``."""
    match expr:
        case CondRef(name):
            return name
        case CondQuantifier(quant, pattern):
            return f"{'1' if quant == 'one' else 'all'} of {pattern or 'them'}"
        case CondNot(child):
            return f"not {format_condition(child)}"
        case CondAnd(left, right):
            return f"({format_condition(left)} and {format_condition(right)})"
        case CondOr(left, right):
            return f"({format_condition(left)} or {format_condition(right)})"
