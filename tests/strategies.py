"""Hypothesis strategies that generate random Sigma rules and matching-relevant events.

Rules are generated at the *YAML level* (detection dicts with modifier keys and condition
strings), so the whole front end - modifiers, condition parser, quantifiers, simplifier - is in
the loop, not just the backends.

The alphabet is chosen to stress escaping: LIKE/GLOB metacharacters (``%``, ``_``, ``[``),
Sigma wildcards and escapes (``*``, ``?``, ``\\``), SQL quotes, and non-ASCII letters whose case
folding is backend-defined (``é``/``É``, the Kelvin sign).
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

from sigmaforge.condition import (
    CondAnd,
    CondExpr,
    CondNot,
    CondOr,
    CondQuantifier,
    CondRef,
    format_condition,
)

FIELDS = ["Image", "CommandLine", "User", "EventID", "DestinationIp", "Port"]
ALPHABET = "abAB01-/_%\\'\"*?[]. éÉKk"
IDENTIFIERS = ["sel1", "sel2", "filter_a", "_helper"]

texts = st.text(alphabet=ALPHABET, max_size=6)
ints = st.integers(min_value=-5, max_value=70000)
ips = st.sampled_from(
    ["10.1.2.3", "10.255.0.1", "192.168.1.7", "192.168.2.7", "8.8.8.8", "::1", "2001:db8::5"]
)
networks = st.sampled_from(
    ["10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0", "::1/128", "2001:db8::/32", "8.8.8.8/32"]
)
regexes = st.sampled_from(
    ["^a", "b$", "a.b", "[0-9]+", "(?:ab|cd)", "\\\\", "A", "^$", "é", "x*y?", "^[a-z]+$", "%_"]
)

event_values = st.one_of(st.none(), texts, ints, ips)
events = st.lists(
    st.dictionaries(st.sampled_from(FIELDS), event_values, max_size=len(FIELDS)), max_size=8
)


def _mined_values(obj: Any) -> list[Any]:
    """Every scalar that appears in a detection, to seed events that actually hit the rule."""
    if isinstance(obj, dict):
        return [v for value in obj.values() for v in _mined_values(value)]
    if isinstance(obj, list):
        return [v for value in obj for v in _mined_values(value)]
    if isinstance(obj, str | int) and not isinstance(obj, bool):
        return [obj]
    return []


@st.composite
def _near_miss(draw: st.DrawFn, seed: Any) -> Any:
    """A value derived from ``seed``: wildcards filled, case flipped, padded, or as-is."""
    if isinstance(seed, int):
        return draw(st.sampled_from([seed, str(seed), seed + 1, f"0{seed}"]))
    filled = "".join(
        draw(texts) if ch == "*" else (draw(st.sampled_from("aZ%")) if ch == "?" else ch)
        for ch in seed.replace("\\*", "*")
    )
    variant = draw(st.sampled_from(["same", "upper", "lower", "swap", "pad"]))
    if variant == "upper":
        filled = filled.upper()
    elif variant == "lower":
        filled = filled.lower()
    elif variant == "swap":
        filled = filled.swapcase()
    elif variant == "pad":
        filled = draw(texts) + filled + draw(texts)
    return filled


def events_for(doc: dict[str, Any]) -> st.SearchStrategy[list[dict[str, Any]]]:
    """Events biased towards values mentioned in the rule, plus fully random ones."""
    seeds = [v for v in _mined_values(doc["detection"]) if v != doc["detection"]["condition"]]
    value = event_values
    if seeds:
        value = st.one_of(event_values, st.sampled_from(seeds).flatmap(_near_miss))
    return st.lists(
        st.dictionaries(st.sampled_from(FIELDS), value, max_size=len(FIELDS)), max_size=8
    )


@st.composite
def rule_and_events(draw: st.DrawFn) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    doc = draw(rule_yaml_dict())
    return doc, draw(events_for(doc))


@st.composite
def detection_item(draw: st.DrawFn) -> tuple[str, Any]:
    field = draw(st.sampled_from(FIELDS))
    kind = draw(
        st.sampled_from(
            [
                "plain",
                "contains",
                "startswith",
                "endswith",
                "contains_all",
                "cased",
                "contains_cased",
                "re",
                "re_i",
                "cidr",
                "cmp",
                "exists",
                "null",
                "int",
                "windash",
                "base64offset",
            ]
        )
    )
    many = st.lists(texts, min_size=1, max_size=3)
    match kind:
        case "plain":
            return field, draw(st.one_of(texts, many))
        case "contains" | "startswith" | "endswith":
            return f"{field}|{kind}", draw(st.one_of(texts, many))
        case "contains_all":
            return f"{field}|contains|all", draw(many)
        case "cased":
            return f"{field}|cased", draw(texts)
        case "contains_cased":
            return f"{field}|contains|cased", draw(many)
        case "re":
            return f"{field}|re", draw(regexes)
        case "re_i":
            return f"{field}|re|i", draw(regexes)
        case "cidr":
            return f"{field}|cidr", draw(st.one_of(networks, st.lists(networks, min_size=1)))
        case "cmp":
            op = draw(st.sampled_from(["gt", "gte", "lt", "lte"]))
            return f"{field}|{op}", draw(ints)
        case "exists":
            return f"{field}|exists", draw(st.booleans())
        case "null":
            return field, None
        case "int":
            return field, draw(st.one_of(ints, st.lists(ints, min_size=1, max_size=3)))
        case "windash":
            return f"{field}|windash|contains", draw(st.sampled_from(["-a", "/b x", "a -k"]))
        case _:
            return f"{field}|base64offset|contains", draw(st.sampled_from(["ab", "abc", "é1"]))


@st.composite
def selection(draw: st.DrawFn) -> Any:
    """A selection: a mapping, a list of mappings, or a keyword list."""
    form = draw(st.sampled_from(["map", "map", "map", "list_of_maps", "keywords"]))

    def mapping() -> dict[str, Any]:
        items = draw(st.lists(detection_item(), min_size=1, max_size=3))
        return dict(items)  # duplicate keys collapse, as YAML would reject them anyway

    if form == "map":
        return mapping()
    if form == "list_of_maps":
        return [mapping() for _ in range(draw(st.integers(1, 3)))]
    return draw(st.lists(texts.filter(bool), min_size=1, max_size=3))


def condition_tree(names: list[str]) -> st.SearchStrategy[CondExpr]:
    base = st.one_of(
        st.sampled_from(names).map(CondRef),
        st.sampled_from(["one", "all"]).map(lambda q: CondQuantifier(q, None)),  # type: ignore[arg-type]
        st.sampled_from(["one", "all"]).map(lambda q: CondQuantifier(q, "sel*")),  # type: ignore[arg-type]
    )
    return st.recursive(
        base,
        lambda inner: st.one_of(
            st.builds(CondAnd, inner, inner),
            st.builds(CondOr, inner, inner),
            st.builds(CondNot, inner),
        ),
        max_leaves=6,
    )


@st.composite
def rule_yaml_dict(draw: st.DrawFn) -> dict[str, Any]:
    count = draw(st.integers(min_value=1, max_value=len(IDENTIFIERS)))
    names = IDENTIFIERS[:count]
    if "sel1" not in names:
        names = ["sel1", *names]
    detection: dict[str, Any] = {name: draw(selection()) for name in names}
    detection["condition"] = format_condition(draw(condition_tree(names)))
    return {
        "title": "generated",
        "logsource": {"product": "test"},
        "detection": detection,
    }
