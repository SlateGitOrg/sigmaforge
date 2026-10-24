"""Sigma rule documents: strict YAML loading and the :class:`SigmaRule` model.

YAML 1.1 (what PyYAML implements) silently turns ``0x1410`` into ``5136``, ``010`` into ``8``,
``yes`` into ``True`` and ``2024-01-01`` into a ``date``. Each of those would change what a
detection matches, so rules are read with :class:`SigmaYAMLLoader`, which only resolves plain
decimal integers/floats, ``true``/``false`` and ``null``; everything else stays a string.
Duplicate mapping keys are an error instead of last-one-wins.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sigmaforge.errors import SigmaRuleError, UnsupportedFeatureError

log = logging.getLogger(__name__)


class SigmaYAMLLoader(yaml.SafeLoader):
    """SafeLoader with conservative scalar typing and duplicate-key detection."""


# Replace PyYAML's implicit resolvers with a conservative set.
SigmaYAMLLoader.yaml_implicit_resolvers = {}
SigmaYAMLLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)
SigmaYAMLLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^(?:[-+]?(?:0|[1-9][0-9]*))$"), list("-+0123456789")
)
SigmaYAMLLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(r"^(?:[-+]?(?:0|[1-9][0-9]*)\.[0-9]+)$"),
    list("-+0123456789"),
)
SigmaYAMLLoader.add_implicit_resolver(
    "tag:yaml.org,2002:null", re.compile(r"^(?:~|null|Null|NULL|)$"), ["~", "n", "N", ""]
)


def _construct_mapping(loader: SigmaYAMLLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in result:
            mark = key_node.start_mark
            raise SigmaRuleError(
                f"duplicate key {key!r}", location=f"line {mark.line + 1}, column {mark.column + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=True)
    return result


SigmaYAMLLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml_documents(text: str, source: str = "<string>") -> list[Any]:
    """Parse every YAML document in ``text`` with the Sigma loader."""
    try:
        return list(yaml.load_all(text, Loader=SigmaYAMLLoader))  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise SigmaRuleError(f"YAML syntax error: {exc}", location=source) from exc


@dataclass(frozen=True, slots=True)
class LogSource:
    category: str | None = None
    product: str | None = None
    service: str | None = None

    def __str__(self) -> str:
        bits = [f"{k}={v}" for k, v in self.as_dict().items()]
        return " ".join(bits) or "(any)"

    def as_dict(self) -> dict[str, str]:
        out = {"category": self.category, "product": self.product, "service": self.service}
        return {k: v for k, v in out.items() if v is not None}


@dataclass(frozen=True, slots=True)
class SigmaRule:
    """A parsed Sigma rule. ``detection`` keeps the raw search identifiers."""

    title: str
    detection: dict[str, Any]
    conditions: tuple[str, ...]
    logsource: LogSource = field(default_factory=LogSource)
    id: str | None = None
    status: str | None = None
    level: str | None = None
    description: str | None = None
    tags: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    source: str = "<string>"

    @property
    def search_identifiers(self) -> dict[str, Any]:
        return {k: v for k, v in self.detection.items() if k not in ("condition", "timeframe")}


def _opt_str(doc: dict[str, Any], key: str, source: str) -> str | None:
    value = doc.get(key)
    if value is None:
        return None
    if isinstance(value, str | int | float):
        return str(value)
    raise SigmaRuleError(f"'{key}' must be a string", location=source)


def _str_list(doc: dict[str, Any], key: str, source: str) -> tuple[str, ...]:
    value = doc.get(key)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str | int | float) for v in value):
        return tuple(str(v) for v in value)
    raise SigmaRuleError(f"'{key}' must be a list of strings", location=source)


def rule_from_dict(doc: Any, source: str = "<string>") -> SigmaRule:
    """Validate a decoded YAML document and build a :class:`SigmaRule`."""
    if not isinstance(doc, dict):
        raise SigmaRuleError("rule document must be a mapping", location=source)
    if "correlation" in doc:
        raise UnsupportedFeatureError("correlation rule", "correlation rules are not supported")
    if doc.get("action") is not None:
        raise UnsupportedFeatureError(
            "rule collection action", f"rule collection 'action: {doc['action']}' is not supported"
        )
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        raise SigmaRuleError("missing or empty 'title'", location=source)
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaRuleError("'detection' must be a mapping", location=source)
    raw_condition = detection.get("condition")
    if isinstance(raw_condition, str):
        conditions: tuple[str, ...] = (raw_condition,)
    elif (
        isinstance(raw_condition, list)
        and raw_condition
        and all(isinstance(c, str) for c in raw_condition)
    ):
        conditions = tuple(raw_condition)
    else:
        raise SigmaRuleError(
            "'detection.condition' must be a string or a list of strings", location=source
        )
    for name in detection:
        if not isinstance(name, str):
            raise SigmaRuleError(f"search identifier {name!r} must be a string", location=source)
    raw_ls = doc.get("logsource", {})
    if not isinstance(raw_ls, dict):
        raise SigmaRuleError("'logsource' must be a mapping", location=source)
    logsource = LogSource(
        category=_opt_str(raw_ls, "category", source),
        product=_opt_str(raw_ls, "product", source),
        service=_opt_str(raw_ls, "service", source),
    )
    return SigmaRule(
        title=title.strip(),
        detection=detection,
        conditions=conditions,
        logsource=logsource,
        id=_opt_str(doc, "id", source),
        status=_opt_str(doc, "status", source),
        level=_opt_str(doc, "level", source),
        description=_opt_str(doc, "description", source),
        tags=_str_list(doc, "tags", source),
        falsepositives=_str_list(doc, "falsepositives", source),
        source=source,
    )


def parse_rule(text: str, source: str = "<string>") -> SigmaRule:
    """Parse exactly one Sigma rule from YAML text."""
    docs = [d for d in load_yaml_documents(text, source) if d is not None]
    if not docs:
        raise SigmaRuleError("empty document", location=source)
    if len(docs) > 1:
        raise UnsupportedFeatureError(
            "multi-document rule file", f"{source}: {len(docs)} YAML documents in one rule file"
        )
    return rule_from_dict(docs[0], source)


def load_rule(path: Path) -> SigmaRule:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SigmaRuleError(f"cannot read rule file: {exc}", location=str(path)) from exc
    return parse_rule(text, str(path))


RULE_SUFFIXES = (".yml", ".yaml")


def iter_rule_files(paths: Iterable[Path]) -> Iterator[Path]:
    """Expand files and directories (recursively) into a sorted stream of rule files."""
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix in RULE_SUFFIXES)
        elif path.exists():
            yield path
        else:
            raise SigmaRuleError("no such file or directory", location=str(path))
