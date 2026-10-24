"""YAML processing pipelines: field mapping and target-specific rewrites.

Sigma rules are written against generic log field names (Sysmon/Windows style). A pipeline
adapts a compiled rule to a concrete data model before a backend renders it:

``field_name_mapping``
    Rename fields. A list target maps one field to several (the leaf becomes an OR).
    ``fallback_prefix`` prefixes every field the mapping does not mention.
``field_name_prefix``
    Prefix every field name.
``add_condition``
    AND an extra detection mapping (same syntax as a Sigma selection) onto the rule.
``set_state``
    Store a backend parameter (``kql_table``, ``eql_category``, ``splunk_prefix``, ``sql_table``).
``change_logsource``
    Rewrite the logsource seen by later transformations.
``field_allowlist``
    Fail the rule if it uses a field outside the target schema.
``rule_failure``
    Fail the rule with a fixed message (for logsources a target cannot serve).

Every transformation may carry ``rule_conditions`` (logsource matches) joined by
``rule_condition_linking: all|any``; it then runs only for matching rules. Pipelines are
applied in ascending ``priority`` order, transformations in file order.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any, ClassVar

from sigmaforge.ast import And, FieldMatch, Leaf, Node, Or, fields, transform_leaves
from sigmaforge.errors import PipelineError, SigmaForgeError, UnsupportedFeatureError
from sigmaforge.rule import LogSource, load_yaml_documents

log = logging.getLogger(__name__)


@dataclass
class PipelineContext:
    """Mutable state threaded through every transformation of a compilation."""

    logsource: LogSource
    node: Node
    state: dict[str, str] = field(default_factory=dict)
    applied: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class LogsourceCondition:
    category: str | None = None
    product: str | None = None
    service: str | None = None

    def matches(self, ls: LogSource) -> bool:
        return all(
            want is None or want == have
            for want, have in (
                (self.category, ls.category),
                (self.product, ls.product),
                (self.service, ls.service),
            )
        )


@dataclass(frozen=True)
class Transformation(ABC):
    """Base class; subclasses register under their YAML ``type`` name."""

    id: str | None = None
    conditions: tuple[LogsourceCondition, ...] = ()
    linking: str = "all"

    registry: ClassVar[dict[str, type[Transformation]]] = {}
    type_name: ClassVar[str] = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.type_name:
            Transformation.registry[cls.type_name] = cls

    def applies_to(self, ctx: PipelineContext) -> bool:
        if not self.conditions:
            return True
        results = (c.matches(ctx.logsource) for c in self.conditions)
        return all(results) if self.linking == "all" else any(results)

    @abstractmethod
    def apply(self, ctx: PipelineContext) -> None: ...

    @classmethod
    @abstractmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> Transformation: ...


def _require(params: dict[str, Any], key: str, kind: type | tuple[type, ...], where: str) -> Any:
    if key not in params:
        raise PipelineError(f"missing '{key}'", location=where)
    value = params[key]
    if not isinstance(value, kind):
        raise PipelineError(f"'{key}' has the wrong type ({type(value).__name__})", location=where)
    return value


@dataclass(frozen=True)
class FieldNameMapping(Transformation):
    type_name: ClassVar[str] = "field_name_mapping"
    mapping: tuple[tuple[str, tuple[str, ...]], ...] = ()
    fallback_prefix: str | None = None

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> FieldNameMapping:
        raw = _require(params, "mapping", dict, "field_name_mapping")
        mapping: list[tuple[str, tuple[str, ...]]] = []
        for src, dst in raw.items():
            targets = (dst,) if isinstance(dst, str) else dst
            if not (
                isinstance(targets, list | tuple)
                and targets
                and all(isinstance(t, str) and t for t in targets)
            ):
                raise PipelineError(
                    f"mapping for {src!r} must be a field name or a non-empty list of names",
                    location="field_name_mapping",
                )
            mapping.append((str(src), tuple(targets)))
        prefix = params.get("fallback_prefix")
        if prefix is not None and not isinstance(prefix, str):
            raise PipelineError("'fallback_prefix' must be a string", location="field_name_mapping")
        return cls(mapping=tuple(mapping), fallback_prefix=prefix, **common)

    def apply(self, ctx: PipelineContext) -> None:
        table = dict(self.mapping)

        def rename(leaf: Leaf) -> Node:
            if not isinstance(leaf, FieldMatch):
                return leaf
            targets = table.get(leaf.field)
            if targets is None:
                if self.fallback_prefix is None:
                    return leaf
                return replace(leaf, field=self.fallback_prefix + leaf.field)
            if len(targets) == 1:
                return replace(leaf, field=targets[0])
            return Or(tuple(replace(leaf, field=t) for t in targets))

        ctx.node = transform_leaves(ctx.node, rename)


@dataclass(frozen=True)
class FieldNamePrefix(Transformation):
    type_name: ClassVar[str] = "field_name_prefix"
    prefix: str = ""

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> FieldNamePrefix:
        return cls(prefix=_require(params, "prefix", str, cls.type_name), **common)

    def apply(self, ctx: PipelineContext) -> None:
        def add(leaf: Leaf) -> Node:
            if isinstance(leaf, FieldMatch):
                return replace(leaf, field=self.prefix + leaf.field)
            return leaf

        ctx.node = transform_leaves(ctx.node, add)


@dataclass(frozen=True)
class AddCondition(Transformation):
    type_name: ClassVar[str] = "add_condition"
    condition: Node | None = None
    source: tuple[tuple[str, Any], ...] = ()

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> AddCondition:
        # Imported lazily: the compiler imports this module.
        from sigmaforge.compiler import compile_search_identifier  # noqa: PLC0415

        raw = _require(params, "conditions", dict, cls.type_name)
        try:
            node = compile_search_identifier(raw)
        except SigmaForgeError as exc:
            raise PipelineError(f"invalid conditions: {exc}", location=cls.type_name) from exc
        return cls(condition=node, source=tuple(raw.items()), **common)

    def apply(self, ctx: PipelineContext) -> None:
        if self.condition is None:  # only constructible without one by direct instantiation
            raise PipelineError("add_condition has no condition", location=self.id)
        ctx.node = And((self.condition, ctx.node))


@dataclass(frozen=True)
class SetState(Transformation):
    type_name: ClassVar[str] = "set_state"
    key: str = ""
    value: str = ""

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> SetState:
        key = _require(params, "key", str, cls.type_name)
        value = _require(params, "val", (str, int), cls.type_name)
        return cls(key=key, value=str(value), **common)

    def apply(self, ctx: PipelineContext) -> None:
        ctx.state[self.key] = self.value


@dataclass(frozen=True)
class ChangeLogsource(Transformation):
    type_name: ClassVar[str] = "change_logsource"
    new: LogsourceCondition = field(default_factory=LogsourceCondition)

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> ChangeLogsource:
        new = LogsourceCondition(
            category=params.get("category"),
            product=params.get("product"),
            service=params.get("service"),
        )
        return cls(new=new, **common)

    def apply(self, ctx: PipelineContext) -> None:
        ls = ctx.logsource
        ctx.logsource = LogSource(
            category=self.new.category or ls.category,
            product=self.new.product or ls.product,
            service=self.new.service or ls.service,
        )


@dataclass(frozen=True)
class FieldAllowlist(Transformation):
    type_name: ClassVar[str] = "field_allowlist"
    allowed: frozenset[str] = frozenset()
    target: str = "the target schema"

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> FieldAllowlist:
        allowed = _require(params, "fields", list, cls.type_name)
        target = params.get("target", "the target schema")
        return cls(allowed=frozenset(str(f) for f in allowed), target=str(target), **common)

    def apply(self, ctx: PipelineContext) -> None:
        unknown = [f for f in fields(ctx.node) if f not in self.allowed]
        if unknown:
            raise UnsupportedFeatureError(
                "unmapped field",
                f"field(s) {', '.join(unknown)} have no mapping in {self.target}",
            )


@dataclass(frozen=True)
class RuleFailure(Transformation):
    type_name: ClassVar[str] = "rule_failure"
    message: str = ""
    feature: str = "unsupported logsource"

    @classmethod
    def from_params(cls, params: dict[str, Any], common: dict[str, Any]) -> RuleFailure:
        message = _require(params, "message", str, cls.type_name)
        feature = str(params.get("feature", "unsupported logsource"))
        return cls(message=message, feature=feature, **common)

    def apply(self, ctx: PipelineContext) -> None:
        raise UnsupportedFeatureError(self.feature, self.message)


def _parse_conditions(raw: Any, where: str) -> tuple[LogsourceCondition, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PipelineError("'rule_conditions' must be a list", location=where)
    out = []
    for item in raw:
        if not isinstance(item, dict) or item.get("type") != "logsource":
            raise PipelineError("only 'type: logsource' rule conditions exist", location=where)
        unknown = set(item) - {"type", "category", "product", "service"}
        if unknown:
            raise PipelineError(f"unknown logsource keys {sorted(unknown)}", location=where)
        out.append(
            LogsourceCondition(item.get("category"), item.get("product"), item.get("service"))
        )
    return tuple(out)


@dataclass(frozen=True)
class Pipeline:
    name: str
    transformations: tuple[Transformation, ...]
    priority: int = 50
    description: str = ""

    @classmethod
    def from_dict(cls, doc: Any, source: str = "<string>") -> Pipeline:
        if not isinstance(doc, dict):
            raise PipelineError("pipeline document must be a mapping", location=source)
        name = doc.get("name")
        if not isinstance(name, str) or not name:
            raise PipelineError("pipeline needs a 'name'", location=source)
        raw_items = doc.get("transformations")
        if not isinstance(raw_items, list):
            raise PipelineError("'transformations' must be a list", location=source)
        items: list[Transformation] = []
        for index, raw in enumerate(raw_items):
            where = f"{source}: transformations[{index}]"
            if not isinstance(raw, dict):
                raise PipelineError("transformation must be a mapping", location=where)
            kind = raw.get("type")
            impl = Transformation.registry.get(str(kind))
            if impl is None:
                known = ", ".join(sorted(Transformation.registry))
                raise PipelineError(f"unknown type {kind!r} (known: {known})", location=where)
            linking = raw.get("rule_condition_linking", "all")
            if linking not in ("all", "any"):
                raise PipelineError("'rule_condition_linking' must be all|any", location=where)
            common = {
                "id": raw.get("id"),
                "conditions": _parse_conditions(raw.get("rule_conditions"), where),
                "linking": linking,
            }
            params = {
                k: v
                for k, v in raw.items()
                if k not in ("type", "id", "rule_conditions", "rule_condition_linking")
            }
            try:
                items.append(impl.from_params(params, common))
            except PipelineError as exc:
                raise PipelineError(exc.message, location=where) from exc
        priority = doc.get("priority", 50)
        if not isinstance(priority, int):
            raise PipelineError("'priority' must be an integer", location=source)
        return cls(name, tuple(items), priority, str(doc.get("description", "")))

    @classmethod
    def from_yaml(cls, text: str, source: str = "<string>") -> Pipeline:
        try:
            docs = load_yaml_documents(text, source)
        except SigmaForgeError as exc:
            raise PipelineError(exc.message, location=source) from exc
        if len(docs) != 1:
            raise PipelineError("expected exactly one YAML document", location=source)
        return cls.from_dict(docs[0], source)

    def apply(self, ctx: PipelineContext) -> None:
        for index, item in enumerate(self.transformations):
            if not item.applies_to(ctx):
                continue
            item.apply(ctx)
            label = f"{self.name}:{item.id or f'{item.type_name}[{index}]'}"
            ctx.applied.append(label)
            log.debug("applied %s", label)


def apply_pipelines(pipelines: list[Pipeline], ctx: PipelineContext) -> None:
    for pipeline in sorted(pipelines, key=lambda p: p.priority):
        pipeline.apply(ctx)


BUILTIN_PACKAGE = "sigmaforge.pipelines"


def builtin_pipelines() -> dict[str, str]:
    """Map of built-in pipeline name to its description."""
    out = {}
    for entry in sorted(resources.files(BUILTIN_PACKAGE).iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yml"):
            pipeline = Pipeline.from_yaml(entry.read_text(encoding="utf-8"), entry.name)
            out[pipeline.name] = pipeline.description
    return out


def load_pipeline(spec: str) -> Pipeline:
    """Load a pipeline from a YAML path or by built-in name."""
    path = Path(spec)
    if path.suffix in (".yml", ".yaml") or path.exists():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PipelineError(f"cannot read pipeline: {exc}", location=spec) from exc
        return Pipeline.from_yaml(text, spec)
    resource = resources.files(BUILTIN_PACKAGE) / f"{spec}.yml"
    if not resource.is_file():
        known = ", ".join(builtin_pipelines())
        raise PipelineError(f"unknown pipeline {spec!r} (built-in: {known})")
    return Pipeline.from_yaml(resource.read_text(encoding="utf-8"), f"builtin:{spec}")
