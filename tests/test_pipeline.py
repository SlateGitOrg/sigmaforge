from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sigmaforge.ast import And, FieldMatch, KeywordMatch, NumMatch, Or, StrMatch, fields
from sigmaforge.compiler import compile_rule
from sigmaforge.errors import PipelineError, UnsupportedFeatureError
from sigmaforge.pipeline import Pipeline, builtin_pipelines, load_pipeline
from sigmaforge.rule import rule_from_dict
from sigmaforge.sigmastr import SigmaString


def rule(detection: dict[str, Any], **logsource: str) -> Any:
    return rule_from_dict({"title": "t", "logsource": logsource, "detection": detection})


def pipeline(text: str) -> Pipeline:
    return Pipeline.from_yaml(text)


MAPPING = """
name: test
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      Image: process.executable
      User: [user.name, user.id]
    rule_conditions: [{type: logsource, product: windows}]
"""


def test_field_mapping_one_to_one_and_one_to_many() -> None:
    r = rule({"sel": {"Image": "a", "User": "b"}, "condition": "sel"}, product="windows")
    compiled = compile_rule(r, [pipeline(MAPPING)])
    assert fields(compiled.node) == ["process.executable", "user.name", "user.id"]
    assert isinstance(compiled.node, And)
    assert isinstance(compiled.node.children[1], Or)
    assert compiled.applied == ("test:map",)


def test_rule_conditions_gate_transformations() -> None:
    r = rule({"sel": {"Image": "a"}, "condition": "sel"}, product="linux")
    compiled = compile_rule(r, [pipeline(MAPPING)])
    assert fields(compiled.node) == ["Image"]
    assert compiled.applied == ()


def test_keywords_are_not_renamed() -> None:
    r = rule({"kw": ["x"], "condition": "kw"}, product="windows")
    node = compile_rule(r, [pipeline(MAPPING)]).node
    assert isinstance(node, KeywordMatch)


def test_fallback_prefix_prefix_add_condition_and_state() -> None:
    p = pipeline(
        """
name: combo
priority: 5
transformations:
  - type: field_name_mapping
    mapping: {EventID: event.code}
    fallback_prefix: winlog.event_data.
  - type: add_condition
    conditions: {event.kind: event}
  - type: set_state
    key: kql_table
    val: SecurityEvent
  - type: change_logsource
    service: security
  - type: set_state
    key: marker
    val: 7
    rule_conditions: [{type: logsource, service: security}]
"""
    )
    r = rule({"sel": {"EventID": 4625, "LogonType": 3}, "condition": "sel"}, product="windows")
    compiled = compile_rule(r, [p])
    assert fields(compiled.node) == ["event.kind", "event.code", "winlog.event_data.LogonType"]
    assert compiled.state == {"kql_table": "SecurityEvent", "marker": "7"}
    assert compiled.logsource.service == "security"
    assert compiled.logsource.product == "windows"


def test_field_name_prefix_and_priority_order() -> None:
    first = pipeline(
        "name: a\npriority: 1\ntransformations: [{type: field_name_prefix, prefix: x.}]"
    )
    second = pipeline(
        "name: b\npriority: 9\ntransformations: [{type: field_name_prefix, prefix: y.}]"
    )
    r = rule({"sel": {"F": 1}, "condition": "sel"})
    assert compile_rule(r, [second, first]).node == FieldMatch("y.x.F", NumMatch(1))


def test_allowlist_and_rule_failure() -> None:
    p = pipeline(
        """
name: strict
transformations:
  - type: field_allowlist
    target: T
    fields: [A]
"""
    )
    with pytest.raises(UnsupportedFeatureError, match="B have no mapping in T") as info:
        compile_rule(rule({"sel": {"A": 1, "B": 2}, "condition": "sel"}), [p])
    assert info.value.feature == "unmapped field"
    fail = pipeline(
        "name: f\ntransformations: [{type: rule_failure, message: nope, feature: no table}]"
    )
    with pytest.raises(UnsupportedFeatureError, match="nope") as info:
        compile_rule(rule({"sel": {"A": 1}, "condition": "sel"}), [fail])
    assert info.value.feature == "no table"


def test_any_linking() -> None:
    p = pipeline(
        """
name: any
transformations:
  - type: set_state
    key: k
    val: v
    rule_condition_linking: any
    rule_conditions: [{type: logsource, category: a}, {type: logsource, category: b}]
"""
    )
    assert compile_rule(rule({"s": {"F": 1}, "condition": "s"}, category="b"), [p]).state == {
        "k": "v"
    }
    assert compile_rule(rule({"s": {"F": 1}, "condition": "s"}, category="c"), [p]).state == {}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[1]", "must be a mapping"),
        ("transformations: []", "needs a 'name'"),
        ("name: x", "'transformations' must be a list"),
        ("name: x\ntransformations: [1]", "transformation must be a mapping"),
        ("name: x\ntransformations: [{type: nope}]", "unknown type 'nope'"),
        ("name: x\npriority: high\ntransformations: []", "'priority' must be an integer"),
        ("name: x\ntransformations: [{type: field_name_mapping}]", "missing 'mapping'"),
        (
            "name: x\ntransformations: [{type: field_name_mapping, mapping: {A: []}}]",
            "non-empty list",
        ),
        (
            "name: x\ntransformations: [{type: field_name_mapping, mapping: {A: b}, "
            "fallback_prefix: 1}]",
            "'fallback_prefix' must be a string",
        ),
        ("name: x\ntransformations: [{type: set_state, key: k}]", "missing 'val'"),
        ("name: x\ntransformations: [{type: set_state, key: 1, val: v}]", "wrong type"),
        (
            "name: x\ntransformations: [{type: add_condition, conditions: {A|bad: 1}}]",
            "invalid conditions",
        ),
        (
            "name: x\ntransformations: [{type: set_state, key: k, val: v, rule_conditions: x}]",
            "must be a list",
        ),
        (
            "name: x\ntransformations: [{type: set_state, key: k, val: v, "
            "rule_conditions: [{type: field}]}]",
            "only 'type: logsource'",
        ),
        (
            "name: x\ntransformations: [{type: set_state, key: k, val: v, "
            "rule_conditions: [{type: logsource, os: x}]}]",
            "unknown logsource keys",
        ),
        (
            "name: x\ntransformations: [{type: set_state, key: k, val: v, "
            "rule_condition_linking: some}]",
            "all\\|any",
        ),
        ("a: [", "YAML syntax error"),
        ("a: 1\n---\nb: 2", "exactly one YAML document"),
    ],
)
def test_pipeline_errors(text: str, message: str) -> None:
    with pytest.raises(PipelineError, match=message):
        Pipeline.from_yaml(text)


def test_builtin_pipelines_load(tmp_path: Path) -> None:
    names = builtin_pipelines()
    assert set(names) == {"ecs-windows", "sentinel-windows", "splunk-windows"}
    for name in names:
        assert load_pipeline(name).name == name
    with pytest.raises(PipelineError, match="unknown pipeline 'nope'"):
        load_pipeline("nope")
    custom = tmp_path / "mine.yml"
    custom.write_text("name: mine\ntransformations: []\n", encoding="utf-8")
    assert load_pipeline(str(custom)).name == "mine"
    with pytest.raises(PipelineError, match="cannot read pipeline"):
        load_pipeline(str(tmp_path / "missing.yml"))


def test_splunk_pipeline_adds_sysmon_event_code() -> None:
    r = rule({"sel": {"Image": "x"}, "condition": "sel"}, product="windows", category="dns_query")
    compiled = compile_rule(r, [load_pipeline("splunk-windows")])
    assert compiled.node == And(
        (
            FieldMatch("EventCode", NumMatch(22)),
            FieldMatch("Image", StrMatch(SigmaString.parse("x"))),
        )
    )
    assert "Sysmon" in compiled.state["splunk_prefix"]
