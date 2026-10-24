from __future__ import annotations

from pathlib import Path

import pytest

from sigmaforge.errors import SigmaRuleError, UnsupportedFeatureError
from sigmaforge.rule import iter_rule_files, load_rule, load_yaml_documents, parse_rule

MINIMAL = """
title: t
logsource: {product: windows, category: process_creation}
detection:
  sel: {Image: x}
  condition: sel
"""


def test_minimal_rule() -> None:
    rule = parse_rule(MINIMAL)
    assert rule.title == "t"
    assert rule.conditions == ("sel",)
    assert str(rule.logsource) == "category=process_creation product=windows"
    assert list(rule.search_identifiers) == ["sel"]


@pytest.mark.parametrize(
    ("scalar", "expected"),
    [
        ("0x1410", "0x1410"),  # YAML 1.1 would make this 5136
        ("010", "010"),  # ... and this 8
        ("yes", "yes"),  # ... and this True
        ("2024-01-01", "2024-01-01"),  # ... and this a date
        ("4688", 4688),
        ("-3", -3),
        ("1.5", 1.5),
        ("true", True),
        ("null", None),
        ("~", None),
    ],
)
def test_conservative_scalar_typing(scalar: str, expected: object) -> None:
    assert load_yaml_documents(f"v: {scalar}")[0] == {"v": expected}


def test_duplicate_keys_rejected() -> None:
    with pytest.raises(SigmaRuleError, match="duplicate key 'a'"):
        load_yaml_documents("a: 1\na: 2\n")


def test_yaml_syntax_error() -> None:
    with pytest.raises(SigmaRuleError, match="YAML syntax error"):
        parse_rule("title: [unclosed")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "empty document"),
        ("- a\n- b", "must be a mapping"),
        ("detection: {condition: x}", "title"),
        ("title: t\ndetection: [1]", "'detection' must be a mapping"),
        ("title: t\ndetection: {sel: {a: 1}}", "condition"),
        ("title: t\ndetection: {condition: [1]}", "condition"),
        ("title: t\nlogsource: x\ndetection: {condition: s}", "'logsource' must be a mapping"),
        ("title: t\ntags: {a: 1}\ndetection: {condition: s}", "'tags' must be a list"),
        ("title: t\nlevel: [1]\ndetection: {condition: s}", "'level' must be a string"),
        ("title: t\ndetection: {1: {a: b}, condition: s}", "search identifier"),
    ],
)
def test_structural_errors(text: str, message: str) -> None:
    with pytest.raises(SigmaRuleError, match=message):
        parse_rule(text)


def test_condition_list_and_tags() -> None:
    rule = parse_rule(
        "title: t\ntags: attack.x\nfalsepositives: [a, 1]\n"
        "detection: {a: {f: 1}, b: {f: 2}, condition: [a, b]}"
    )
    assert rule.conditions == ("a", "b")
    assert rule.tags == ("attack.x",)
    assert rule.falsepositives == ("a", "1")


@pytest.mark.parametrize(
    ("text", "feature"),
    [
        ("title: t\ncorrelation: {type: event_count}", "correlation rule"),
        ("title: t\naction: global\ndetection: {condition: s}", "rule collection action"),
        (MINIMAL + "---\n" + MINIMAL, "multi-document rule file"),
    ],
)
def test_unsupported_documents(text: str, feature: str) -> None:
    with pytest.raises(UnsupportedFeatureError) as info:
        parse_rule(text)
    assert info.value.feature == feature


def test_load_rule_and_iter_files(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.yml").write_text(MINIMAL, encoding="utf-8")
    (tmp_path / "a.yaml").write_text(MINIMAL, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    files = list(iter_rule_files([tmp_path]))
    assert [f.name for f in files] == ["a.yaml", "b.yml"]
    assert load_rule(files[0]).source == str(files[0])
    with pytest.raises(SigmaRuleError, match="no such file"):
        list(iter_rule_files([tmp_path / "missing.yml"]))
    (tmp_path / "bad.yml").write_bytes(b"\xff\xfe")
    with pytest.raises(SigmaRuleError, match="cannot read"):
        load_rule(tmp_path / "bad.yml")
