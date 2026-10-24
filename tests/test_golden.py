"""Golden-file tests: every example rule through every backend with its default pipeline.

Regenerate after an intended output change with ``UPDATE_GOLDEN=1 uv run pytest
tests/test_golden.py`` and review the diff like any other code change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sigmaforge.backends import BACKENDS, get_backend
from sigmaforge.compiler import compile_rule
from sigmaforge.errors import UnsupportedFeatureError
from sigmaforge.evaluator import Evaluator
from sigmaforge.pipeline import load_pipeline
from sigmaforge.rule import load_rule
from tests.helpers import load_jsonl

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "examples" / "rules").glob("*.yml"))
GOLDEN = ROOT / "tests" / "golden"


def render(rule_path: Path, backend: str) -> str:
    pipelines = [load_pipeline(p) for p in BACKENDS[backend].default_pipelines]
    try:
        compiled = compile_rule(load_rule(rule_path), pipelines)
        return get_backend(backend).convert(compiled).text + "\n"
    except UnsupportedFeatureError as exc:
        return f"UNSUPPORTED [{exc.feature}]: {exc}\n"


@pytest.mark.parametrize("backend", list(BACKENDS))
@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_golden(rule_path: Path, backend: str) -> None:
    golden = GOLDEN / f"{rule_path.stem}.{backend}.txt"
    actual = render(rule_path, backend)
    if os.environ.get("UPDATE_GOLDEN"):
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(actual, encoding="utf-8")
    assert golden.read_text(encoding="utf-8") == actual


def test_examples_match_hand_labelled_expectations() -> None:
    events = load_jsonl(ROOT / "examples" / "events" / "windows.jsonl")
    expected = json.loads((ROOT / "examples" / "events" / "expected.json").read_text())
    assert sorted(expected) == [p.name for p in RULES]
    for path in RULES:
        hits = Evaluator(compile_rule(load_rule(path)).node).filter(events)
        assert hits == expected[path.name], path.name
