from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigmaforge.backends import BACKENDS
from sigmaforge.errors import (
    PipelineError,
    SigmaConditionError,
    SigmaForgeError,
    SigmaModifierError,
    SigmaRuleError,
    UnsupportedFeatureError,
)
from sigmaforge.pipeline import load_pipeline
from sigmaforge.report import build_report, failure_label

ROOT = Path(__file__).resolve().parent.parent
SIGMAHQ = ROOT / "third_party" / "sigmahq"


def default_pipelines() -> dict[str, list[object]]:
    return {b: [load_pipeline(p) for p in cls.default_pipelines] for b, cls in BACKENDS.items()}


@pytest.mark.parametrize(
    ("exc", "label"),
    [
        (UnsupportedFeatureError("x feature"), "x feature"),
        (SigmaConditionError("m", condition="c"), "invalid condition"),
        (SigmaModifierError("m"), "invalid modifier usage"),
        (SigmaRuleError("m"), "invalid rule"),
        (PipelineError("m"), "pipeline error"),
        (SigmaForgeError("m"), "error"),
        (KeyError("k"), "internal error (KeyError)"),
    ],
)
def test_failure_labels(exc: BaseException, label: str) -> None:
    assert failure_label(exc) == label


def test_report_with_broken_rule_files(tmp_path: Path) -> None:
    (tmp_path / "a_ok.yml").write_text(
        "title: ok\ndetection: {s: {A: 1}, condition: s}\n", encoding="utf-8"
    )
    (tmp_path / "b_bad.yml").write_text("title: [\n", encoding="utf-8")
    (tmp_path / "c_cond.yml").write_text(
        "title: c\ndetection: {s: {A: 1}, condition: s and}\n", encoding="utf-8"
    )
    report = build_report([tmp_path], ["sql", "kql"], {}, relative_to=tmp_path)
    assert [r.path for r in report.rules] == ["a_ok.yml", "b_bad.yml", "c_cond.yml"]
    assert report.counts("sql") == (1, 3)
    assert report.reasons("sql") == {"invalid rule": 1, "invalid condition": 1}
    assert report.reasons("kql")["no KQL table for logsource"] == 1
    md = report.to_markdown()
    assert "| `b_bad.yml` | FAIL: invalid rule | FAIL: invalid rule |" in md
    assert "### sql" in md
    assert json.loads(json.dumps(report.to_dict()))["backends"]["sql"]["compiled"] == 1
    assert report.internal_errors() == []


def test_report_empty_backend_section(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(
        "title: ok\ndetection: {s: {A: 1}, condition: s}\n", encoding="utf-8"
    )
    md = build_report([tmp_path], ["splunk"], {}).to_markdown()
    assert "No failures." in md


def test_internal_errors_are_caught_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.yml").write_text(
        "title: ok\ndetection: {s: {A: 1}, condition: s}\n", encoding="utf-8"
    )

    def boom(*_: object, **__: object) -> None:
        raise ZeroDivisionError

    monkeypatch.setattr("sigmaforge.report.compile_rule", boom)
    report = build_report([tmp_path], ["sql"], {})
    assert report.internal_errors()[0][1] == "sql"


def test_pinned_sigmahq_subset_compiles_without_internal_errors() -> None:
    """Integration: all 200 pinned SigmaHQ rules through all four backends."""
    manifest = json.loads((SIGMAHQ / "MANIFEST.json").read_text())
    report = build_report([SIGMAHQ / "rules"], list(BACKENDS), default_pipelines())  # type: ignore[arg-type]
    assert len(report.rules) == len(manifest["files"]) - 1  # minus the LICENSE entry
    assert report.internal_errors() == []
    for backend in BACKENDS:
        ok, total = report.counts(backend)
        assert ok / total > 0.6, backend
    # every failure is explained by a known, rule-independent reason
    for backend in BACKENDS:
        assert all("internal" not in reason for reason in report.reasons(backend))
