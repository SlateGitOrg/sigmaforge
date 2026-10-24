from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sigmaforge.cli import main

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "examples" / "rules"
EVENTS = ROOT / "examples" / "events" / "windows.jsonl"


def test_compile_kql_directory(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["compile", "-t", "kql", str(RULES)])
    out, err = capsys.readouterr()
    assert code == 1  # the keyword rule has no KQL table
    assert "DeviceProcessEvents\n| where" in out
    assert "kw_credential_dumper_strings.yml" in err
    assert main(["compile", "-t", "kql", "--allow-failures", str(RULES)]) == 0


def test_compile_json_to_file(tmp_path: Path) -> None:
    out = tmp_path / "q.json"
    code = main(
        [
            "compile",
            "-t",
            "sqlite",
            "--sql-keyword-columns",
            "CommandLine, ScriptBlockText",
            "--sql-table",
            "logs",
            "-f",
            "json",
            "-o",
            str(out),
            str(RULES),
        ]
    )
    assert code == 0
    queries = json.loads(out.read_text())
    assert len(queries) == 9
    assert all(q["query"].startswith('SELECT * FROM "logs"') for q in queries)


def test_compile_custom_pipeline_without_defaults(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pipeline = tmp_path / "p.yml"
    pipeline.write_text(
        "name: p\ntransformations: [{type: field_name_prefix, prefix: x_}]\n", encoding="utf-8"
    )
    rule = RULES / "proc_certutil_download.yml"
    code = main(
        ["compile", "-t", "splunk", "--no-default-pipelines", "-p", str(pipeline), str(rule)]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "x_CommandLine" in out
    assert "Sysmon" not in out


def test_report_markdown_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", str(RULES)]) == 0
    out = capsys.readouterr().out
    assert "| splunk | 9 | 0 | 100.0% |" in out
    assert "| keyword search | 1 |" in out
    target = tmp_path / "r.json"
    assert (
        main(["report", "-t", "eql", "-t", "sql", "-f", "json", "-o", str(target), str(RULES)]) == 0
    )
    data = json.loads(target.read_text())
    assert set(data["backends"]) == {"eql", "sql"}
    assert "eql" in capsys.readouterr().err
    md = tmp_path / "r.md"
    assert main(["report", "--heading", "H", "--preamble", "P", "-o", str(md), str(RULES)]) == 0
    assert md.read_text().startswith("# H\n\nP\n")


def test_eval(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["eval", str(RULES / "proc_encoded_powershell.yml"), str(EVENTS)]) == 0
    out = capsys.readouterr().out
    assert "3 of 21 events match" in out
    assert "match event #1:" in out


def test_sql_run_agrees(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["sql-run", str(RULES), "-e", str(EVENTS)]) == 0
    out = capsys.readouterr().out
    assert "0 disagreement(s), 0 failure(s)" in out
    assert "DISAGREE" not in out


def test_sql_run_reports_compile_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule = tmp_path / "bad.yml"
    rule.write_text("title: t\ndetection: {s: {A|re: '(?<bad'}, condition: s}\n", encoding="utf-8")
    assert main(["sql-run", str(rule), "-e", str(EVENTS)]) == 1
    assert "1 failure(s)" in capsys.readouterr().out


def test_sql_run_case_only_field_collision_in_events_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events = tmp_path / "ev.jsonl"
    events.write_text('{"image": "x"}\n{"Image": "x"}\n', encoding="utf-8")
    assert main(["sql-run", str(RULES), "-e", str(events)]) == 2
    err = capsys.readouterr().err
    assert "differ only by case" in err
    assert "Traceback" not in err


def test_sql_run_case_only_rule_field_collision_is_a_rule_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule = tmp_path / "lower.yml"
    rule.write_text("title: t\ndetection: {s: {image: x}, condition: s}\n", encoding="utf-8")
    events = tmp_path / "ev.jsonl"
    events.write_text('{"Image": "x"}\n', encoding="utf-8")
    assert main(["sql-run", str(rule), "-e", str(events)]) == 1
    captured = capsys.readouterr()
    assert "differ only by case" in captured.err
    assert "0 disagreement(s), 1 failure(s)" in captured.out


def test_sql_run_sqlite_load_error_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events = tmp_path / "wide.jsonl"
    # More columns than SQLite's default SQLITE_MAX_COLUMN (2000).
    events.write_text(json.dumps({f"f{i}": i for i in range(2100)}) + "\n", encoding="utf-8")
    assert main(["sql-run", str(RULES), "-e", str(events)]) == 2
    assert "cannot load events into SQLite" in capsys.readouterr().err


def test_sql_run_reports_sqlite_errors_per_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from sigmaforge import cli

    def broken(conn: object, query: str) -> list[int]:
        raise sqlite3.OperationalError("boom")

    monkeypatch.setattr(cli, "run_query", broken)
    assert main(["sql-run", str(RULES / "proc_encoded_powershell.yml"), "-e", str(EVENTS)]) == 1
    captured = capsys.readouterr()
    assert "boom" in captured.err
    assert "1 failure(s)" in captured.out


def test_ast_and_pipelines(capsys: pytest.CaptureFixture[str]) -> None:
    rule = RULES / "proc_office_child_shell.yml"
    assert main(["ast", "-p", "sentinel-windows", str(rule)]) == 0
    out = capsys.readouterr().out
    assert "(InitiatingProcessFolderPath" in out
    assert "state: {'kql_table': 'DeviceProcessEvents'}" in out
    assert "pipeline steps: sentinel-windows:process_table" in out
    assert main(["ast", "--raw", str(rule)]) == 0
    assert main(["pipelines"]) == 0
    assert "sentinel-windows" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["compile", "-t", "nosuch", "x.yml"], "unknown backend"),
        (["compile", "-t", "kql", "missing-dir"], "no such file"),
        (["compile", "-t", "kql", "-p", "nosuch", str(RULES)], "unknown pipeline"),
        (["eval", str(RULES / "proc_base64_whoami.yml"), "missing.jsonl"], "cannot read events"),
        (["report", "-o", "no/such/dir/r.md", str(RULES)], "cannot write"),
    ],
)
def test_usage_errors(argv: list[str], message: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "message"), [("{bad json\n", "invalid JSON"), ("[1, 2]\n", "JSON object")]
)
def test_bad_events(
    tmp_path: Path, content: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    events = tmp_path / "e.jsonl"
    events.write_text("\n" + content, encoding="utf-8")
    assert main(["eval", str(RULES / "proc_base64_whoami.yml"), str(events)]) == 2
    assert message in capsys.readouterr().err


def test_verbose_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["-vv", "pipelines"]) == 0
