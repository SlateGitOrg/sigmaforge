"""Command-line interface.

``sigmaforge compile -t kql rules/``        compile rules for one backend
``sigmaforge report -t all rules/``         per-backend compile coverage with failure reasons
``sigmaforge eval rule.yml events.jsonl``   run the reference evaluator over JSONL events
``sigmaforge sql-run rules/ -e ev.jsonl``   execute the SQL backend in SQLite, cross-check
``sigmaforge ast rule.yml``                 print the compiled expression tree
``sigmaforge pipelines``                    list built-in pipelines

Exit codes: 0 success, 1 some rules failed (or disagreed), 2 usage / input errors.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from sigmaforge import __version__
from sigmaforge.ast import fields, to_sexpr
from sigmaforge.backends import BACKENDS, get_backend, resolve_backend_name
from sigmaforge.compiler import compile_rule
from sigmaforge.errors import SigmaForgeError
from sigmaforge.evaluator import Evaluator
from sigmaforge.pipeline import Pipeline, builtin_pipelines, load_pipeline
from sigmaforge.report import build_report
from sigmaforge.rule import iter_rule_files, load_rule
from sigmaforge.sqlite_runtime import connect, load_events, run_query

log = logging.getLogger("sigmaforge")


class UsageError(Exception):
    """Bad command-line input; maps to exit code 2."""


def _pipelines_for(backend: str, args: argparse.Namespace) -> list[Pipeline]:
    names: list[str] = []
    if not args.no_default_pipelines:
        names.extend(BACKENDS[backend].default_pipelines)
    names.extend(args.pipeline or [])
    return [load_pipeline(n) for n in names]


def _backend_options(backend: str, args: argparse.Namespace) -> dict[str, Any]:
    if backend != "sql":
        return {}
    options: dict[str, Any] = {"table": args.sql_table}
    if args.sql_keyword_columns:
        options["keyword_columns"] = [c.strip() for c in args.sql_keyword_columns.split(",")]
    return options


def _read_events(path: Path) -> list[dict[str, Any]]:
    events = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UsageError(f"cannot read events: {exc}") from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UsageError(f"{path}:{number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise UsageError(f"{path}:{number}: each line must be a JSON object")
        events.append(value)
    return events


def _open_output(path: str | None) -> TextIO:
    if path is None or path == "-":
        return sys.stdout
    return Path(path).open("w", encoding="utf-8")


# ----------------------------------------------------------------------------- commands


def cmd_compile(args: argparse.Namespace) -> int:
    backend_name = resolve_backend_name(args.target)
    pipelines = _pipelines_for(backend_name, args)
    backend = get_backend(backend_name, **_backend_options(backend_name, args))
    queries: list[dict[str, Any]] = []
    failures = 0
    out = _open_output(args.output)
    try:
        for file in iter_rule_files(Path(p) for p in args.rules):
            try:
                query = backend.convert(compile_rule(load_rule(file), pipelines))
            except SigmaForgeError as exc:
                failures += 1
                print(f"error: {file}: {exc}", file=sys.stderr)
                continue
            if args.format == "json":
                queries.append(query.as_dict())
            else:
                out.write(f"// {query.title} ({file})\n{query.text}\n\n")
        if args.format == "json":
            json.dump(queries, out, indent=2, ensure_ascii=False)
            out.write("\n")
    finally:
        if out is not sys.stdout:
            out.close()
    log.info("compiled for %s: %d failure(s)", backend_name, failures)
    return 1 if failures and not args.allow_failures else 0


def cmd_report(args: argparse.Namespace) -> int:
    targets = list(BACKENDS) if "all" in args.target else [resolve_backend_name(t) for t in args.target]
    pipelines = {b: _pipelines_for(b, args) for b in targets}
    options = {b: _backend_options(b, args) for b in targets}
    report = build_report([Path(p) for p in args.rules], targets, pipelines, options)
    out = _open_output(args.output)
    try:
        if args.format == "json":
            json.dump(report.to_dict(), out, indent=2, ensure_ascii=False)
            out.write("\n")
        else:
            out.write(report.to_markdown(args.heading, args.preamble or ""))
    finally:
        if out is not sys.stdout:
            out.close()
    if out is not sys.stdout or args.format == "json":
        for b in targets:
            ok, total = report.counts(b)
            print(f"{b:7s} {ok}/{total} compiled", file=sys.stderr)
    return 1 if report.internal_errors() else 0


def cmd_eval(args: argparse.Namespace) -> int:
    compiled = compile_rule(load_rule(Path(args.rule)), [load_pipeline(p) for p in args.pipeline or []])
    events = _read_events(Path(args.events))
    hits = Evaluator(compiled.node).filter(events)
    for index in hits:
        print(f"match event #{index}: {json.dumps(events[index], ensure_ascii=False)}")
    print(f"{len(hits)} of {len(events)} events match '{compiled.rule.title}'")
    return 0


def cmd_sql_run(args: argparse.Namespace) -> int:
    events = _read_events(Path(args.events))
    disagreements = 0
    failures = 0
    for file in iter_rule_files(Path(p) for p in args.rules):
        try:
            compiled = compile_rule(load_rule(file), [load_pipeline(p) for p in args.pipeline or []])
            keyword_columns = sorted({k for e in events for k in e})
            query = get_backend("sql", keyword_columns=keyword_columns).convert(compiled)
        except SigmaForgeError as exc:
            failures += 1
            print(f"error: {file}: {exc}", file=sys.stderr)
            continue
        conn = connect()
        try:
            load_events(conn, events, extra_columns=fields(compiled.node))
            sql_hits = run_query(conn, query.text)
        finally:
            conn.close()
        ref_hits = Evaluator(compiled.node).filter(events)
        verdict = "agree" if sql_hits == ref_hits else "DISAGREE"
        disagreements += sql_hits != ref_hits
        print(f"{file.name:40s} sqlite={sql_hits} evaluator={ref_hits} {verdict}")
    print(f"{disagreements} disagreement(s), {failures} compile failure(s)")
    return 1 if disagreements or failures else 0


def cmd_ast(args: argparse.Namespace) -> int:
    pipelines = [load_pipeline(p) for p in args.pipeline or []]
    compiled = compile_rule(load_rule(Path(args.rule)), pipelines, optimize=not args.raw)
    print(to_sexpr(compiled.node))
    if compiled.state:
        print(f"state: {dict(compiled.state)}")
    if compiled.applied:
        print(f"pipeline steps: {', '.join(compiled.applied)}")
    return 0


def cmd_pipelines(_: argparse.Namespace) -> int:
    for name, description in builtin_pipelines().items():
        print(f"{name:18s} {description}")
    return 0


# ----------------------------------------------------------------------------- parser


def _add_pipeline_args(p: argparse.ArgumentParser, defaults: bool) -> None:
    p.add_argument(
        "-p", "--pipeline", action="append", help="pipeline name or YAML file (repeatable)"
    )
    if defaults:
        p.add_argument(
            "--no-default-pipelines",
            action="store_true",
            help="do not apply the backend's built-in default pipeline",
        )
        p.add_argument("--sql-table", default="events", help="SQL backend table name")
        p.add_argument(
            "--sql-keyword-columns", help="comma-separated columns searched by keyword rules"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmaforge", description="Compile Sigma detection rules to SIEM query languages."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="more logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("compile", help="compile rules for one backend")
    p.add_argument("-t", "--target", required=True, help=f"backend: {', '.join(BACKENDS)}")
    p.add_argument("rules", nargs="+", help="rule files or directories")
    p.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p.add_argument("-o", "--output", help="write queries here instead of stdout")
    p.add_argument(
        "--allow-failures", action="store_true", help="exit 0 even if some rules fail to compile"
    )
    _add_pipeline_args(p, defaults=True)
    p.set_defaults(func=cmd_compile)

    p = sub.add_parser("report", help="per-backend compile coverage with failure reasons")
    p.add_argument("rules", nargs="+")
    p.add_argument(
        "-t", "--target", action="append", default=None, help="backend (repeatable) or 'all'"
    )
    p.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("-o", "--output")
    p.add_argument("--heading", default="Compile report")
    p.add_argument("--preamble", help="markdown paragraph placed under the heading")
    _add_pipeline_args(p, defaults=True)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("eval", help="run the reference evaluator over JSONL events")
    p.add_argument("rule")
    p.add_argument("events")
    _add_pipeline_args(p, defaults=False)
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("sql-run", help="execute SQL queries in SQLite and cross-check")
    p.add_argument("rules", nargs="+")
    p.add_argument("-e", "--events", required=True, help="JSONL events file")
    _add_pipeline_args(p, defaults=False)
    p.set_defaults(func=cmd_sql_run)

    p = sub.add_parser("ast", help="print the compiled expression tree")
    p.add_argument("rule")
    p.add_argument("--raw", action="store_true", help="skip simplification")
    _add_pipeline_args(p, defaults=False)
    p.set_defaults(func=cmd_ast)

    p = sub.add_parser("pipelines", help="list built-in pipelines")
    p.set_defaults(func=cmd_pipelines)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "target", None) is None and args.command == "report":
        args.target = ["all"]
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    try:
        code: int = args.func(args)
    except (SigmaForgeError, UsageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
