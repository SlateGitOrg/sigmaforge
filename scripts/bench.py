"""Micro-benchmarks: compile throughput and matching throughput.

  uv run python scripts/bench.py [--repeat 5] [--events 20000]

* compile: the pinned SigmaHQ subset (parse once), then front end + default pipeline +
  backend for every rule, per backend; median of ``--repeat`` runs.
* match: the example rules over the demo events replicated to ``--events`` events, with the
  reference evaluator and with SQLite (load time reported separately).

Numbers depend on the machine; the header prints what it ran on. Single-threaded.
"""

from __future__ import annotations

import argparse
import os
import platform
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.helpers import load_jsonl  # noqa: E402

from sigmaforge.ast import fields  # noqa: E402
from sigmaforge.backends import BACKENDS, get_backend  # noqa: E402
from sigmaforge.compiler import compile_rule  # noqa: E402
from sigmaforge.errors import SigmaForgeError  # noqa: E402
from sigmaforge.evaluator import Evaluator  # noqa: E402
from sigmaforge.pipeline import load_pipeline  # noqa: E402
from sigmaforge.rule import SigmaRule, iter_rule_files, load_rule  # noqa: E402
from sigmaforge.sqlite_runtime import connect, load_events, run_query  # noqa: E402


def median_seconds(fn: Callable[[], object], repeat: int) -> float:
    times = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def main() -> None:
    parser = argparse.ArgumentParser(description="sigmaforge micro-benchmarks")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--events", type=int, default=20000)
    args = parser.parse_args()
    print(
        f"python {platform.python_version()} on {platform.machine()} "
        f"({os.cpu_count()} cpus), median of {args.repeat} runs\n"
    )

    files = list(iter_rule_files([ROOT / "third_party" / "sigmahq" / "rules"]))
    parse_s = median_seconds(lambda: [load_rule(f) for f in files], args.repeat)
    rules: list[SigmaRule] = [load_rule(f) for f in files]
    print("| stage | rules | seconds | rules/s |\n|---|---|---|---|")
    print(f"| YAML load + validate | {len(files)} | {parse_s:.3f} | {len(files) / parse_s:,.0f} |")
    for name, cls in BACKENDS.items():
        pipelines = [load_pipeline(p) for p in cls.default_pipelines]
        backend = get_backend(name)

        def run(backend: object = backend, pipelines: object = pipelines) -> int:
            ok = 0
            for rule in rules:
                try:
                    backend.convert(compile_rule(rule, pipelines))  # type: ignore[attr-defined,arg-type]
                    ok += 1
                except SigmaForgeError:
                    pass
            return ok

        seconds = median_seconds(run, args.repeat)
        print(f"| compile -> {name} | {len(rules)} | {seconds:.3f} | {len(rules) / seconds:,.0f} |")

    base = load_jsonl(ROOT / "examples" / "events" / "windows.jsonl")
    events = [base[i % len(base)] for i in range(args.events)]
    examples = [
        compile_rule(load_rule(p)) for p in sorted((ROOT / "examples" / "rules").glob("*.yml"))
    ]
    columns = sorted({k for e in base for k in e} | {f for c in examples for f in fields(c.node)})
    print("\n| matcher | rules x events | seconds | rule-event checks/s |\n|---|---|---|---|")
    work = len(examples) * len(events)

    def evaluate_all() -> None:
        for compiled in examples:
            Evaluator(compiled.node).filter(events)

    seconds = median_seconds(evaluate_all, args.repeat)
    shape = f"{len(examples)} x {len(events)}"
    print(f"| reference evaluator | {shape} | {seconds:.3f} | {work / seconds:,.0f} |")

    conn = connect()
    load_s = median_seconds(lambda: load_events(conn, events, extra_columns=columns), args.repeat)
    backend = get_backend("sql", keyword_columns=columns)
    queries = [backend.convert(c).text for c in examples]
    query_s = median_seconds(lambda: [run_query(conn, q) for q in queries], args.repeat)
    print(f"| SQLite load (one-off) | {len(events)} events | {load_s:.3f} | - |")
    print(f"| SQLite queries | {shape} | {query_s:.3f} | {work / query_s:,.0f} |")
    conn.close()


if __name__ == "__main__":
    main()
