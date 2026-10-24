"""Compile-coverage report: which rules compile for which backend, and why the rest do not.

Every failure is labelled with a short reason (the ``feature`` of an
:class:`~sigmaforge.errors.UnsupportedFeatureError`, or the class of a rule error) so a run over
hundreds of rules reduces to a small histogram of causes. An exception that is *not* a
:class:`~sigmaforge.errors.SigmaForgeError` is a compiler bug; it is reported as
``internal error`` instead of crashing the run, and the test-suite asserts there are none.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigmaforge.backends import get_backend
from sigmaforge.compiler import compile_rule
from sigmaforge.errors import (
    PipelineError,
    SigmaConditionError,
    SigmaForgeError,
    SigmaModifierError,
    SigmaRuleError,
    UnsupportedFeatureError,
)
from sigmaforge.pipeline import Pipeline
from sigmaforge.rule import SigmaRule, iter_rule_files, load_rule

log = logging.getLogger(__name__)


def failure_label(exc: BaseException) -> str:
    """Short, rule-independent reason used for aggregation."""
    if isinstance(exc, UnsupportedFeatureError):
        return exc.feature
    if isinstance(exc, SigmaConditionError):
        return "invalid condition"
    if isinstance(exc, SigmaModifierError):
        return "invalid modifier usage"
    if isinstance(exc, SigmaRuleError):
        return "invalid rule"
    if isinstance(exc, PipelineError):
        return "pipeline error"
    if isinstance(exc, SigmaForgeError):
        return exc.category
    return f"internal error ({type(exc).__name__})"


@dataclass(frozen=True)
class BackendResult:
    backend: str
    ok: bool
    query: str | None = None
    reason: str | None = None
    message: str | None = None


@dataclass
class RuleResult:
    path: str
    title: str | None
    logsource: str | None
    results: dict[str, BackendResult] = field(default_factory=dict)


@dataclass
class CompileReport:
    backends: list[str]
    rules: list[RuleResult] = field(default_factory=list)

    def counts(self, backend: str) -> tuple[int, int]:
        ok = sum(1 for r in self.rules if r.results[backend].ok)
        return ok, len(self.rules)

    def reasons(self, backend: str) -> Counter[str]:
        return Counter(
            r.results[backend].reason or "?" for r in self.rules if not r.results[backend].ok
        )

    def internal_errors(self) -> list[tuple[str, str, str]]:
        return [
            (r.path, b, res.message or "")
            for r in self.rules
            for b, res in r.results.items()
            if res.reason and res.reason.startswith("internal error")
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "backends": {
                b: {
                    "compiled": self.counts(b)[0],
                    "total": self.counts(b)[1],
                    "failure_reasons": dict(self.reasons(b).most_common()),
                }
                for b in self.backends
            },
            "rules": [
                {
                    "path": r.path,
                    "title": r.title,
                    "logsource": r.logsource,
                    "results": {
                        b: {"ok": res.ok, "reason": res.reason, "message": res.message}
                        for b, res in r.results.items()
                    },
                }
                for r in self.rules
            ],
        }

    def to_markdown(self, heading: str = "Compile report", preamble: str = "") -> str:
        lines = [f"# {heading}", ""]
        if preamble:
            lines += [preamble, ""]
        lines += ["## Summary", "", "| backend | compiled | failed | success |", "|---|---|---|---|"]
        for b in self.backends:
            ok, total = self.counts(b)
            pct = f"{100 * ok / total:.1f}%" if total else "n/a"
            lines.append(f"| {b} | {ok} | {total - ok} | {pct} |")
        lines += ["", "## Failure reasons", ""]
        for b in self.backends:
            reasons = self.reasons(b)
            lines += [f"### {b}", ""]
            if not reasons:
                lines += ["No failures.", ""]
                continue
            lines += ["| reason | rules |", "|---|---|"]
            lines += [f"| {reason} | {count} |" for reason, count in reasons.most_common()]
            lines.append("")
        lines += ["## Per-rule results", ""]
        lines.append("| rule | " + " | ".join(self.backends) + " |")
        lines.append("|---|" + "---|" * len(self.backends))
        for r in self.rules:
            cells = [
                "ok" if r.results[b].ok else f"FAIL: {r.results[b].reason}" for b in self.backends
            ]
            lines.append(f"| `{r.path}` | " + " | ".join(cells) + " |")
        return "\n".join(lines) + "\n"


def _compile_one(
    rule: SigmaRule, backend: str, pipelines: Sequence[Pipeline], options: Mapping[str, Any]
) -> BackendResult:
    try:
        compiled = compile_rule(rule, pipelines)
        query = get_backend(backend, **options).convert(compiled)
    except SigmaForgeError as exc:
        return BackendResult(backend, False, reason=failure_label(exc), message=str(exc))
    except Exception as exc:  # a bug: record it, keep the run going
        log.exception("internal error compiling %s for %s", rule.source, backend)
        return BackendResult(backend, False, reason=failure_label(exc), message=repr(exc))
    return BackendResult(backend, True, query=query.text)


def build_report(
    paths: Iterable[Path],
    backends: Sequence[str],
    pipelines: Mapping[str, Sequence[Pipeline]],
    backend_options: Mapping[str, Mapping[str, Any]] | None = None,
    relative_to: Path | None = None,
) -> CompileReport:
    """Compile every rule under ``paths`` for every backend and collect the outcomes."""
    options = backend_options or {}
    report = CompileReport(list(backends))
    for file in iter_rule_files(paths):
        shown = str(file.relative_to(relative_to)) if relative_to else str(file)
        try:
            rule = load_rule(file)
        except SigmaForgeError as exc:
            label = failure_label(exc)
            results = {b: BackendResult(b, False, reason=label, message=str(exc)) for b in backends}
            report.rules.append(RuleResult(shown, None, None, results))
            continue
        entry = RuleResult(shown, rule.title, str(rule.logsource))
        for b in backends:
            entry.results[b] = _compile_one(rule, b, pipelines.get(b, ()), options.get(b, {}))
        report.rules.append(entry)
    return report
