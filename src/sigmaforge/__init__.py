"""sigmaforge - a Sigma detection-rule compiler.

Typical use::

    from sigmaforge import compile_rule, get_backend, load_pipeline, parse_rule

    rule = parse_rule(yaml_text)
    compiled = compile_rule(rule, [load_pipeline("sentinel-windows")])
    print(get_backend("kql").convert(compiled).text)
"""

from __future__ import annotations

from sigmaforge.backends import BACKENDS, Backend, Query, get_backend
from sigmaforge.compiler import CompiledRule, compile_rule
from sigmaforge.errors import (
    PipelineError,
    SigmaConditionError,
    SigmaForgeError,
    SigmaModifierError,
    SigmaRuleError,
    UnsupportedFeatureError,
)
from sigmaforge.evaluator import Evaluator, evaluate
from sigmaforge.pipeline import Pipeline, load_pipeline
from sigmaforge.rule import SigmaRule, load_rule, parse_rule

__version__ = "0.1.0"

__all__ = [
    "BACKENDS",
    "Backend",
    "CompiledRule",
    "Evaluator",
    "Pipeline",
    "PipelineError",
    "Query",
    "SigmaConditionError",
    "SigmaForgeError",
    "SigmaModifierError",
    "SigmaRule",
    "SigmaRuleError",
    "UnsupportedFeatureError",
    "__version__",
    "compile_rule",
    "evaluate",
    "get_backend",
    "load_pipeline",
    "load_rule",
    "parse_rule",
]
