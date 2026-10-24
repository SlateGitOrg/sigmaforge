"""Exception hierarchy.

Every error raised on purpose by sigmaforge derives from :class:`SigmaForgeError` and carries a
short, stable ``category`` string. The compile report groups failures by that category, so the
categories are part of the public contract: change them deliberately.
"""

from __future__ import annotations


class SigmaForgeError(Exception):
    """Base class for all sigmaforge errors."""

    category: str = "error"

    def __init__(self, message: str, *, location: str | None = None) -> None:
        self.message = message
        self.location = location
        super().__init__(f"{location}: {message}" if location else message)


class SigmaRuleError(SigmaForgeError):
    """The rule document is structurally invalid (missing keys, wrong types, bad YAML)."""

    category = "invalid-rule"


class SigmaConditionError(SigmaRuleError):
    """The ``condition`` expression could not be parsed or references unknown identifiers."""

    category = "invalid-condition"

    def __init__(self, message: str, *, condition: str, position: int | None = None) -> None:
        self.condition = condition
        self.position = position
        where = f"condition {condition!r}"
        if position is not None:
            where += f" at column {position + 1}"
        super().__init__(message, location=where)


class SigmaModifierError(SigmaRuleError):
    """A value modifier was misused (wrong value type, bad regex, bad CIDR...)."""

    category = "invalid-modifier"


class UnsupportedFeatureError(SigmaForgeError):
    """A valid Sigma construct that this compiler or a specific backend cannot express.

    ``feature`` is a short human-readable label ("keyword search", "modifier 'expand'"); it is
    what the compile report aggregates on, so keep it free of rule-specific detail. Put the
    detail in ``message``.
    """

    category = "unsupported"

    def __init__(self, feature: str, message: str | None = None, *, backend: str | None = None):
        self.feature = feature
        self.backend = backend
        prefix = f"[{backend}] " if backend else ""
        super().__init__(f"{prefix}{message or feature}")


class PipelineError(SigmaForgeError):
    """A processing pipeline definition is invalid or failed while being applied."""

    category = "pipeline"
