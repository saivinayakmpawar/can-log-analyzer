"""Exceptions that carry messages which are safe to show to API clients."""
from __future__ import annotations


class AnalysisError(Exception):
    """Input could not be analyzed. The message is safe to return to the user."""

    status_code = 422


class DbcError(AnalysisError):
    """The DBC file could not be parsed."""


class LogParseError(AnalysisError):
    """The CAN log could not be parsed."""


class RuleError(AnalysisError):
    """The diagnostic rules are invalid or reference unknown messages/signals."""


class LimitExceeded(AnalysisError):
    """A configured resource limit (frames, time) was exceeded."""

    status_code = 413
