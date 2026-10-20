"""Diagnostic rules: optional JSON configuration layered on top of the DBC.

Everything here is explicit configuration. Nothing is inferred about a signal
being a counter or a checksum; if it is not listed, it is not checked.
"""
from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import RuleError

Severity = Literal["high", "medium", "low"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ThresholdRule(_Strict):
    """Extra min/max limit for a signal, independent of the DBC range."""

    signal: str = Field(description="Message.Signal")
    min: float | None = None
    max: float | None = None
    severity: Severity = "high"


class MessageRule(_Strict):
    cycle_ms: float | None = Field(default=None, gt=0)
    required: bool | None = None
    gap_factor: float | None = Field(default=None, gt=1, le=1000)
    tolerance_pct: float | None = Field(default=None, gt=0, le=1000)


class CounterRule(_Strict):
    message: str
    signal: str
    modulus: int | None = Field(default=None, ge=2)
    severity: Severity = "medium"


class ChecksumRule(_Strict):
    message: str
    signal: str
    algorithm: str
    params: dict[str, int] = Field(default_factory=dict)
    bytes: list[int] | None = Field(
        default=None, description="Payload byte indexes covered; default is every byte except the checksum"
    )
    severity: Severity = "high"


class Rules(_Strict):
    gap_factor: float = Field(default=3.0, gt=1, le=1000)
    frequency_tolerance_pct: float = Field(default=20.0, gt=0, le=1000)
    use_dbc_limits: bool = True
    thresholds: list[ThresholdRule] = Field(default_factory=list)
    messages: dict[str, MessageRule] = Field(default_factory=dict)
    counters: list[CounterRule] = Field(default_factory=list)
    checksums: list[ChecksumRule] = Field(default_factory=list)


def parse_rules(raw: bytes | str | dict[str, Any] | None) -> Rules:
    """Parse and validate a rules document. Raises RuleError with a readable message."""
    if raw is None:
        return Rules()
    try:
        data = raw if isinstance(raw, dict) else json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuleError(f"Rules file is not valid JSON: {str(exc)[:120]}") from exc
    if not isinstance(data, dict):
        raise RuleError("Rules file must contain a JSON object")
    try:
        return Rules.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "(root)"
        raise RuleError(f"Invalid rules at '{where}': {first['msg']}") from exc
