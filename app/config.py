"""Runtime settings, read from environment variables on every call.

All variables are optional. Defaults are conservative for a public deployment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MB = 1024 * 1024


def _num(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_log_bytes: int
    max_dbc_bytes: int
    max_rules_bytes: int
    max_frames: int
    analysis_timeout_s: float
    upload_timeout_s: float
    max_concurrent_analyses: int
    max_analyses: int
    api_token: str | None

    @property
    def max_body_bytes(self) -> int:
        """Upper bound for a whole multipart request (files plus form overhead)."""
        return self.max_log_bytes + self.max_dbc_bytes + self.max_rules_bytes + MB


def get_settings() -> Settings:
    token = os.environ.get("CAN_ANALYZER_TOKEN", "").strip() or None
    return Settings(
        data_dir=Path(os.environ.get("CAN_ANALYZER_DATA_DIR", "data")).resolve(),
        max_log_bytes=int(_num("CAN_ANALYZER_MAX_LOG_MB", 25, 0.001) * MB),
        max_dbc_bytes=int(_num("CAN_ANALYZER_MAX_DBC_MB", 5, 0.001) * MB),
        max_rules_bytes=int(_num("CAN_ANALYZER_MAX_RULES_KB", 256, 1) * 1024),
        max_frames=int(_num("CAN_ANALYZER_MAX_FRAMES", 3_000_000, 1)),
        analysis_timeout_s=_num("CAN_ANALYZER_TIMEOUT_S", 120, 0.1),
        upload_timeout_s=_num("CAN_ANALYZER_UPLOAD_TIMEOUT_S", 60, 0.1),
        max_concurrent_analyses=int(_num("CAN_ANALYZER_MAX_CONCURRENT", 2, 1)),
        max_analyses=int(_num("CAN_ANALYZER_MAX_ANALYSES", 25, 1)),
        api_token=token,
    )
