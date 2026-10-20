"""Finding model shared by every check.

A finding separates three things that must not be blurred:

* ``classification`` - ``confirmed_violation`` means a configured rule (DBC range,
  user threshold, counter or checksum definition) was demonstrably broken in the
  data. ``observed_anomaly`` means the data deviates from an expectation
  (timing, unknown ID, ...) but no explicit rule defines it as a fault.
* ``evidence`` - the measured values that triggered the finding.
* ``possible_causes`` - hypotheses only. They are never confirmed by this tool.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CONFIRMED = "confirmed_violation"
OBSERVED = "observed_anomaly"

METHODS: dict[str, str] = {
    "out_of_range": (
        "Every decoded value of the signal is compared with the configured limits (DBC minimum/maximum, or a "
        "user threshold). Consecutive violating frames of the same message are merged into one event."
    ),
    "gap": (
        "Time between consecutive frames of the same message is compared with its expected cycle time "
        "(rules file, then DBC GenMsgCycleTime, then the median period observed in the log). A gap larger than "
        "gap_factor x expected cycle is reported."
    ),
    "missing_message": "The message is defined in the DBC but no frame with its ID and frame format occurs in the log.",
    "unknown_id": "The frame's identifier and format (11-bit/29-bit) match no message in the DBC.",
    "decode_error": "The DBC decoder raised an error for the frame (for example a payload length mismatch).",
    "frequency_deviation": (
        "Mean period of the message (gaps excluded) is compared with the configured or DBC cycle time; "
        "a deviation larger than the tolerance is reported."
    ),
    "timestamp_regression": "A frame carries an earlier timestamp than the frame before it in the log order.",
    "counter_error": (
        "The configured rolling counter is expected to increase by one (modulo its range) on every frame of its "
        "message; any other step is reported."
    ),
    "checksum_error": (
        "The configured checksum algorithm is recomputed over the covered payload bytes and compared with the "
        "transmitted checksum signal."
    ),
    "malformed_input": (
        "Text lines that match the frame layout of the log format are counted and compared with the number of "
        "frames the log reader produced. The difference is the number of lines skipped as unparseable."
    ),
    "empty_log": "No data frames could be read from the log file.",
}

CAUSES: dict[str, list[str]] = {
    "out_of_range": [
        "Sensor or ECU fault",
        "Scaling/offset in the DBC differs from what the transmitter uses",
        "A genuine out-of-limit physical condition",
    ],
    "gap": [
        "Transmitting ECU reset or power interruption",
        "Bus-off, wiring or arbitration problem",
        "The logger dropped frames (buffer overflow or trigger gap)",
    ],
    "missing_message": [
        "The transmitting ECU was not present or not active during the recording",
        "The DBC describes a different vehicle variant than the one logged",
        "Wrong channel was recorded",
    ],
    "malformed_input": [
        "Truncated or corrupted log (for example an interrupted download or logger crash)",
        "Payload bytes missing from a line, or an unsupported variant of the log format",
    ],
    "unknown_id": [
        "The DBC is incomplete or a different version",
        "Traffic from a node or channel not covered by the DBC",
        "A corrupted identifier",
    ],
    "decode_error": [
        "Payload length differs from the DBC definition",
        "The DBC message definition is wrong for this ID",
    ],
    "frequency_deviation": [
        "The ECU transmits at a different rate than the DBC states",
        "Event-triggered transmissions are mixed with cyclic ones",
    ],
    "timestamp_regression": [
        "Logs from several channels or sources were merged out of order",
        "Logger clock adjustment",
    ],
    "counter_error": [
        "Frames were lost or duplicated between transmitter and logger",
        "Transmitter restarted its counter",
    ],
    "checksum_error": [
        "Payload corruption",
        "The configured algorithm or covered bytes do not match the ECU's implementation",
    ],
}


@dataclass
class Finding:
    type: str
    severity: str
    classification: str
    time: float
    message: str
    detail: str
    signal: str | None = None
    end_time: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    legacy: dict[str, Any] = field(default_factory=dict)  # kept for API backward compatibility
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "classification": self.classification,
            "time": self.time,
            "end_time": self.end_time if self.end_time is not None else self.time,
            "message": self.message,
            "signal": self.signal,
            "detail": self.detail,
            "method": METHODS.get(self.type, ""),
            "evidence": self.evidence,
            "possible_causes": CAUSES.get(self.type, []),
        }
        d.update(self.legacy)
        return d


class FindingSink:
    """Collects findings and caps the number kept per (type, key) so that one broken
    signal cannot exhaust memory. The number dropped is reported, never hidden."""

    def __init__(self, cap_per_key: int = 200) -> None:
        self.cap = cap_per_key
        self.items: list[Finding] = []
        self._count: dict[tuple[str, str], int] = {}
        self.truncated: dict[str, int] = {}

    def add(self, finding: Finding, key: str = "") -> bool:
        k = (finding.type, key)
        n = self._count.get(k, 0) + 1
        self._count[k] = n
        if n > self.cap:
            label = f"{finding.type}:{key}" if key else finding.type
            self.truncated[label] = self.truncated.get(label, 0) + 1
            return False
        self.items.append(finding)
        return True
