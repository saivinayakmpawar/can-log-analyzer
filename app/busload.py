"""Bus-load estimation for classical CAN.

Assumptions (also written into every report):

* Frame length on the wire is computed from the standard frame layout:
  47 bits of overhead for 11-bit identifiers and 67 bits for 29-bit identifiers
  (including 3 bits of interframe space), plus 8 bits per data byte.
* The *nominal* figure ignores bit stuffing. The *worst-case* figure adds the
  maximum number of stuff bits (one per 4 bits of the stuffed region) and is an
  upper bound, not a measurement.
* The bit rate is supplied by the user; it cannot be derived from a log.
* CAN FD frames are excluded because their length depends on a separate
  data-phase bit rate that a log file does not record.
"""
from __future__ import annotations

from collections import defaultdict


def frame_bits(extended: bool, data_bytes: int) -> tuple[int, int]:
    """Return (nominal_bits, worst_case_bits) for one classical CAN frame."""
    overhead = 67 if extended else 47
    stuffed_region = (54 if extended else 34) + 8 * data_bytes
    nominal = overhead + 8 * data_bytes
    return nominal, nominal + (stuffed_region - 1) // 4


class BusLoad:
    def __init__(self, bitrate: int) -> None:
        self.bitrate = bitrate
        self.frames: dict[int, int] = defaultdict(int)
        self.nominal: dict[int, int] = defaultdict(int)
        self.worst: dict[int, int] = defaultdict(int)
        self.fd_frames = 0

    def add(self, t: float, extended: bool, data_bytes: int, counted: bool = True) -> None:
        """Add one frame. Remote frames use ``counted=False``: they occupy bus time but
        are not data frames, so they add bits without adding to the frame count."""
        sec = int(t)
        nominal, worst = frame_bits(extended, data_bytes)
        if counted:
            self.frames[sec] += 1
        self.nominal[sec] += nominal
        self.worst[sec] += worst

    def add_fd(self) -> None:
        self.fd_frames += 1

    def result(self, last_t: float) -> dict:
        points, worst_points = [], []
        for sec in range(int(last_t) + 1):
            window = max(min(1.0, last_t - sec), 0.1)
            cap = self.bitrate * window
            points.append([sec, self.frames[sec], round(self.nominal[sec] / cap * 100, 3)])
            worst_points.append([sec, round(self.worst[sec] / cap * 100, 3)])
        span = self.bitrate * max(last_t, 0.1)
        loads = [p[2] for p in points] or [0]
        worst_loads = [p[1] for p in worst_points] or [0]
        return {
            "bitrate": self.bitrate,
            "points": points,
            "avg_pct": round(sum(self.nominal.values()) / span * 100, 3),
            "peak_pct": max(loads),
            "worst_case_points": worst_points,
            "avg_pct_worst_case": round(sum(self.worst.values()) / span * 100, 3),
            "peak_pct_worst_case": max(worst_loads),
            "fd_frames_excluded": self.fd_frames,
            "assumptions": [
                "Nominal load ignores bit stuffing; worst-case adds the maximum possible stuff bits.",
                "Bit rate is user-supplied and not verified against the log.",
                "Classical CAN frames only; CAN FD frames are excluded from load figures.",
                "Load is computed per 1-second window from first-frame time.",
            ],
        }
