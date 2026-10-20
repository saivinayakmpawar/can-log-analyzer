"""Cycle-time checks: gaps, stopped messages, missing messages, frequency, timestamp order."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from ..findings import OBSERVED, Finding, FindingSink
from ..rules import Rules
from .base import Check, FinishContext, Frame, Key


@dataclass
class _State:
    count: int = 0
    last_t: float = 0.0
    last_idx: int = 0
    n: int = 0          # normal (non-gap) intervals
    mean: float = 0.0
    m2: float = 0.0
    gaps: int = 0
    max_dt: float = 0.0
    regressions: int = 0
    duplicates: int = 0


def label(fid: int, ext: bool) -> str:
    return f"0x{fid:X} (ext)" if ext else f"0x{fid:X}"


class TimingCheck(Check):
    name = "timing"

    def __init__(self, db: Any, rules: Rules, expected: dict[Key, tuple[float, str]]) -> None:
        self.db, self.rules = db, rules
        self.expected = expected  # key -> (seconds, source)
        self.state: dict[Key, _State] = {}
        self.names = {(m.frame_id, m.is_extended_frame): m for m in db.messages}

    def _gap_factor(self, name: str) -> float:
        r = self.rules.messages.get(name)
        return (r.gap_factor if r and r.gap_factor else self.rules.gap_factor)

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:
        st = self.state.setdefault(frame.key, _State())
        st.count += 1
        if st.count == 1:
            st.last_t, st.last_idx = frame.t, frame.idx
            return
        d = frame.t - st.last_t
        if d < 0:  # timestamps went backwards; restart the interval chain here
            st.regressions += 1
            st.last_t, st.last_idx = frame.t, frame.idx
            return
        if d == 0:
            st.duplicates += 1
            st.last_idx = frame.idx
            return
        exp = self.expected.get(frame.key)
        factor = self._gap_factor(frame.msg.name)
        st.max_dt = max(st.max_dt, d)
        if exp and d > factor * exp[0]:
            st.gaps += 1
            expected_s, source = exp
            suffix = " (expected period inferred from the log median)" if source == "log_median_estimate" else ""
            sink.add(
                Finding(
                    type="gap", severity="high" if d > 10 * expected_s else "medium", classification=OBSERVED,
                    time=st.last_t, end_time=frame.t, message=frame.msg.name,
                    detail=(
                        f"No {frame.msg.name} for {d:.2f}s (expected every {expected_s * 1000:g} ms, "
                        f"about {int(d / expected_s) - 1} frames missing){suffix}"
                    ),
                    evidence={
                        "gap_s": round(d, 6), "expected_s": expected_s, "expected_source": source,
                        "gap_factor": factor, "estimated_missing_frames": int(d / expected_s) - 1,
                        "frame_before": st.last_idx, "frame_after": frame.idx,
                    },
                ),
                key=frame.msg.name,
            )
        else:
            st.n += 1
            delta = d - st.mean
            st.mean += delta / st.n
            st.m2 += delta * (d - st.mean)
        st.last_t, st.last_idx = frame.t, frame.idx

    def finish(self, ctx: FinishContext, sink: FindingSink) -> None:
        rows: list[dict[str, Any]] = []
        for (fid, ext), msg in self.names.items():
            st = self.state.get((fid, ext))
            exp = self.expected.get((fid, ext))
            rule = self.rules.messages.get(msg.name)
            base: dict[str, Any] = {
                "id": f"0x{fid:X}", "extended": ext, "name": msg.name,
                "senders": list(msg.senders),
                "expected_source": exp[1] if exp else None,
            }
            if st is None or st.count == 0:
                rows.append({**base, "count": 0, "expected_ms": round(exp[0] * 1000, 1) if exp else None,
                             "avg_ms": None, "jitter_ms": 0, "gaps": 0, "max_gap_ms": None})
                required = rule.required if rule and rule.required is not None else None
                if ctx.total_frames and required is not False:
                    cyclic = bool(exp)
                    sink.add(Finding(
                        type="missing_message", severity="high" if (cyclic or required) else "low",
                        classification=OBSERVED, time=0.0, message=msg.name,
                        detail=f"{msg.name} ({label(fid, ext)}) is defined in the DBC but never appears in the log",
                        evidence={"id": label(fid, ext), "expected_ms": round(exp[0] * 1000, 1) if exp else None,
                                  "log_frames_total": ctx.total_frames},
                    ), key=msg.name)
                continue
            expected_s = exp[0] if exp else None
            avg = st.mean if st.n else None
            row = {
                **base, "count": st.count,
                "expected_ms": round(expected_s * 1000, 1) if expected_s else None,
                "avg_ms": round(avg * 1000, 1) if avg is not None else None,
                "jitter_ms": round(math.sqrt(st.m2 / st.n) * 1000, 2) if st.n > 1 else 0,
                "gaps": st.gaps, "max_gap_ms": round(st.max_dt * 1000, 1) if st.max_dt else None,
            }
            if expected_s:
                factor = self._gap_factor(msg.name)
                tail = ctx.last_t - st.last_t
                if tail > factor * expected_s:
                    row["gaps"] += 1
                    sink.add(Finding(
                        type="gap", severity="high", classification=OBSERVED, time=st.last_t, end_time=ctx.last_t,
                        message=msg.name,
                        detail=(f"{msg.name} stopped at {st.last_t:.2f}s and never resumed "
                                f"(log continues for another {tail:.2f}s)"),
                        evidence={"gap_s": round(tail, 6), "expected_s": expected_s,
                                  "expected_source": exp[1] if exp else None, "gap_factor": factor,
                                  "stopped_for_rest_of_log": True, "frame_before": st.last_idx},
                    ), key=msg.name)
                tol = (rule.tolerance_pct if rule and rule.tolerance_pct else self.rules.frequency_tolerance_pct)
                if exp and exp[1] != "log_median_estimate" and avg is not None and st.n >= 10:
                    dev = abs(avg - expected_s) / expected_s * 100
                    if dev > tol:
                        sink.add(Finding(
                            type="frequency_deviation", severity="medium" if dev > 2 * tol else "low",
                            classification=OBSERVED, time=0.0, end_time=ctx.last_t, message=msg.name,
                            detail=(f"{msg.name} averages {avg * 1000:.1f} ms between frames, "
                                    f"{dev:.0f}% away from the expected {expected_s * 1000:g} ms"),
                            evidence={"expected_ms": expected_s * 1000, "mean_ms": avg * 1000,
                                      "deviation_pct": round(dev, 2), "tolerance_pct": tol, "intervals": st.n},
                        ), key=msg.name)
            rows.append(row)
        ctx.sections["messages"] = sorted(rows, key=lambda r: (r["extended"], r["id"]))
        ctx.sections["timestamp_stats"] = {
            "per_message_regressions": sum(s.regressions for s in self.state.values()),
            "duplicate_timestamps_same_message": sum(s.duplicates for s in self.state.values()),
        }


class TimestampOrderCheck(Check):
    """Reports frames whose timestamp is earlier than the previous frame in the log."""

    name = "timestamp_order"

    def __init__(self) -> None:
        self.prev_t: float | None = None
        self.prev_idx = -1
        self.count = 0

    def observe(self, idx: int, t: float, sink: FindingSink) -> None:
        if self.prev_t is not None and t < self.prev_t:
            self.count += 1
            sink.add(Finding(
                type="timestamp_regression", severity="medium", classification=OBSERVED, time=t,
                message="(log)", detail=f"Timestamp went backwards by {self.prev_t - t:.6f}s at frame #{idx}",
                evidence={"previous_t": self.prev_t, "t": t, "frame": idx, "previous_frame": self.prev_idx},
            ), key="log")
        self.prev_t, self.prev_idx = t, idx

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:  # unused: fed for all frames via observe()
        pass
