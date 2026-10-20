"""Signal limit check (DBC min/max and user thresholds)."""
from __future__ import annotations

from typing import Any

from ..findings import CONFIRMED, Finding, FindingSink
from ..rules import Rules
from .base import Check, FinishContext, Frame

Limit = tuple[float | None, float | None, str, str]  # lo, hi, source, severity


def excess(v: float, lo: float | None, hi: float | None) -> float:
    """How far a value sits outside its limits (0 when inside)."""
    if lo is not None and v < lo:
        return lo - v
    if hi is not None and v > hi:
        return v - hi
    return 0.0


def dbc_limits(sig: Any) -> tuple[float | None, float | None] | None:
    """DBC limits, or None when the file does not define any.

    A DBC range of ``[0|0]`` is the conventional "unspecified" marker, so it is
    not treated as a limit that only allows the value zero.
    """
    lo, hi = sig.minimum, sig.maximum
    if lo is None and hi is None:
        return None
    if lo == 0 and hi == 0:
        return None
    return lo, hi


class RangeCheck(Check):
    name = "range"

    def __init__(self, db: Any, rules: Rules) -> None:
        self.limits: dict[tuple[str, str], list[Limit]] = {}
        for msg in db.messages:
            for sig in msg.signals:
                lst: list[Limit] = []
                if rules.use_dbc_limits:
                    lim = dbc_limits(sig)
                    if lim:
                        lst.append((lim[0], lim[1], "DBC", "high"))
                if lst:
                    self.limits[(msg.name, sig.name)] = lst
        for rule in rules.thresholds:
            m, s = rule.signal.split(".", 1)
            self.limits.setdefault((m, s), []).append((rule.min, rule.max, "rule", rule.severity))
        self.units = {(m.name, s.name): s.unit or "" for m in db.messages for s in m.signals}
        self.open: dict[tuple[str, str, int], dict[str, Any]] = {}

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:
        if frame.values is None:
            return
        name = frame.msg.name
        for sig, v in frame.values.items():
            limits = self.limits.get((name, sig))
            if not limits or v != v:  # no limits, or NaN
                continue
            for i, (lo, hi, source, severity) in enumerate(limits):
                key = (name, sig, i)
                bad = excess(v, lo, hi) > 0
                ev = self.open.get(key)
                if bad:
                    if ev is None:
                        self.open[key] = {
                            "start": frame.t, "end": frame.t, "frames": 1, "worst": v, "first": v,
                            "first_frame": frame.idx, "worst_frame": frame.idx, "last_frame": frame.idx,
                            "limits": (lo, hi), "source": source, "severity": severity,
                        }
                    else:
                        ev["frames"] += 1
                        ev["end"] = frame.t
                        ev["last_frame"] = frame.idx
                        if excess(v, lo, hi) > excess(ev["worst"], lo, hi):
                            ev["worst"], ev["worst_frame"] = v, frame.idx
                elif ev is not None:
                    self._close(key, sink)

    def _close(self, key: tuple[str, str, int], sink: FindingSink) -> None:
        ev = self.open.pop(key)
        msg, sig, _ = key
        lo, hi = ev["limits"]
        unit = self.units.get((msg, sig), "")
        detail = (
            f"{sig} reached {ev['worst']:g} (allowed {lo} to {hi}), {ev['frames']} frame(s) "
            f"from {ev['start']:.2f}s to {ev['end']:.2f}s"
        )
        sink.add(
            Finding(
                type="out_of_range", severity=ev["severity"], classification=CONFIRMED,
                time=ev["start"], end_time=ev["end"], message=msg, signal=sig, detail=detail,
                evidence={
                    "limit_source": ev["source"], "min": lo, "max": hi, "unit": unit,
                    "first_value": ev["first"], "worst_value": ev["worst"], "violating_frames": ev["frames"],
                    "first_frame": ev["first_frame"], "worst_frame": ev["worst_frame"],
                    "last_frame": ev["last_frame"],
                },
                legacy={"limits": [lo, hi], "worst": ev["worst"], "frames": ev["frames"]},
            ),
            key=f"{msg}.{sig}",
        )

    def finish(self, ctx: FinishContext, sink: FindingSink) -> None:
        for key in list(self.open):
            self._close(key, sink)
