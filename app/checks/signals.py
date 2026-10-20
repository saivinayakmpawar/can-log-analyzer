"""Collects plot series and per-signal statistics in a single streaming pass."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from ..downsample import MinMaxDecimator
from ..findings import FindingSink
from .base import Check, FinishContext, Frame
from .ranges import dbc_limits


@dataclass
class _Stat:
    n: int = 0
    vmin: float = math.inf
    vmax: float = -math.inf
    mean_v: float = 0.0
    m2_v: float = 0.0
    mean_t: float = 0.0
    m2_t: float = 0.0
    c_tv: float = 0.0

    def add(self, t: float, v: float) -> None:
        self.n += 1
        dt, dv = t - self.mean_t, v - self.mean_v
        self.mean_t += dt / self.n
        self.mean_v += dv / self.n
        self.m2_t += dt * (t - self.mean_t)
        self.m2_v += dv * (v - self.mean_v)
        self.c_tv += dt * (v - self.mean_v)
        if v < self.vmin:
            self.vmin = v
        if v > self.vmax:
            self.vmax = v


class SignalCollector(Check):
    name = "signals"

    def __init__(self, db: Any, max_points: int = 1500) -> None:
        self.max_points = max_points
        self.sig = {(m.name, s.name): s for m in db.messages for s in m.signals}
        self.series: dict[tuple[str, str], MinMaxDecimator] = {}
        self.stats: dict[tuple[str, str], _Stat] = {}

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:
        if frame.values is None:
            return
        for name, v in frame.values.items():
            if v != v:
                continue
            key = (frame.msg.name, name)
            dec = self.series.get(key)
            if dec is None:
                dec = self.series[key] = MinMaxDecimator(self.max_points)
                self.stats[key] = _Stat()
            dec.add(frame.t, float(v))
            self.stats[key].add(frame.t, float(v))

    def finish(self, ctx: FinishContext, sink: FindingSink) -> None:
        signals: dict[str, Any] = {}
        stats: dict[str, Any] = {}
        for key, dec in self.series.items():
            s = self.sig[key]
            lim = dbc_limits(s)
            label = f"{key[0]}.{key[1]}"
            signals[label] = {
                "unit": s.unit or "", "points": dec.points(),
                "min": lim[0] if lim else None, "max": lim[1] if lim else None,
                "downsampled": dec.downsampled, "samples": dec.n_seen,
            }
            st = self.stats[key]
            slope = st.c_tv / st.m2_t if st.m2_t > 0 else None
            stats[label] = {
                "unit": s.unit or "", "count": st.n, "min": st.vmin, "max": st.vmax,
                "mean": round(st.mean_v, 6), "std": round(math.sqrt(st.m2_v / st.n), 6),
                "slope_per_s": slope,
            }
        ctx.sections["signals"] = signals
        ctx.sections["signal_stats"] = stats
