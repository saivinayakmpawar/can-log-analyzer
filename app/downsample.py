"""Streaming, bounded-memory reduction of a (time, value) series for plotting.

The reducer keeps both the minimum and the maximum of every bucket, so a short
spike (for example a 3-frame SOC excursion) is never averaged away. While the
series has at most ``max_points / 2`` samples it is returned exactly.
"""
from __future__ import annotations

Point = tuple[float, float]


class MinMaxDecimator:
    def __init__(self, max_points: int = 1500) -> None:
        self.cap = max(2, max_points // 2)
        self.width = 1
        self.n_seen = 0
        # bucket: [count, t_first, vmin, tmin, vmax, tmax]
        self._buckets: list[list[float]] = []
        self._cur: list[float] | None = None

    def add(self, t: float, v: float) -> None:
        self.n_seen += 1
        c = self._cur
        if c is None:
            self._cur = c = [1, t, v, t, v, t]
        else:
            c[0] += 1
            if v < c[2]:
                c[2], c[3] = v, t
            if v > c[4]:
                c[4], c[5] = v, t
        if c[0] >= self.width:
            self._buckets.append(c)
            self._cur = None
            if len(self._buckets) > self.cap:
                self._merge()

    def _merge(self) -> None:
        merged: list[list[float]] = []
        b = self._buckets
        for i in range(0, len(b) - 1, 2):
            x, y = b[i], b[i + 1]
            lo = x if x[2] <= y[2] else y
            hi = x if x[4] >= y[4] else y
            merged.append([x[0] + y[0], x[1], lo[2], lo[3], hi[4], hi[5]])
        if len(b) % 2:
            merged.append(b[-1])
        self._buckets = merged
        self.width *= 2

    @property
    def downsampled(self) -> bool:
        return self.width > 1 or (self._cur is not None and self._cur[0] > 1)

    def points(self) -> list[list[float]]:
        buckets = list(self._buckets)
        if self._cur is not None:
            buckets.append(self._cur)
        out: list[list[float]] = []
        for count, t_first, vmin, tmin, vmax, tmax in buckets:
            if count == 1:
                out.append([t_first, vmin])
                continue
            pair = sorted({(tmin, vmin), (tmax, vmax)})
            out.extend([p[0], p[1]] for p in pair)
        return out
