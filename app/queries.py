"""On-demand queries against a stored analysis: frame pages, signal ranges, correlation."""
from __future__ import annotations

import bisect
import math
from typing import Any

from .analyzer import load_dbc
from .checks.signals import _Stat
from .downsample import MinMaxDecimator
from .store import FrameFilter, FrameRow, FrameStore


class QueryError(ValueError):
    """Bad query parameter; the message is safe to show to the client."""


def fmt_id(fid: int, ext: bool) -> str:
    return f"0x{fid:08X}" if ext else f"0x{fid:03X}"


def _plain(v: Any) -> Any:
    if isinstance(v, (int, float)):
        return v
    return str(v)


class DbcIndex:
    def __init__(self, dbc_path: Any) -> None:
        self.db, _ = load_dbc(dbc_path)
        self.by_key = {(m.frame_id, m.is_extended_frame): m for m in self.db.messages}
        self.by_name = {m.name: m for m in self.db.messages}

    def signal_ref(self, name: str) -> tuple[Any, Any]:
        if "." not in name:
            raise QueryError("Signal must be written Message.Signal")
        m, s = name.split(".", 1)
        msg = self.by_name.get(m)
        if msg is None:
            raise QueryError(f"Unknown message '{m}'")
        try:
            return msg, msg.get_signal_by_name(s)
        except KeyError:
            raise QueryError(f"Unknown signal '{name}'") from None


def build_filter(
    idx: DbcIndex, *, t0: float | None, t1: float | None, can_id: str | None, text: str | None,
    fmt: str | None, message: str | None,
) -> FrameFilter:
    flt = FrameFilter(t0=t0, t1=t1)
    if fmt in ("std", "ext"):
        flt.ext = fmt == "ext"
    elif fmt == "fd":
        flt.fd = True
    elif fmt not in (None, "", "any"):
        raise QueryError("format must be one of any, std, ext, fd")
    keys: list[tuple[int, bool | None]] | None = None
    if can_id:
        try:
            keys = [(int(can_id.strip(), 16), None)]
        except ValueError:
            raise QueryError("ID must be hexadecimal, for example 1A0 or 0x1A0") from None
    if message:
        m = idx.by_name.get(message)
        if m is None:
            raise QueryError(f"Unknown message '{message}'")
        keys = [(m.frame_id, m.is_extended_frame)]
    if text:
        needle = text.strip()
        hits: list[tuple[int, bool | None]] = [
            (m.frame_id, m.is_extended_frame) for m in idx.db.messages if needle.lower() in m.name.lower()
        ]
        # A hex-looking search term can also match payload bytes.
        hexlike = needle.replace(" ", "")
        if hexlike and all(c in "0123456789abcdefABCDEF" for c in hexlike) and not hits:
            flt.data_hex = hexlike
        elif hits:
            keys = hits if keys is None else [k for k in keys if k in hits]
        else:
            keys = []
    flt.keys = keys
    return flt


def decode_page(idx: DbcIndex, rows: list[FrameRow]) -> list[dict[str, Any]]:
    out = []
    for i, t, fid, ext, fd, remote, dlc, data in rows:
        msg = idx.by_key.get((fid, bool(ext)))
        decoded: dict[str, Any] | None = None
        status = "ok"
        if msg is None:
            status = "unknown"
        elif remote:
            status = "remote"
        else:
            try:
                vals = msg.decode(data, decode_choices=True)
                decoded = {k: {"value": _plain(v), "unit": msg.get_signal_by_name(k).unit or ""} for k, v in vals.items()}
            except Exception:
                status = "decode_error"
        out.append({
            "idx": i, "t": t, "id": fmt_id(fid, bool(ext)), "format": "FD" if fd else ("EXT" if ext else "STD"),
            "remote": bool(remote), "dlc": dlc, "data": " ".join(f"{b:02X}" for b in data),
            "message": msg.name if msg else None, "status": status, "signals": decoded,
        })
    return out


def signal_series(
    idx: DbcIndex, store: FrameStore, name: str, t0: float | None, t1: float | None, max_points: int
) -> dict[str, Any]:
    if not 50 <= max_points <= 20000:
        raise QueryError("max_points must be between 50 and 20000")
    msg, sig = idx.signal_ref(name)
    dec = MinMaxDecimator(max_points)
    stat = _Stat()
    flt = FrameFilter(t0=t0, t1=t1, keys=[(msg.frame_id, msg.is_extended_frame)])
    for _i, t, _fid, _ext, _fd, remote, _dlc, data in store.iter_frames(flt):
        if remote:
            continue
        try:
            v = msg.decode(data, decode_choices=False).get(sig.name)
        except Exception:  # noqa: S112 - undecodable frames are reported by the analysis, not here
            continue
        if v is None or v != v:
            continue
        dec.add(t, float(v))
        stat.add(t, float(v))
    slope = stat.c_tv / stat.m2_t if stat.m2_t > 0 else None
    return {
        "name": name, "unit": sig.unit or "", "points": dec.points(), "samples": dec.n_seen,
        "downsampled": dec.downsampled, "t0": t0, "t1": t1,
        "stats": None if not stat.n else {
            "count": stat.n, "min": stat.vmin, "max": stat.vmax, "mean": stat.mean_v,
            "std": math.sqrt(stat.m2_v / stat.n), "slope_per_s": slope,
        },
        "trend_method": "Ordinary least-squares slope of value against time over the selected range; "
                        "descriptive only, it does not imply a linear process.",
    }


def _raw_series(idx: DbcIndex, store: FrameStore, name: str, t0: float | None, t1: float | None) -> list[tuple[float, float]]:
    msg, sig = idx.signal_ref(name)
    out: list[tuple[float, float]] = []
    flt = FrameFilter(t0=t0, t1=t1, keys=[(msg.frame_id, msg.is_extended_frame)])
    for _i, t, _fid, _ext, _fd, remote, _dlc, data in store.iter_frames(flt):
        if remote:
            continue
        try:
            v = msg.decode(data, decode_choices=False).get(sig.name)
        except Exception:  # noqa: S112 - undecodable frames are reported by the analysis, not here
            continue
        if v is not None and v == v:
            out.append((t, float(v)))
    return out


def correlation(
    idx: DbcIndex, store: FrameStore, x: str, y: str, t0: float | None, t1: float | None
) -> dict[str, Any]:
    """Pearson correlation of two signals. ``y`` is linearly interpolated at the sample
    times of ``x``, only inside the time span where ``y`` has data."""
    xs, ys = _raw_series(idx, store, x, t0, t1), _raw_series(idx, store, y, t0, t1)
    base = {"x": x, "y": y, "t0": t0, "t1": t1, "method": (
        "Pearson r between x and y, with y linearly interpolated at x's timestamps inside y's time span. "
        "Correlation does not establish causation."), "n": 0, "r": None}
    if len(xs) < 3 or len(ys) < 3:
        return {**base, "note": "Not enough samples in the selected range"}
    yt = [p[0] for p in ys]
    pairs: list[tuple[float, float]] = []
    for t, xv in xs:
        if t < yt[0] or t > yt[-1]:
            continue
        j = bisect.bisect_left(yt, t)
        if j < len(yt) and yt[j] == t:
            yv = ys[j][1]
        else:
            (ta, va), (tb, vb) = ys[j - 1], ys[j]
            yv = va + (vb - va) * (t - ta) / (tb - ta)
        pairs.append((xv, yv))
    if len(pairs) > 20000:
        pairs = pairs[:: math.ceil(len(pairs) / 20000)]
    n = len(pairs)
    if n < 10:
        return {**base, "n": n, "note": "Fewer than 10 overlapping samples; no coefficient reported"}
    mx, my = sum(p[0] for p in pairs) / n, sum(p[1] for p in pairs) / n
    sxx = sum((p[0] - mx) ** 2 for p in pairs)
    syy = sum((p[1] - my) ** 2 for p in pairs)
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pairs)
    if sxx == 0 or syy == 0:
        return {**base, "n": n, "note": "One signal is constant in this range; correlation is undefined"}
    return {**base, "n": n, "r": sxy / math.sqrt(sxx * syy)}


def around_finding(idx: DbcIndex, store: FrameStore, finding: dict[str, Any], n: int = 4) -> list[dict[str, Any]]:
    """Frames of the finding's message nearest its start time (related-frame context)."""
    msg = idx.by_name.get(finding.get("message", ""))
    if msg is None:
        return []
    rows = store.around((msg.frame_id, msg.is_extended_frame), float(finding["time"]), before=n, after=n)
    return decode_page(idx, rows)
