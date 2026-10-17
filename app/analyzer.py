"""Decode a CAN log against a DBC file and flag problems.

Checks: out-of-range signals, missing/late cyclic messages, unknown IDs and
frames that do not decode (for example a DLC mismatch).
"""
import math
import statistics
from collections import defaultdict

import can
import cantools

MAX_POINTS = 1500  # per signal, for plotting


def _downsample(points):
    step = max(1, math.ceil(len(points) / MAX_POINTS))
    return points[::step]


def _excess(v, lo, hi):
    """How far a value sits outside its limits (0 when inside)."""
    if lo is not None and v < lo:
        return lo - v
    if hi is not None and v > hi:
        return v - hi
    return 0


def analyze(dbc_path, log_path, gap_factor=3.0, bitrate=500_000):
    db = cantools.database.load_file(str(dbc_path))
    by_id = {m.frame_id: m for m in db.messages}

    stamps = defaultdict(list)    # frame_id -> [t]
    series = defaultdict(list)    # (message, signal) -> [[t, v]]
    open_events = {}              # (message, signal) -> running out-of-range event
    anomalies = []
    unknown = {}
    sec_frames = defaultdict(int)
    sec_bits = defaultdict(int)
    t0 = None
    total = 0
    last_t = 0.0

    with can.LogReader(str(log_path)) as reader:
        for frame in reader:
            if frame.is_error_frame or frame.is_remote_frame:
                continue
            if t0 is None:
                t0 = frame.timestamp
            t = round(frame.timestamp - t0, 6)
            last_t = t
            total += 1
            # Approximate frame size on the wire (no bit stuffing)
            bits = (67 if frame.is_extended_id else 47) + 8 * len(frame.data)
            sec_frames[int(t)] += 1
            sec_bits[int(t)] += bits
            fid = frame.arbitration_id
            msg = by_id.get(fid)

            if msg is None:
                u = unknown.setdefault(fid, {"count": 0, "first": t})
                u["count"] += 1
                continue

            stamps[fid].append(t)
            try:
                values = msg.decode(frame.data, decode_choices=False)
            except Exception as exc:  # DLC mismatch, bad data
                anomalies.append({
                    "type": "decode_error", "severity": "medium", "time": t,
                    "message": msg.name,
                    "detail": f"Could not decode {len(frame.data)}-byte frame: {exc}"})
                continue

            for sig in msg.signals:
                v = values[sig.name]
                key = (msg.name, sig.name)
                series[key].append([t, v])
                lo, hi = sig.minimum, sig.maximum
                bad = _excess(v, lo, hi) > 0
                ev = open_events.get(key)
                if bad:
                    if ev is None:
                        open_events[key] = {
                            "type": "out_of_range", "severity": "high", "time": t,
                            "message": msg.name, "signal": sig.name,
                            "limits": [lo, hi], "worst": v, "frames": 1, "end": t}
                    else:
                        ev["frames"] += 1
                        ev["end"] = t
                        if _excess(v, lo, hi) > _excess(ev["worst"], lo, hi):
                            ev["worst"] = v
                elif ev is not None:
                    anomalies.append(open_events.pop(key))

    anomalies.extend(open_events.values())
    for ev in anomalies:
        if ev["type"] == "out_of_range":
            ev["detail"] = (f"{ev['signal']} reached {ev['worst']:g} "
                            f"(allowed {ev['limits'][0]} to {ev['limits'][1]}), "
                            f"{ev['frames']} frame(s) from {ev['time']:.2f}s to {ev['end']:.2f}s")

    # Cycle timing per message
    messages = []
    for fid, msg in by_id.items():
        ts = stamps.get(fid, [])
        cycle = msg.cycle_time / 1000 if msg.cycle_time else None
        if not ts:  # defined in the DBC but never seen
            messages.append({"id": f"0x{fid:X}", "name": msg.name, "count": 0,
                             "expected_ms": round(cycle * 1000, 1) if cycle else None,
                             "avg_ms": None, "jitter_ms": 0, "gaps": 0})
            anomalies.append({
                "type": "missing_message", "severity": "high" if cycle else "low",
                "time": 0.0, "message": msg.name,
                "detail": f"{msg.name} (0x{fid:X}) is defined in the DBC but never appears in the log"})
            continue
        diffs = [b - a for a, b in zip(ts, ts[1:])]
        expected = cycle or (statistics.median(diffs) if diffs else None)
        # Timing stats ignore dropouts so they describe normal operation
        normal = [d for d in diffs if not expected or d <= gap_factor * expected]
        row = {"id": f"0x{fid:X}", "name": msg.name, "count": len(ts),
               "expected_ms": round(expected * 1000, 1) if expected else None,
               "avg_ms": round(statistics.mean(normal) * 1000, 1) if normal else None,
               "jitter_ms": round(statistics.pstdev(normal) * 1000, 2) if len(normal) > 1 else 0,
               "gaps": 0}
        if expected:
            for a, b in zip(ts, ts[1:]):
                if b - a > gap_factor * expected:
                    row["gaps"] += 1
                    anomalies.append({
                        "type": "gap", "severity": "high" if b - a > 10 * expected else "medium",
                        "time": a, "message": msg.name,
                        "detail": (f"No {msg.name} for {b - a:.2f}s "
                                   f"(expected every {expected * 1000:g} ms, "
                                   f"about {int((b - a) / expected) - 1} frames missing)")})
            tail = last_t - ts[-1]
            if tail > gap_factor * expected:  # stopped and never resumed
                row["gaps"] += 1
                anomalies.append({
                    "type": "gap", "severity": "high", "time": ts[-1], "message": msg.name,
                    "detail": (f"{msg.name} stopped at {ts[-1]:.2f}s and never resumed "
                               f"(log continues for another {tail:.2f}s)")})
        messages.append(row)

    for fid, u in unknown.items():
        anomalies.append({
            "type": "unknown_id", "severity": "low", "time": u["first"],
            "message": f"0x{fid:X}",
            "detail": f"ID 0x{fid:X} is not in the DBC ({u['count']} frames)"})

    order = {"high": 0, "medium": 1, "low": 2}
    anomalies.sort(key=lambda a: (order[a["severity"]], a["time"]))
    for a in anomalies:
        a.pop("end", None)

    by_name = {m.name: m for m in db.messages}
    signals = {}
    for (m, s), pts in series.items():
        sig = by_name[m].get_signal_by_name(s)
        signals[f"{m}.{s}"] = {"unit": sig.unit or "", "points": _downsample(pts),
                                "min": sig.minimum, "max": sig.maximum}

    points = []
    for sec in range(int(last_t) + 1):
        window = max(min(1.0, last_t - sec), 0.1)
        pct = sec_bits[sec] / (bitrate * window) * 100
        points.append([sec, sec_frames[sec], round(pct, 3)])
    loads = [p[2] for p in points] or [0]
    bus_load = {"bitrate": bitrate, "points": points,
                "avg_pct": round(sum(sec_bits.values()) / (bitrate * max(last_t, 0.1)) * 100, 3),
                "peak_pct": max(loads)}

    return {
        "bus_load": bus_load,
        "summary": {"frames": total, "duration_s": round(last_t, 3),
                    "messages_decoded": len(messages), "unknown_ids": len(unknown),
                    "anomalies": len(anomalies)},
        "messages": sorted(messages, key=lambda r: r["id"]),
        "anomalies": anomalies,
        "signals": signals,
    }


def inspect_dbc(dbc_path):
    """Describe a DBC file without needing a log."""
    db = cantools.database.load_file(str(dbc_path))
    messages = []
    for m in sorted(db.messages, key=lambda x: x.frame_id):
        messages.append({
            "id": f"0x{m.frame_id:X}", "name": m.name, "dlc": m.length,
            "cycle_ms": m.cycle_time, "extended": m.is_extended_frame,
            "senders": list(m.senders),
            "signals": [{
                "name": sg.name, "start": sg.start, "length": sg.length,
                "scale": sg.scale, "offset": sg.offset,
                "min": sg.minimum, "max": sg.maximum, "unit": sg.unit or "",
                "choices": ({str(k): str(v) for k, v in sg.choices.items()} if sg.choices else None),
            } for sg in m.signals]})
    return {"summary": {"messages": len(messages),
                        "signals": sum(len(m["signals"]) for m in messages),
                        "nodes": [n.name for n in db.nodes]},
            "messages": messages}
