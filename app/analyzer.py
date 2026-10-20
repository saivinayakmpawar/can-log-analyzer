"""Decode a CAN log against a DBC file and flag problems.

Pipeline
    1. ``ingest``  - stream the log into a SQLite frame store (bounded memory).
    2. ``check``   - stream the stored frames once through the registered checks.
    3. ``assemble``- build a JSON-serialisable result.

Checks live in ``app/checks`` and are listed in :func:`build_checks`.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import can
import cantools
from cantools.database.errors import Error as CantoolsError

from . import __version__
from .busload import BusLoad
from .checks import Check, FinishContext, Frame, Key
from .checks.integrity import ChecksumCheck, CounterCheck
from .checks.ranges import RangeCheck
from .checks.signals import SignalCollector
from .checks.timing import TimestampOrderCheck, TimingCheck, label
from .checksums import available as checksum_algorithms
from .errors import DbcError, LimitExceeded, LogParseError, RuleError
from .findings import OBSERVED, Finding, FindingSink
from .rules import Rules, parse_rules
from .store import FrameStore

MAX_POINTS = 1500  # per signal, for plotting
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

LIMITATIONS = [
    "Findings marked 'confirmed_violation' mean a configured rule (DBC range, user threshold, counter or "
    "checksum definition) was broken in the data. 'observed_anomaly' means a deviation from an expectation; "
    "it is not proof of a fault.",
    "Possible causes are hypotheses for the engineer to check. This tool does not confirm them.",
    "Expected cycle times come from the rules file, then the DBC GenMsgCycleTime attribute, then the median "
    "period seen in the log (an estimate, marked as such).",
    "A DBC signal range of [0|0] is treated as 'no limit defined'.",
    "Bus load is an estimate for classical CAN; CAN FD frames are excluded.",
    "Checksum algorithms and rolling counters are never guessed; only those declared in the rules are checked.",
    "Event-triggered messages without a cycle time have no gap detection beyond the log-median estimate.",
    "Lines the log reader cannot parse are skipped by python-can without notice; for .asc and .log files the "
    "tool compares frame-like lines with parsed frames and reports any difference. .csv and .blf files "
    "cannot be checked this way.",
    "A payload longer than the DBC message length is decoded with the DBC layout and the extra bytes are ignored.",
    "CAN FD frames are decoded with the DBC message definition; bit-rate switching and the data-phase bit rate "
    "are not evaluated.",
]


@dataclass
class Limits:
    max_frames: int = 3_000_000
    timeout_s: float | None = None

    def deadline(self) -> float | None:
        return time.monotonic() + self.timeout_s if self.timeout_s else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dbc(dbc_path: str | Path) -> tuple[Any, list[str]]:
    """Load a DBC. Falls back to non-strict mode (and says so) if signals overlap."""
    warnings: list[str] = []
    try:
        try:
            return cantools.database.load_file(str(dbc_path), strict=True), warnings
        except CantoolsError as strict_exc:
            db = cantools.database.load_file(str(dbc_path), strict=False)
            warnings.append(f"DBC loaded in tolerant mode: {str(strict_exc)[:200]}")
            return db, warnings
    except Exception as exc:  # parser errors are many types; message is trimmed
        raise DbcError(f"Could not read the DBC file: {str(exc)[:200]}") from exc


def validate_rules(db: Any, rules: Rules) -> None:
    def msg_of(name: str) -> Any:
        try:
            return db.get_message_by_name(name)
        except KeyError:
            raise RuleError(f"Rule refers to message '{name}', which is not in the DBC") from None

    def sig_of(msg: str, sig: str) -> Any:
        try:
            return msg_of(msg).get_signal_by_name(sig)
        except KeyError:
            raise RuleError(f"Rule refers to signal '{msg}.{sig}', which is not in the DBC") from None

    for t in rules.thresholds:
        if "." not in t.signal:
            raise RuleError(f"Threshold signal '{t.signal}' must be written Message.Signal")
        sig_of(*t.signal.split(".", 1))
        if t.min is None and t.max is None:
            raise RuleError(f"Threshold for '{t.signal}' needs a min or a max")
    for name in rules.messages:
        msg_of(name)
    for counter in rules.counters:
        sig_of(counter.message, counter.signal)
    for checksum in rules.checksums:
        sig_of(checksum.message, checksum.signal)


def build_checks(db: Any, rules: Rules, expected: dict[Key, tuple[float, str]]) -> list[Check]:
    """Registered checks, in execution order. Add new Check subclasses here."""
    return [
        RangeCheck(db, rules),
        TimingCheck(db, rules, expected),
        CounterCheck(db, rules),
        ChecksumCheck(db, rules),
        SignalCollector(db, MAX_POINTS),
    ]


_CANDIDATE = {
    # Vector ASC: "<time> <channel> <id> Rx|Tx ..." or "<time> CANFD <channel> Rx|Tx ..."
    ".asc": re.compile(r"^\s*\d+(?:\.\d+)?\s+(?:\d+\s+\S+\s+(?:Rx|Tx)\b|CANFD\s+\d+\s+(?:Rx|Tx)\b)"),
    # candump -L: "(<time>) <iface> <id>#<data>"
    ".log": re.compile(r"^\s*\(\d+(?:\.\d+)?\)\s+\S+\s+[0-9A-Fa-f]+#"),
}


def count_frame_like_lines(path: Path) -> int | None:
    """Number of text lines that look like CAN frames (None for formats we cannot scan).

    python-can skips lines it cannot parse without reporting them. Comparing this
    count with the number of frames actually parsed reveals silently dropped lines.
    """
    pattern = _CANDIDATE.get(path.suffix.lower())
    if pattern is None:
        return None
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if pattern.match(line):
                n += 1
    return n


def ingest(
    log_path: Path, store: FrameStore, bitrate: int, limits: Limits, deadline: float | None
) -> dict[str, Any]:
    """Stream a log file into the frame store. Returns counters and bus-load data."""
    con = store.open_for_ingest()
    bus = BusLoad(bitrate)
    batch: list[tuple] = []
    t0: float | None = None
    n = idx = remote = errors = fd = 0
    last_t = 0.0
    try:
        with can.LogReader(str(log_path)) as reader:
            for frame in reader:
                if frame.is_error_frame:
                    errors += 1
                    continue
                if t0 is None:
                    t0 = frame.timestamp
                t = round(frame.timestamp - t0, 6)
                last_t = max(last_t, t)
                data = bytes(frame.data)
                is_fd = bool(getattr(frame, "is_fd", False))
                is_remote = bool(frame.is_remote_frame)
                if idx >= limits.max_frames:
                    raise LimitExceeded(f"Log has more than {limits.max_frames:,} frames (limit)")
                if idx % 2000 == 0 and deadline and time.monotonic() > deadline:
                    raise LimitExceeded("Analysis time limit exceeded while reading the log")
                batch.append((idx, t, frame.arbitration_id, int(frame.is_extended_id), int(is_fd),
                              int(is_remote), frame.dlc if is_remote else len(data), data))
                idx += 1
                if is_fd:
                    fd += 1
                    bus.add_fd()
                elif is_remote:
                    remote += 1
                    bus.add(t, frame.is_extended_id, 0, counted=False)
                else:
                    n += 1
                    bus.add(t, frame.is_extended_id, len(data))
                if len(batch) >= 5000:
                    store.insert_many(con, batch)
                    batch.clear()
        if batch:
            store.insert_many(con, batch)
        store.finalize(con)
    except LimitExceeded:
        raise
    except Exception as exc:
        raise LogParseError(f"Could not read the CAN log: {str(exc)[:200]}") from exc
    finally:
        con.close()
    like = count_frame_like_lines(log_path)
    parsed = n + remote + fd
    skipped = max(0, like - parsed) if like is not None else None
    return {"data_frames": n, "remote": remote, "errors": errors, "fd": fd, "stored": idx,
            "last_t": last_t, "bus": bus.result(last_t), "frame_like_lines": like, "skipped_lines": skipped}


def analyze(
    dbc_path: str | Path,
    log_path: str | Path,
    gap_factor: float | None = None,
    bitrate: int = 500_000,
    rules: Rules | dict | bytes | str | None = None,
    store: FrameStore | None = None,
    limits: Limits | None = None,
    names: tuple[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Analyze a log. ``store`` keeps the decoded frame store for the viewer; when
    omitted a temporary one is used and deleted."""
    dbc_path, log_path = Path(dbc_path), Path(log_path)
    limits = limits or Limits()
    deadline = limits.deadline()
    rules_obj = rules if isinstance(rules, Rules) else parse_rules(rules)
    if gap_factor is not None:
        rules_obj = rules_obj.model_copy(update={"gap_factor": gap_factor})

    db, dbc_warnings = load_dbc(dbc_path)
    validate_rules(db, rules_obj)
    tmpdir = None
    if store is None:
        tmpdir = tempfile.mkdtemp(prefix="can-analyzer-")
        store = FrameStore(Path(tmpdir) / "frames.sqlite")
    try:
        ing = ingest(log_path, store, bitrate, limits, deadline)
        return _assemble(db, dbc_warnings, rules_obj, store, ing, dbc_path, log_path, names, now, deadline)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _expected_periods(db: Any, rules: Rules, store: FrameStore) -> dict[Key, tuple[float, str]]:
    out: dict[Key, tuple[float, str]] = {}
    need: list[Key] = []
    for m in db.messages:
        key = (m.frame_id, m.is_extended_frame)
        rule = rules.messages.get(m.name)
        if rule and rule.cycle_ms:
            out[key] = (rule.cycle_ms / 1000, "rule")
        elif m.cycle_time:
            out[key] = (m.cycle_time / 1000, "dbc")
        else:
            need.append(key)
    for key, period in store.median_periods(need).items():
        out[key] = (period, "log_median_estimate")
    return out


def _assemble(
    db: Any, dbc_warnings: list[str], rules: Rules, store: FrameStore, ing: dict[str, Any],
    dbc_path: Path, log_path: Path, names: tuple[str, str] | None, now: datetime | None,
    deadline: float | None,
) -> dict[str, Any]:
    by_key: dict[Key, Any] = {(m.frame_id, m.is_extended_frame): m for m in db.messages}
    expected = _expected_periods(db, rules, store)
    checks = build_checks(db, rules, expected)
    order = TimestampOrderCheck()
    sink = FindingSink()
    unknown: dict[Key, dict[str, Any]] = {}
    seen_keys: set[Key] = set()
    decoded_ok = 0

    for n, (idx, t, fid, ext, _fd, remote, _dlc, data) in enumerate(store.iter_frames()):
        if n % 2000 == 0 and deadline and time.monotonic() > deadline:
            raise LimitExceeded("Analysis time limit exceeded")
        order.observe(idx, t, sink)
        if remote:  # remote frames carry no payload; they are stored and counted for bus load only
            continue
        key = (fid, bool(ext))
        seen_keys.add(key)
        msg = by_key.get(key)
        if msg is None:
            u = unknown.setdefault(key, {"count": 0, "first": t, "last": t, "first_idx": idx, "dlcs": set()})
            u["count"] += 1
            u["last"] = t
            u["dlcs"].add(len(data))
            continue
        values: dict[str, float] | None
        try:
            values = msg.decode(data, decode_choices=False)
        except Exception as exc:  # DLC mismatch, bad data
            values = None
            _record_decode_error(sink, msg, t, idx, data, exc)
        else:
            decoded_ok += 1
        frame = Frame(idx=idx, t=t, key=key, msg=msg, data=data, values=values)
        for chk in checks:
            chk.on_frame(frame, sink)

    ctx = FinishContext(last_t=ing["last_t"], total_frames=ing["data_frames"] + ing["fd"], db=db)
    for chk in checks:
        chk.finish(ctx, sink)

    if ing["stored"] == 0:
        sink.add(Finding(type="empty_log", severity="high", classification=OBSERVED, time=0.0, message="(log)",
                         detail="The log contains no frames that could be read", evidence={}))
    if ing["skipped_lines"]:
        sink.add(Finding(
            type="malformed_input", severity="medium", classification=OBSERVED, time=0.0, message="(log)",
            detail=(f"{ing['skipped_lines']} line(s) look like CAN frames but could not be parsed and were skipped "
                    f"({ing['frame_like_lines']} frame-like lines, {ing['data_frames'] + ing['remote'] + ing['fd']} parsed)"),
            evidence={"frame_like_lines": ing["frame_like_lines"], "skipped_lines": ing["skipped_lines"],
                      "parsed_frames": ing["data_frames"] + ing["remote"] + ing["fd"]},
        ), key="log")
    for key, u in unknown.items():
        sink.add(Finding(
            type="unknown_id", severity="low", classification=OBSERVED, time=u["first"], end_time=u["last"],
            message=label(*key) if key[1] else f"0x{key[0]:X}",
            detail=f"ID {label(*key)} is not in the DBC ({u['count']} frames)",
            evidence={"id": key[0], "extended": key[1], "frames": u["count"], "first_frame": u["first_idx"],
                      "payload_lengths": sorted(u["dlcs"])},
        ), key=label(*key))

    findings = sorted(sink.items, key=lambda f: (SEVERITY_ORDER[f.severity], f.time, f.type, f.message))
    for i, f in enumerate(findings, 1):
        f.id = f"F{i:04d}"

    sections = ctx.sections
    messages = sections.get("messages", [])
    now = now or datetime.now(timezone.utc)
    dbc_name, log_name = names or (dbc_path.name, log_path.name)
    n_signals = sum(len(m.signals) for m in db.messages)
    return {
        "meta": {
            "software_version": __version__,
            "analyzed_at": now.replace(microsecond=0).isoformat(),
            "dbc": {"name": dbc_name, "sha256": _sha256(dbc_path), "size_bytes": dbc_path.stat().st_size,
                    "messages": len(db.messages), "signals": n_signals, "nodes": [n.name for n in db.nodes],
                    "version": db.version or None, "warnings": dbc_warnings},
            "log": {"name": log_name, "sha256": _sha256(log_path), "size_bytes": log_path.stat().st_size,
                    "format": log_path.suffix.lower().lstrip(".")},
            "config": {"bitrate": ing["bus"]["bitrate"], "rules": rules.model_dump(),
                       "checksum_algorithms_available": checksum_algorithms(), "max_plot_points": MAX_POINTS},
            "truncated_findings": sink.truncated,
        },
        "bus_load": ing["bus"],
        "summary": {
            "frames": ing["data_frames"], "duration_s": round(ing["last_t"], 3),
            "messages_decoded": len(messages), "messages_seen": sum(1 for m in messages if m["count"]),
            "unknown_ids": len(unknown), "anomalies": len(findings),
            "skipped_lines": ing["skipped_lines"],
            "unique_ids": len(seen_keys), "remote_frames": ing["remote"], "error_frames": ing["errors"],
            "fd_frames": ing["fd"], "frames_decoded": decoded_ok,
            "timestamp_regressions": order.count,
            **sections.get("timestamp_stats", {}),
        },
        "messages": messages,
        "anomalies": [f.to_dict() for f in findings],
        "signals": sections.get("signals", {}),
        "signal_stats": sections.get("signal_stats", {}),
        "limitations": LIMITATIONS,
    }




def _record_decode_error(sink: FindingSink, msg: Any, t: float, idx: int, data: bytes, exc: Exception) -> None:
    """One finding per message; later errors extend it instead of flooding the report."""
    for f in sink.items:
        if f.type == "decode_error" and f.message == msg.name:
            f.evidence["frames"] += 1
            f.end_time = t
            return
    sink.add(Finding(
        type="decode_error", severity="medium", classification=OBSERVED, time=t, end_time=t, message=msg.name,
        detail=f"Could not decode {len(data)}-byte frame: {str(exc)[:160]} (first occurrence; see evidence for count)",
        evidence={"frames": 1, "first_frame": idx, "payload_length": len(data), "expected_length": msg.length,
                  "error": str(exc)[:160]},
    ), key=msg.name)


def inspect_dbc(dbc_path: str | Path) -> dict[str, Any]:
    """Describe a DBC file without needing a log."""
    db, warnings = load_dbc(dbc_path)
    messages = []
    for m in sorted(db.messages, key=lambda x: (x.is_extended_frame, x.frame_id)):
        messages.append({
            "id": f"0x{m.frame_id:X}", "name": m.name, "dlc": m.length,
            "cycle_ms": m.cycle_time, "extended": m.is_extended_frame,
            "fd": bool(getattr(m, "is_fd", False)), "multiplexed": m.is_multiplexed(),
            "senders": list(m.senders),
            "signals": [{
                "name": sg.name, "start": sg.start, "length": sg.length,
                "byte_order": sg.byte_order, "signed": sg.is_signed,
                "scale": sg.scale, "offset": sg.offset,
                "min": sg.minimum, "max": sg.maximum, "unit": sg.unit or "",
                "multiplexer": bool(sg.is_multiplexer),
                "mux_ids": list(sg.multiplexer_ids) if sg.multiplexer_ids else None,
                "choices": ({str(k): str(v) for k, v in sg.choices.items()} if sg.choices else None),
            } for sg in m.signals]})
    return {"summary": {"messages": len(messages),
                        "signals": sum(len(m["signals"]) for m in messages),
                        "nodes": [n.name for n in db.nodes], "warnings": warnings},
            "messages": messages}
