"""Rolling-counter and checksum validation (only for signals declared in the rules)."""
from __future__ import annotations

from typing import Any

from ..checksums import available, get_checksum
from ..errors import RuleError
from ..findings import CONFIRMED, Finding, FindingSink
from ..rules import Rules
from .base import Check, FinishContext, Frame


def _raw(sig: Any, physical: float) -> int:
    return round((physical - sig.offset) / sig.scale)


class CounterCheck(Check):
    name = "counter"

    def __init__(self, db: Any, rules: Rules) -> None:
        self.rules_by_msg: dict[str, list[tuple[Any, int, str]]] = {}
        for r in rules.counters:
            sig = db.get_message_by_name(r.message).get_signal_by_name(r.signal)
            modulus = r.modulus or 2 ** sig.length
            self.rules_by_msg.setdefault(r.message, []).append((sig, modulus, r.severity))
        self.prev: dict[tuple[str, str], tuple[int, float, int]] = {}

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:
        if frame.values is None:
            return
        for sig, modulus, severity in self.rules_by_msg.get(frame.msg.name, ()):
            if sig.name not in frame.values:  # inactive multiplexed signal
                continue
            cur = _raw(sig, frame.values[sig.name])
            key = (frame.msg.name, sig.name)
            prev = self.prev.get(key)
            if prev is not None:
                expected = (prev[0] + 1) % modulus
                if cur != expected:
                    step = (cur - prev[0]) % modulus
                    sink.add(Finding(
                        type="counter_error", severity=severity, classification=CONFIRMED, time=frame.t,
                        message=frame.msg.name, signal=sig.name,
                        detail=(f"{sig.name} went from {prev[0]} to {cur} (expected {expected}) at {frame.t:.3f}s"),
                        evidence={"previous_value": prev[0], "value": cur, "expected": expected,
                                  "modulus": modulus, "step": step,
                                  "frames_skipped_if_loss": (step - 1) % modulus,
                                  "previous_frame": prev[2], "frame": frame.idx},
                    ), key=f"{frame.msg.name}.{sig.name}")
            self.prev[key] = (cur, frame.t, frame.idx)

    def finish(self, ctx: FinishContext, sink: FindingSink) -> None:
        pass


class ChecksumCheck(Check):
    name = "checksum"

    def __init__(self, db: Any, rules: Rules) -> None:
        self.by_msg: dict[str, list[dict[str, Any]]] = {}
        self.open: dict[tuple[str, str], dict[str, Any]] = {}
        for r in rules.checksums:
            fn = get_checksum(r.algorithm)
            if fn is None:
                raise RuleError(f"Unknown checksum algorithm '{r.algorithm}'. Available: {', '.join(available())}")
            msg = db.get_message_by_name(r.message)
            sig = msg.get_signal_by_name(r.signal)
            msb_first = sig.byte_order == "big_endian"
            if sig.length != 8 or sig.start % 8 != (7 if msb_first else 0):
                raise RuleError(
                    f"Checksum signal {r.message}.{r.signal} must be a byte-aligned 8-bit signal "
                    "(other layouts are not supported)"
                )
            pos = sig.start // 8
            covered = r.bytes if r.bytes is not None else [i for i in range(msg.length) if i != pos]
            if any(i < 0 or i >= msg.length or i == pos for i in covered):
                raise RuleError(f"Checksum {r.message}.{r.signal}: 'bytes' must be payload indexes other than the checksum byte")
            try:
                fn(b"\x00", **r.params)
            except TypeError as exc:
                raise RuleError(f"Checksum {r.message}.{r.signal}: bad params for '{r.algorithm}': {exc}") from exc
            self.by_msg.setdefault(r.message, []).append(
                {"sig": sig, "fn": fn, "covered": covered, "params": r.params, "alg": r.algorithm,
                 "severity": r.severity, "pos": pos})

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:
        if frame.values is None:
            return
        for c in self.by_msg.get(frame.msg.name, ()):
            if c["sig"].name not in frame.values or len(frame.data) <= max([*c["covered"], c["pos"]]):
                continue
            key = (frame.msg.name, c["sig"].name)
            observed = _raw(c["sig"], frame.values[c["sig"].name])
            expected = c["fn"](bytes(frame.data[i] for i in c["covered"]), **c["params"])
            ev = self.open.get(key)
            if observed == expected:
                if ev is not None:
                    self._close(key, sink)
                continue
            if ev is None:
                self.open[key] = {"c": c, "start": frame.t, "end": frame.t, "frames": 1, "first_frame": frame.idx,
                                  "last_frame": frame.idx, "observed": observed, "expected": expected,
                                  "payload": bytes(frame.data).hex().upper()}
            else:
                ev["frames"] += 1
                ev["end"], ev["last_frame"] = frame.t, frame.idx

    def _close(self, key: tuple[str, str], sink: FindingSink) -> None:
        ev = self.open.pop(key)
        c = ev["c"]
        what = (f"{c['sig'].name} is 0x{ev['observed']:02X} but {c['alg']} over the payload gives "
                f"0x{ev['expected']:02X} at {ev['start']:.3f}s")
        if ev["frames"] > 1:
            what += f" ({ev['frames']} consecutive frames until {ev['end']:.3f}s)"
        sink.add(Finding(
            type="checksum_error", severity=c["severity"], classification=CONFIRMED, time=ev["start"],
            end_time=ev["end"], message=key[0], signal=key[1], detail=what,
            evidence={"algorithm": c["alg"], "params": c["params"], "covered_bytes": c["covered"],
                      "first_observed": ev["observed"], "first_expected": ev["expected"],
                      "failing_frames": ev["frames"], "first_frame": ev["first_frame"],
                      "last_frame": ev["last_frame"], "first_payload_hex": ev["payload"]},
        ), key=f"{key[0]}.{key[1]}")

    def finish(self, ctx: FinishContext, sink: FindingSink) -> None:
        for key in list(self.open):
            self._close(key, sink)
