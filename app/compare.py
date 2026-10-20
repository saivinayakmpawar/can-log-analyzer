"""Descriptive comparison of two stored analyses. Differences are reported, not explained."""
from __future__ import annotations

from collections import Counter
from typing import Any


def _fkey(f: dict[str, Any]) -> tuple[str, str, str]:
    return f["type"], f["message"], f.get("signal") or ""


def compare_results(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    notes: list[str] = []
    if a["meta"]["dbc"]["sha256"] != b["meta"]["dbc"]["sha256"]:
        notes.append("The two analyses used different DBC files; signal and message names may not be comparable.")
    if a["bus_load"]["bitrate"] != b["bus_load"]["bitrate"]:
        notes.append("The analyses assumed different bit rates; bus-load figures are not directly comparable.")

    def msg_index(r: dict[str, Any]) -> dict[tuple[str, bool], dict[str, Any]]:
        return {(m["name"], m["extended"]): m for m in r["messages"]}

    ma, mb = msg_index(a), msg_index(b)
    messages = []
    for key in sorted(set(ma) | set(mb)):
        x, y = ma.get(key), mb.get(key)
        row: dict[str, Any] = {"name": key[0], "extended": key[1],
                               "count_a": x["count"] if x else None, "count_b": y["count"] if y else None,
                               "avg_ms_a": x["avg_ms"] if x else None, "avg_ms_b": y["avg_ms"] if y else None,
                               "gaps_a": x["gaps"] if x else None, "gaps_b": y["gaps"] if y else None}
        if row["avg_ms_a"] is not None and row["avg_ms_b"] is not None:
            row["avg_ms_delta"] = round(row["avg_ms_b"] - row["avg_ms_a"], 2)
        messages.append(row)

    sa, sb = a.get("signal_stats", {}), b.get("signal_stats", {})
    signals = []
    for name in sorted(set(sa) | set(sb)):
        x, y = sa.get(name), sb.get(name)
        row = {"name": name, "unit": (x or y or {}).get("unit", ""),
               "present_a": x is not None, "present_b": y is not None}
        if x and y:
            row.update({"min_a": x["min"], "min_b": y["min"], "max_a": x["max"], "max_b": y["max"],
                        "mean_a": x["mean"], "mean_b": y["mean"], "mean_delta": round(y["mean"] - x["mean"], 6)})
        signals.append(row)

    ca, cb = Counter(map(_fkey, a["anomalies"])), Counter(map(_fkey, b["anomalies"]))
    findings = []
    for k in sorted(set(ca) | set(cb)):
        status = "in_both" if k in ca and k in cb else ("only_in_a" if k in ca else "only_in_b")
        findings.append({"type": k[0], "message": k[1], "signal": k[2] or None,
                         "count_a": ca.get(k, 0), "count_b": cb.get(k, 0), "status": status})
    return {
        "a": {"name": a["meta"]["log"]["name"], "analyzed_at": a["meta"]["analyzed_at"], "summary": a["summary"]},
        "b": {"name": b["meta"]["log"]["name"], "analyzed_at": b["meta"]["analyzed_at"], "summary": b["summary"]},
        "notes": notes, "messages": messages, "signals": signals, "findings": findings,
        "method": "Messages and signals are matched by name. Findings are matched by (type, message, signal) "
                  "and counted per log. The comparison is descriptive and does not state causes.",
    }
