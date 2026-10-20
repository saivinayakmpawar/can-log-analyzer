"""CSV, HTML and PDF engineering reports.

Reports are rendered purely from a stored analysis result. They contain the
analysis timestamp (not the time of download) and no random IDs, so the same
analysis always produces the same report.
"""
from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

FINDING_COLUMNS = ["severity", "type", "message", "time_s", "detail", "classification", "signal", "end_time_s",
                   "finding_id", "method", "evidence_json"]
SEV_COLOR = {"high": "#b3261e", "medium": "#a45c00", "low": "#586674"}
CLASS_LABEL = {"confirmed_violation": "Confirmed rule violation", "observed_anomaly": "Observed anomaly"}
MAX_PLOTS = 8


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection (values come from DBC/log content)."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def findings_csv(result: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(FINDING_COLUMNS)
    for a in result["anomalies"]:
        w.writerow([csv_safe(x) for x in (
            a["severity"], a["type"], a["message"], f"{a['time']:.3f}", a["detail"], a.get("classification", ""),
            a.get("signal") or "", f"{a.get('end_time', a['time']):.3f}", a.get("id", ""), a.get("method", ""),
            json.dumps(a.get("evidence", {}), sort_keys=True))])
    return buf.getvalue()


def messages_csv(result: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    cols = ["id", "extended", "name", "senders", "count", "expected_ms", "expected_source", "avg_ms", "jitter_ms",
            "gaps", "max_gap_ms"]
    w.writerow(cols)
    for m in result["messages"]:
        w.writerow([csv_safe(", ".join(m[c]) if c == "senders" else m.get(c)) for c in cols])
    return buf.getvalue()


# ---------------------------------------------------------------- plotting geometry

def _nice_ticks(lo: float, hi: float, n: int = 5) -> list[float]:
    if hi == lo:
        return [lo]
    step = (hi - lo) / (n - 1)
    return [lo + i * step for i in range(n)]


def plot_geometry(points: list[list[float]], w: int, h: int, hlines: list[float] | None = None,
                  pad: tuple[int, int, int, int] = (52, 12, 12, 30)) -> dict[str, Any]:
    left, right, top, bottom = pad
    xs, ys = [p[0] for p in points], [p[1] for p in points]
    ymin, ymax = min(ys + (hlines or [])), max(ys + (hlines or []))
    if ymin == ymax:
        ymin, ymax = ymin - 1, ymax + 1
    margin = (ymax - ymin) * 0.05
    ymin, ymax = ymin - margin, ymax + margin
    xmin, xmax = min(xs), max(xs)
    if xmin == xmax:
        xmax = xmin + 1

    def sx(x: float) -> float:
        return left + (x - xmin) / (xmax - xmin) * (w - left - right)

    def sy(y: float) -> float:
        return top + (1 - (y - ymin) / (ymax - ymin)) * (h - top - bottom)

    return {"sx": sx, "sy": sy, "xmin": xmin, "xmax": xmax, "ymin": ymin, "ymax": ymax,
            "box": (left, top, w - right, h - bottom)}


def line_svg(points: list[list[float]], title: str, ylabel: str, hlines: list[float] | None = None,
             w: int = 720, h: int = 220, step: bool = True) -> str:
    if not points:
        return ""
    g = plot_geometry(points, w, h, hlines)
    sx, sy = g["sx"], g["sy"]
    left, top, right, bottom = g["box"]
    path: list[str] = []
    for i, (x, y) in enumerate(points):
        if i == 0:
            path.append(f"M{sx(x):.1f},{sy(y):.1f}")
        elif step:
            path.append(f"H{sx(x):.1f}V{sy(y):.1f}")
        else:
            path.append(f"L{sx(x):.1f},{sy(y):.1f}")
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" '
             f'aria-label="{html.escape(title)}" class="plot">']
    for tv in _nice_ticks(g["ymin"], g["ymax"]):
        parts.append(f'<line x1="{left}" x2="{right}" y1="{sy(tv):.1f}" y2="{sy(tv):.1f}" stroke="#e1e6eb"/>'
                     f'<text x="{left - 6}" y="{sy(tv) + 4:.1f}" text-anchor="end" font-size="10" fill="#586674">{tv:.4g}</text>')
    for tv in _nice_ticks(g["xmin"], g["xmax"]):
        parts.append(f'<text x="{sx(tv):.1f}" y="{bottom + 14}" text-anchor="middle" font-size="10" fill="#586674">{tv:.4g}</text>')
    for hv in hlines or []:
        parts.append(f'<line x1="{left}" x2="{right}" y1="{sy(hv):.1f}" y2="{sy(hv):.1f}" stroke="#b3261e" '
                     f'stroke-dasharray="5 4"/>')
    parts.append(f'<path d="{"".join(path)}" fill="none" stroke="#1f5fbf" stroke-width="1.4"/>')
    parts.append(f'<rect x="{left}" y="{top}" width="{right - left}" height="{bottom - top}" fill="none" stroke="#c4ccd4"/>')
    parts.append(f'<text x="{(left + right) / 2}" y="{h - 3}" text-anchor="middle" font-size="10" fill="#586674">Time (s)</text>')
    parts.append(f'<text x="12" y="{(top + bottom) / 2}" font-size="10" fill="#586674" '
                 f'transform="rotate(-90 12 {(top + bottom) / 2})" text-anchor="middle">{html.escape(ylabel)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def plot_signals(result: dict[str, Any]) -> list[str]:
    """Signals worth plotting: those named by findings first, then the rest alphabetically."""
    flagged = [f"{a['message']}.{a['signal']}" for a in result["anomalies"] if a.get("signal")]
    ordered = list(dict.fromkeys([s for s in flagged if s in result["signals"]] + sorted(result["signals"])))
    return ordered[:MAX_PLOTS]


# ---------------------------------------------------------------- HTML

def _e(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def _evidence(ev: dict[str, Any]) -> str:
    return ", ".join(f"{_e(k)}={_e(json.dumps(v) if isinstance(v, (list, dict)) else v)}" for k, v in ev.items())


def report_html(result: dict[str, Any]) -> str:
    meta, s, bl = result["meta"], result["summary"], result["bus_load"]
    sev = {k: sum(1 for a in result["anomalies"] if a["severity"] == k) for k in ("high", "medium", "low")}
    confirmed = sum(1 for a in result["anomalies"] if a.get("classification") == "confirmed_violation")
    rows = []
    for a in result["anomalies"]:
        causes = "; ".join(_e(c) for c in a.get("possible_causes", []))
        rows.append(
            f'<tr><td><b style="color:{SEV_COLOR[a["severity"]]}">{_e(a["severity"])}</b></td>'
            f'<td>{_e(a.get("id"))}</td><td>{_e(a["type"].replace("_", " "))}<br><small>{_e(CLASS_LABEL.get(a.get("classification", ""), ""))}</small></td>'
            f'<td>{_e(a["message"])}{"." + _e(a["signal"]) if a.get("signal") else ""}</td>'
            f'<td class="n">{a["time"]:.3f}</td>'
            f'<td>{_e(a["detail"])}<br><small><b>Evidence:</b> {_evidence(a.get("evidence", {}))}</small>'
            f'<br><small><b>Method:</b> {_e(a.get("method"))}</small>'
            f'<br><small><b>Possible causes (hypotheses, not confirmed):</b> {causes}</small></td></tr>')
    msg_rows = "".join(
        f'<tr><td>{_e(m["id"])}{" (ext)" if m["extended"] else ""}</td><td>{_e(m["name"])}</td><td class="n">{m["count"]}</td>'
        f'<td class="n">{_e(m["expected_ms"] if m["expected_ms"] is not None else "-")}</td>'
        f'<td>{_e(m.get("expected_source") or "-")}</td>'
        f'<td class="n">{_e(m["avg_ms"] if m["avg_ms"] is not None else "-")}</td>'
        f'<td class="n">{m["jitter_ms"]}</td><td class="n">{m["gaps"]}</td></tr>' for m in result["messages"])
    plots = []
    for name in plot_signals(result):
        sig = result["signals"][name]
        plots.append(f"<figure><figcaption>{_e(name)} ({_e(sig['unit'] or 'no unit')})"
                     f"{' - reduced to min/max envelope' if sig.get('downsampled') else ''}</figcaption>"
                     + line_svg(sig["points"], name, sig["unit"], [v for v in (sig["min"], sig["max"]) if v is not None])
                     + "</figure>")
    bus_pts = [[p[0], p[2]] for p in bl["points"]]
    bus_svg = line_svg(bus_pts, "Estimated bus load", "% of capacity", step=False) if len(bus_pts) > 1 else ""
    trunc = meta.get("truncated_findings") or {}
    warn = ("<p><b>Note:</b> some findings were capped to protect resources: "
            + _e(", ".join(f"{k} (+{v} more)" for k, v in trunc.items())) + ".</p>") if trunc else ""
    dbc, log = meta["dbc"], meta["log"]
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>CAN analysis report - {_e(log['name'])}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#16212b;max-width:980px;margin:28px auto;padding:0 18px}}
h1{{font-size:24px;margin:0}} h2{{font-size:17px;margin:30px 0 8px;border-bottom:1px solid #d5dce3;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border-bottom:1px solid #e1e6eb;padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:#586674;font-weight:600}} td.n{{text-align:right;font-variant-numeric:tabular-nums}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}}
.grid div{{border:1px solid #d5dce3;border-radius:4px;padding:8px 10px}} .grid b{{display:block;font-size:20px}}
.plot{{width:100%;height:auto}} figure{{margin:12px 0}} figcaption{{font-weight:600;font-size:13px}}
small{{color:#44505c}} code{{font:12px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}}
pre{{background:#f3f5f7;padding:10px;overflow:auto;font-size:12px}} .muted{{color:#586674}}
@media print{{body{{margin:0}} h2{{break-after:avoid}} tr,figure{{break-inside:avoid}}}}
</style></head><body>
<h1>CAN log analysis report</h1>
<p class="muted">Analysis date: {_e(meta['analyzed_at'])} &middot; CAN Log Analyzer v{_e(meta['software_version'])}</p>

<h2>Inputs</h2>
<table><tr><th>File</th><th>Name</th><th>Size (bytes)</th><th>SHA-256</th></tr>
<tr><td>DBC</td><td>{_e(dbc['name'])}</td><td class="n">{dbc['size_bytes']}</td><td><code>{_e(dbc['sha256'])}</code></td></tr>
<tr><td>CAN log ({_e(log['format'])})</td><td>{_e(log['name'])}</td><td class="n">{log['size_bytes']}</td><td><code>{_e(log['sha256'])}</code></td></tr></table>
<p>DBC: {dbc['messages']} messages, {dbc['signals']} signals, nodes: {_e(', '.join(dbc['nodes']) or 'none')}{(' &middot; version ' + _e(dbc['version'])) if dbc.get('version') else ''}.
{('<br><b>DBC warnings:</b> ' + _e('; '.join(dbc['warnings']))) if dbc.get('warnings') else ''}</p>

<h2>Analysis configuration</h2>
<p>Assumed bit rate: <b>{meta['config']['bitrate'] // 1000} kbit/s</b> (supplied by the user, not verified).</p>
<pre>{_e(json.dumps(meta['config']['rules'], indent=2, sort_keys=True))}</pre>

<h2>Summary</h2>
<div class="grid">
<div><b>{s['frames']:,}</b>data frames</div><div><b>{s['duration_s']} s</b>duration</div>
<div><b>{s['unique_ids']}</b>unique CAN IDs</div><div><b>{s['unknown_ids']}</b>unknown IDs</div>
<div><b>{bl['avg_pct']:.2f}%</b>est. avg bus load (nominal)</div><div><b>{bl['peak_pct']:.2f}%</b>est. peak (nominal)</div>
<div><b>{bl['peak_pct_worst_case']:.2f}%</b>peak upper bound (max stuffing)</div>
<div><b>{s['remote_frames']} / {s['error_frames']} / {s['fd_frames']}</b>remote / error / FD frames</div></div>
<p>Findings: <b style="color:{SEV_COLOR['high']}">{sev['high']} high</b>, <b style="color:{SEV_COLOR['medium']}">{sev['medium']} medium</b>,
<b>{sev['low']} low</b> - of which {confirmed} confirmed rule violations and {len(result['anomalies']) - confirmed} observed anomalies.</p>{warn}

<h2>Findings</h2>
{'<table><tr><th>Severity</th><th>ID</th><th>Type</th><th>Message / signal</th><th>Start (s)</th><th>Details</th></tr>' + ''.join(rows) + '</table>' if rows else '<p>No findings.</p>'}

<h2>Message timing</h2>
<table><tr><th>ID</th><th>Name</th><th>Frames</th><th>Expected (ms)</th><th>Expected from</th><th>Mean (ms)</th><th>Jitter (ms)</th><th>Gaps</th></tr>{msg_rows}</table>
<p class="muted">Mean and jitter exclude gaps so they describe normal operation.</p>

<h2>Signal plots</h2>
{''.join(plots) or '<p>No decoded signals.</p>'}
<h2>Estimated bus load</h2>
{bus_svg}
<p class="muted">{_e(' '.join(bl['assumptions']))}</p>

<h2>Limitations and assumptions</h2>
<ul>{''.join('<li>' + _e(x) + '</li>' for x in result['limitations'])}</ul>
<p class="muted">Reproducibility: the same DBC, log and configuration (hashes above) give the same findings with this software version.</p>
</body></html>
"""


# ---------------------------------------------------------------- PDF

def report_pdf(result: dict[str, Any]) -> bytes:
    from reportlab.graphics.shapes import Drawing, Line, PolyLine, String
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    meta, s, bl = result["meta"], result["summary"], result["bus_load"]
    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=7.5, leading=9.5)
    body = ss["BodyText"].clone("body9", fontSize=9, leading=12)
    h2 = ss["Heading2"].clone("h2x", fontSize=12, spaceBefore=12, spaceAfter=4)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                            bottomMargin=14 * mm, title="CAN log analysis report", author="CAN Log Analyzer",
                            invariant=1)
    width = A4[0] - 30 * mm

    def P(text: Any, style: Any = body) -> Paragraph:
        return Paragraph(html.escape(str(text)).replace("\n", "<br/>"), style)

    def table(data: list[list[Any]], widths: list[float], header: bool = True) -> Table:
        t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
        style = [("FONTSIZE", (0, 0), (-1, -1), 7.5), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5dce3"))]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f4")))
        t.setStyle(TableStyle(style))
        return t

    def chart(points: list[list[float]], title: str, hlines: list[float] | None = None, step: bool = True) -> Any:
        w, h = width, 120
        d = Drawing(w, h + 14)
        g = plot_geometry(points, int(w), h, hlines, pad=(40, 8, 6, 18))
        sx, sy = g["sx"], g["sy"]
        left, _top, right, _bottom = g["box"]
        # reportlab's y axis points up, so flip.
        def fy(v: float) -> float:
            return h - sy(v) + 14
        d.add(String(left, h + 3, title, fontSize=8))
        for tv in _nice_ticks(g["ymin"], g["ymax"], 4):
            d.add(Line(left, fy(tv), right, fy(tv), strokeColor=colors.HexColor("#e1e6eb"), strokeWidth=0.4))
            d.add(String(left - 3, fy(tv) - 2, f"{tv:.4g}", fontSize=6, textAnchor="end"))
        for tv in _nice_ticks(g["xmin"], g["xmax"], 5):
            d.add(String(sx(tv), 4, f"{tv:.4g}", fontSize=6, textAnchor="middle"))
        for hv in hlines or []:
            d.add(Line(left, fy(hv), right, fy(hv), strokeColor=colors.HexColor("#b3261e"), strokeDashArray=[3, 2], strokeWidth=0.6))
        flat: list[float] = []
        prev_y: float | None = None
        for x, y in points:
            if step and prev_y is not None:
                flat += [sx(x), fy(prev_y)]
            flat += [sx(x), fy(y)]
            prev_y = y
        if len(flat) >= 4:
            d.add(PolyLine(flat, strokeColor=colors.HexColor("#1f5fbf"), strokeWidth=0.8))
        return d

    story: list[Any] = [P("CAN log analysis report", ss["Title"]),
                        P(f"Analysis date: {meta['analyzed_at']} - CAN Log Analyzer v{meta['software_version']}"),
                        P("Inputs", h2)]
    story.append(table([["File", "Name", "Size (bytes)", "SHA-256"],
                        ["DBC", P(meta["dbc"]["name"], small), meta["dbc"]["size_bytes"], P(meta["dbc"]["sha256"], small)],
                        [f"Log ({meta['log']['format']})", P(meta["log"]["name"], small), meta["log"]["size_bytes"],
                         P(meta["log"]["sha256"], small)]], [60, 120, 55, width - 235]))
    story.append(P(f"DBC: {meta['dbc']['messages']} messages, {meta['dbc']['signals']} signals, nodes: "
                   f"{', '.join(meta['dbc']['nodes']) or 'none'}. Assumed bit rate: {meta['config']['bitrate'] // 1000} kbit/s "
                   "(user-supplied, not verified).", body))
    story.append(P("Summary", h2))
    sev = {k: sum(1 for a in result["anomalies"] if a["severity"] == k) for k in ("high", "medium", "low")}
    story.append(table([
        ["Data frames", f"{s['frames']:,}", "Duration", f"{s['duration_s']} s"],
        ["Unique CAN IDs", s["unique_ids"], "Unknown IDs", s["unknown_ids"]],
        ["Est. avg bus load (nominal)", f"{bl['avg_pct']:.2f}%", "Est. peak (nominal / max-stuffing bound)",
         f"{bl['peak_pct']:.2f}% / {bl['peak_pct_worst_case']:.2f}%"],
        ["Findings high / medium / low", f"{sev['high']} / {sev['medium']} / {sev['low']}", "Remote / error / FD frames",
         f"{s['remote_frames']} / {s['error_frames']} / {s['fd_frames']}"]], [95, 70, 130, width - 295], header=False))
    story.append(P("Findings", h2))
    if result["anomalies"]:
        data = [["Sev.", "ID", "Type", "Message / signal", "t (s)", "Details"]]
        for a in result["anomalies"]:
            who = a["message"] + ("." + a["signal"] if a.get("signal") else "")
            detail = (f"{a['detail']}\nClassification: {CLASS_LABEL.get(a.get('classification', ''), '')}. "
                      f"Evidence: {_evidence_plain(a.get('evidence', {}))}\nPossible causes (hypotheses, not confirmed): "
                      f"{'; '.join(a.get('possible_causes', []))}")
            data.append([a["severity"], a.get("id", ""), P(a["type"].replace("_", " "), small), P(who, small),
                         f"{a['time']:.2f}", P(detail, small)])
        story.append(table(data, [28, 32, 55, 70, 30, width - 215]))
    else:
        story.append(P("No findings."))
    story.append(P("Message timing", h2))
    data = [["ID", "Name", "Frames", "Expected ms", "From", "Mean ms", "Jitter ms", "Gaps"]]
    for m in result["messages"]:
        data.append([m["id"] + (" ext" if m["extended"] else ""), P(m["name"], small), m["count"],
                     m["expected_ms"] if m["expected_ms"] is not None else "-", m.get("expected_source") or "-",
                     m["avg_ms"] if m["avg_ms"] is not None else "-", m["jitter_ms"], m["gaps"]])
    story.append(table(data, [45, 110, 40, 50, 60, 45, 45, width - 395]))
    story.append(P("Signal plots", h2))
    for name in plot_signals(result):
        sig = result["signals"][name]
        title = f"{name} ({sig['unit'] or 'no unit'})" + (" - min/max envelope" if sig.get("downsampled") else "")
        story.append(chart(sig["points"], title, [v for v in (sig["min"], sig["max"]) if v is not None]))
        story.append(Spacer(1, 4))
    if len(bl["points"]) > 1:
        story.append(chart([[p[0], p[2]] for p in bl["points"]], "Estimated bus load (% of capacity, nominal)", step=False))
    story.append(P("Limitations and assumptions", h2))
    for x in [*result["limitations"], *bl["assumptions"]]:
        story.append(P("- " + x, small))
    doc.build(story)
    return buf.getvalue()


def _evidence_plain(ev: dict[str, Any]) -> str:
    return ", ".join(f"{k}={json.dumps(v) if isinstance(v, (list, dict)) else v}" for k, v in ev.items())
