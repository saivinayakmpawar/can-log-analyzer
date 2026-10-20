import csv
import io
from datetime import datetime, timezone

import pytest

from app.analyzer import analyze
from app.compare import compare_results
from app.reports import csv_safe, findings_csv, report_html, report_pdf
from tests.conftest import SAMPLE

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
RULES = (SAMPLE / "ev_advanced.rules.json").read_bytes()


@pytest.fixture(scope="module")
def adv():
    return analyze(SAMPLE / "ev_advanced.dbc", SAMPLE / "ev_advanced.asc", rules=RULES, now=FIXED)


@pytest.fixture(scope="module")
def clean():
    return analyze(SAMPLE / "ev_advanced.dbc", SAMPLE / "ev_advanced_clean.asc", rules=RULES, now=FIXED)


def sig(r):
    return sorted((a["type"], a["message"], a.get("signal")) for a in r["anomalies"])


def test_advanced_sample_contains_exactly_the_injected_faults(adv):
    assert sig(adv) == sorted([
        ("gap", "BMS_Pack", None), ("checksum_error", "Motor_Cmd", "MC_Checksum"),
        ("out_of_range", "BMS_Pack", "SOC"), ("out_of_range", "Charger_Status", "ChargerCurrent"),
        ("decode_error", "VCU_Status", None), ("counter_error", "Motor_Cmd", "MC_Counter"),
        ("out_of_range", "BMS_CellData", "CellV_A"), ("unknown_id", "0x6A0", None)])


def test_clean_sample_has_no_findings(clean):
    assert clean["anomalies"] == []


def test_classification_separates_rule_violations_from_observations(adv):
    cls = {a["type"]: a["classification"] for a in adv["anomalies"]}
    assert cls["out_of_range"] == cls["counter_error"] == cls["checksum_error"] == "confirmed_violation"
    assert cls["gap"] == cls["unknown_id"] == cls["decode_error"] == "observed_anomaly"


def test_every_finding_has_method_and_evidence(adv):
    for a in adv["anomalies"]:
        assert a["method"] and a["evidence"], a["type"]


def test_extended_charger_fault_is_attributed_to_the_29bit_message(adv):
    f = next(a for a in adv["anomalies"] if a.get("signal") == "ChargerCurrent")
    assert f["message"] == "Charger_Status" and f["worst"] == 45
    assert not [a for a in adv["anomalies"] if a["message"] == "VCU_Status" and a["type"] == "out_of_range"]


def test_analysis_is_reproducible(adv):
    again = analyze(SAMPLE / "ev_advanced.dbc", SAMPLE / "ev_advanced.asc", rules=RULES, now=FIXED)
    assert again == adv


def test_demo_log_is_chronological():
    """Regression: the original generator wrote the unknown-ID frame 3 ms ahead of the next frames."""
    r = analyze(SAMPLE / "ev_demo.dbc", SAMPLE / "ev_demo.asc")
    assert r["summary"]["timestamp_regressions"] == 0 and r["summary"]["anomalies"] == 4


def test_html_report_is_deterministic_and_contains_required_sections(adv):
    html = report_html(adv)
    assert html == report_html(adv)
    for needle in ("2026-01-02T03:04:05", "CAN Log Analyzer v", adv["meta"]["dbc"]["sha256"], "Possible causes (hypotheses, not confirmed)",
                   "Limitations and assumptions", "Estimated bus load", "<svg", "kbit/s", "max stuffing"):
        assert needle in html
    assert "confirmed rule violations" in html


def test_html_report_escapes_untrusted_names(adv):
    evil = dict(adv, meta={**adv["meta"], "log": {**adv["meta"]["log"], "name": "<script>alert(1)</script>.asc"}})
    html = report_html(evil)
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_pdf_report_is_deterministic(adv):
    a, b = report_pdf(adv), report_pdf(adv)
    assert a.startswith(b"%PDF-") and a == b and len(a) > 5000


def test_csv_has_stable_columns_and_neutralises_formulas(adv):
    rows = list(csv.reader(io.StringIO(findings_csv(adv))))
    assert rows[0][:5] == ["severity", "type", "message", "time_s", "detail"] and len(rows) == 9
    assert csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)" and csv_safe("+1") == "'+1" and csv_safe("ok") == "ok"
    evil = dict(adv, anomalies=[dict(adv["anomalies"][0], detail="=cmd|' /C calc'!A0")])
    assert list(csv.reader(io.StringIO(findings_csv(evil))))[1][4].startswith("'=")


def test_compare_reports_differences_without_causes(adv, clean):
    c = compare_results(adv, clean)
    assert all(f["status"] == "only_in_a" for f in c["findings"]) and len(c["findings"]) == 8
    assert not c["notes"]
    soc = next(s for s in c["signals"] if s["name"] == "BMS_Pack.SOC")
    assert soc["max_a"] == 105 and soc["max_b"] < 100
    bms = next(m for m in c["messages"] if m["name"] == "BMS_Pack")
    assert bms["count_a"] < bms["count_b"]
    assert "does not state causes" in c["method"]


def test_compare_flags_different_dbc(adv):
    other = analyze(SAMPLE / "ev_demo.dbc", SAMPLE / "ev_demo.asc", now=FIXED)
    assert any("different DBC" in n for n in compare_results(adv, other)["notes"])


def test_signal_statistics_and_trend_are_exposed(clean):
    v = clean["signal_stats"]["Charger_Status.ChargerVoltage"]
    assert v["slope_per_s"] == pytest.approx(0.02, abs=0.002)
