import pytest

from app.analyzer import analyze
from tests.conftest import DBC_CYCLIC


def kinds(r):
    return [a["type"] for a in r["anomalies"]]


def cyc(t, speed=50, cnt=0):
    return (t, 100, False, bytes([speed, cnt, 0, 0, 0, 0, 0, 0]))


@pytest.fixture
def dbc(make):
    return make("c.dbc", DBC_CYCLIC)


def test_gap_has_evidence_and_method(dbc, asc):
    rows = [cyc(i * 0.01) for i in range(50)] + [cyc(1.0 + i * 0.01) for i in range(50)]
    r = analyze(dbc, asc(rows))
    gap = next(a for a in r["anomalies"] if a["type"] == "gap")
    assert gap["classification"] == "observed_anomaly"
    assert gap["evidence"]["expected_source"] == "dbc"
    assert gap["evidence"]["gap_s"] == pytest.approx(0.51, abs=0.001)
    assert gap["evidence"]["estimated_missing_frames"] == 50
    assert "gap_factor" in gap["method"] and gap["possible_causes"]


def test_message_defined_but_never_seen_is_reported(dbc, asc):
    r = analyze(dbc, asc([cyc(i * 0.01) for i in range(20)]))
    miss = [a for a in r["anomalies"] if a["type"] == "missing_message"]
    assert [m["message"] for m in miss] == ["Evt"] and miss[0]["severity"] == "low"


def test_rule_can_waive_or_require_missing_message(dbc, asc):
    rows = [cyc(i * 0.01) for i in range(20)]
    waived = analyze(dbc, asc(rows), rules={"messages": {"Evt": {"required": False}}})
    assert "missing_message" not in kinds(waived)
    required = analyze(dbc, asc(rows), rules={"messages": {"Evt": {"required": True}}})
    assert next(a for a in required["anomalies"] if a["type"] == "missing_message")["severity"] == "high"


def test_empty_log_is_one_clear_finding_not_noise(dbc, make):
    empty = make("e.asc", "date Sat Oct 17 10:11:25.463 2026\nbase hex  timestamps absolute\n")
    r = analyze(dbc, empty)
    assert kinds(r) == ["empty_log"] and r["summary"]["frames"] == 0


def test_regression_backwards_timestamp_is_reported(dbc, asc):
    ts = [0, 0.01, 0.02, 0.03, 0.015, 0.04, 0.05]
    r = analyze(dbc, asc([cyc(t) for t in ts]))
    reg = [a for a in r["anomalies"] if a["type"] == "timestamp_regression"]
    assert len(reg) == 1 and reg[0]["evidence"]["previous_t"] > reg[0]["evidence"]["t"]
    assert "gap" not in kinds(r)  # a negative interval is not a gap


def test_duplicate_timestamps_are_counted_not_flagged(dbc, asc):
    rows = [cyc(0.0), cyc(0.0), cyc(0.01), cyc(0.02)]
    r = analyze(dbc, asc(rows))
    assert r["summary"]["duplicate_timestamps_same_message"] == 1
    assert "gap" not in kinds(r)


def test_message_without_cycle_uses_log_median_and_says_so(dbc, asc):
    rows = [cyc(i * 0.01) for i in range(300)]
    rows += [(i * 0.1, 101, False, bytes(8)) for i in range(10)] + [(5.0, 101, False, bytes(8))]
    r = analyze(dbc, asc(rows))
    evt = next(m for m in r["messages"] if m["name"] == "Evt")
    assert evt["expected_source"] == "log_median_estimate" and evt["expected_ms"] == pytest.approx(100)
    gap = next(a for a in r["anomalies"] if a["type"] == "gap" and a["message"] == "Evt")
    assert "inferred from the log median" in gap["detail"]


def test_frequency_deviation_against_dbc_cycle(dbc, asc):
    rows = [cyc(i * 0.02) for i in range(100)]  # 20 ms instead of the declared 10 ms
    r = analyze(dbc, asc(rows))
    dev = next(a for a in r["anomalies"] if a["type"] == "frequency_deviation")
    assert dev["evidence"]["deviation_pct"] == pytest.approx(100, abs=1)


def test_rule_cycle_overrides_dbc_cycle(dbc, asc):
    rows = [cyc(i * 0.02) for i in range(100)]
    r = analyze(dbc, asc(rows), rules={"messages": {"Cyc": {"cycle_ms": 20}}})
    assert "frequency_deviation" not in kinds(r)
    assert next(m for m in r["messages"] if m["name"] == "Cyc")["expected_source"] == "rule"


def test_stopped_message_never_resumes(dbc, asc):
    rows = [cyc(i * 0.01) for i in range(20)] + [(i * 0.01, 101, False, bytes(8)) for i in range(100)]
    r = analyze(dbc, asc(rows))
    stop = next(a for a in r["anomalies"] if a["type"] == "gap" and a["message"] == "Cyc")
    assert stop["evidence"]["stopped_for_rest_of_log"] is True
