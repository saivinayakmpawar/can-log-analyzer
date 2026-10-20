from pathlib import Path

import can
import cantools
import pytest
from fastapi.testclient import TestClient

from app.analyzer import analyze, inspect_dbc
from app.main import app

SAMPLE = Path(__file__).resolve().parent.parent / "app" / "sample"
DBC, LOG = SAMPLE / "ev_demo.dbc", SAMPLE / "ev_demo.asc"


@pytest.fixture(scope="module")
def result():
    return analyze(DBC, LOG)


def find(result, type_, **kw):
    return [a for a in result["anomalies"]
            if a["type"] == type_ and all(a.get(k) == v for k, v in kw.items())]


def test_summary(result):
    assert result["summary"]["messages_decoded"] == 3
    assert result["summary"]["duration_s"] == pytest.approx(29.95, abs=0.1)


def test_bms_dropout_detected(result):
    gap = find(result, "gap", message="BMS_Pack")
    assert len(gap) == 1
    assert gap[0]["time"] == pytest.approx(11.9, abs=0.15)
    assert "frames missing" in gap[0]["detail"]


def test_soc_out_of_range(result):
    ev = find(result, "out_of_range", signal="SOC")
    assert len(ev) == 1 and ev[0]["worst"] == 105 and ev[0]["frames"] == 3


def test_overtemp(result):
    ev = find(result, "out_of_range", signal="MaxCellTemp")
    assert len(ev) == 1 and ev[0]["worst"] == 83


def test_unknown_id(result):
    ev = find(result, "unknown_id")
    assert len(ev) == 1 and ev[0]["message"] == "0x7FF"


def test_clean_messages_have_no_gaps(result):
    gaps = {m["name"]: m["gaps"] for m in result["messages"]}
    assert gaps["VCU_Status"] == 0 and gaps["Motor_Status"] == 0


def test_signals_downsampled(result):
    assert all(len(s["points"]) <= 1500 for s in result["signals"].values())


def test_api_sample_and_upload():
    c = TestClient(app)
    assert c.get("/api/sample").json()["summary"]["anomalies"] == 4
    r = c.post("/api/analyze", files={"dbc": ("a.dbc", DBC.read_bytes()),
                                      "log": ("a.asc", LOG.read_bytes())})
    assert r.status_code == 200 and r.json()["summary"]["anomalies"] == 4


def test_api_rejects_bad_extension():
    c = TestClient(app)
    r = c.post("/api/analyze", files={"dbc": ("a.dbc", DBC.read_bytes()), "log": ("a.txt", b"x")})
    assert r.status_code == 400


def test_jitter_ignores_dropout(result):
    bms = next(m for m in result["messages"] if m["name"] == "BMS_Pack")
    assert bms["avg_ms"] == pytest.approx(100, abs=1)
    assert bms["jitter_ms"] < 5


def test_message_that_stops_and_message_never_seen(tmp_path):
    db = cantools.database.load_file(DBC)
    log = tmp_path / "short.asc"
    vcu, motor = db.get_message_by_name("VCU_Status"), db.get_message_by_name("Motor_Status")
    with can.ASCWriter(log) as w:
        for i in range(100):  # 10 s of VCU, Motor stops at 5 s, BMS never sent
            t = 1000 + i * 0.1
            w.on_message_received(can.Message(timestamp=t, arbitration_id=vcu.frame_id,
                data=vcu.encode(dict(VehicleSpeed=10, DriveMode=1, Handbrake=0)), is_extended_id=False))
            if i < 50:
                w.on_message_received(can.Message(timestamp=t, arbitration_id=motor.frame_id,
                    data=motor.encode(dict(MotorRPM=100, MotorTorque=5)), is_extended_id=False))
    r = analyze(DBC, log)
    stopped = [a for a in r["anomalies"] if a["type"] == "gap" and a["message"] == "Motor_Status"]
    assert len(stopped) == 1 and "never resumed" in stopped[0]["detail"]
    missing = find(r, "missing_message", message="BMS_Pack")
    assert len(missing) == 1 and missing[0]["severity"] == "high"


def test_bus_load(result):
    bl = result["bus_load"]
    assert bl["bitrate"] == 500000
    assert bl["avg_pct"] == pytest.approx(0.88, abs=0.15)
    assert bl["peak_pct"] < 2
    assert len(bl["points"]) == 30
    assert sum(p[1] for p in bl["points"]) == result["summary"]["frames"]


def test_bus_load_scales_with_bitrate():
    half = analyze(DBC, LOG, bitrate=250000)["bus_load"]["avg_pct"]
    assert half == pytest.approx(1.76, abs=0.3)


def test_inspect_dbc():
    r = inspect_dbc(DBC)
    assert r["summary"]["messages"] == 3 and r["summary"]["signals"] == 9
    bms = next(m for m in r["messages"] if m["name"] == "BMS_Pack")
    assert bms["cycle_ms"] == 100 and len(bms["signals"]) == 4
    mode = next(s for m in r["messages"] for s in m["signals"] if s["name"] == "DriveMode")
    assert mode["choices"]["1"] == "ECO"


def test_api_inspect_and_bitrate_validation():
    c = TestClient(app)
    r = c.post("/api/inspect", files={"dbc": ("a.dbc", DBC.read_bytes())})
    assert r.status_code == 200 and r.json()["summary"]["messages"] == 3
    r = c.post("/api/analyze", data={"bitrate": "1234"},
               files={"dbc": ("a.dbc", DBC.read_bytes()), "log": ("a.asc", LOG.read_bytes())})
    assert r.status_code == 400
