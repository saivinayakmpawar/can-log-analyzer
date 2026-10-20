import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import DBC_OVERLAP, SAMPLE

DBC = (SAMPLE / "ev_demo.dbc").read_bytes()
LOG = (SAMPLE / "ev_demo.asc").read_bytes()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


def upload(client, dbc=DBC, log=LOG, log_name="a.asc", dbc_name="a.dbc", **data):
    return client.post("/api/analyze", data=data, files={"dbc": (dbc_name, dbc), "log": (log_name, log)})


@pytest.fixture
def analysis(client):
    r = upload(client)
    assert r.status_code == 200
    return r.json()


def test_analyze_returns_backward_compatible_shape_plus_new_fields(analysis):
    for key in ("summary", "anomalies", "messages", "bus_load", "signals"):
        assert key in analysis
    assert analysis["summary"]["anomalies"] == 4 and analysis["analysis_id"]
    first = analysis["anomalies"][0]
    for key in ("type", "severity", "time", "message", "detail", "classification", "method", "evidence", "possible_causes"):
        assert key in first


def test_validation_errors(client):
    assert upload(client, log_name="a.txt").status_code == 400
    assert upload(client, dbc_name="a.txt").status_code == 400
    assert upload(client, bitrate="1234").status_code == 400
    assert upload(client, log=b"").status_code == 400
    assert client.post("/api/analyze", files={"dbc": ("a.dbc", DBC)}).status_code == 422


def test_malformed_files_return_422_without_internals(client):
    for r in (upload(client, dbc=b"BO_ nonsense ((("), upload(client, log=bytes(range(256)) * 20)):
        assert r.status_code == 422
        text = r.text
        assert "Traceback" not in text and "/home" not in text and "site-packages" not in text


def test_oversized_upload_is_rejected_while_streaming(client, monkeypatch):
    monkeypatch.setenv("CAN_ANALYZER_MAX_LOG_MB", "0.01")  # ~10 KB
    r = upload(client, log=b"x" * 200_000)
    assert r.status_code == 413


def test_per_file_limit_is_enforced_even_if_total_body_fits(client, monkeypatch):
    monkeypatch.setenv("CAN_ANALYZER_MAX_DBC_MB", "0.001")
    r = upload(client, dbc=DBC + b" " * 5000)
    assert r.status_code == 413 and "DBC" in r.json()["detail"]


def test_declared_content_length_over_limit_rejected_early(client, monkeypatch):
    monkeypatch.setenv("CAN_ANALYZER_MAX_LOG_MB", "0.01")
    monkeypatch.setenv("CAN_ANALYZER_MAX_DBC_MB", "0.01")
    r = client.post("/api/analyze", content=b"x" * 3_000_000,
                    headers={"content-type": "multipart/form-data; boundary=x"})
    assert r.status_code == 413


def test_client_filename_is_never_used_as_a_path(client, analysis):
    r = upload(client, log_name="../../../../tmp/evil.asc", dbc_name="..\\..\\x.dbc")
    assert r.status_code == 200
    assert r.json()["meta"]["log"]["name"] == "evil.asc"


@pytest.mark.parametrize("bad", ["../etc/passwd", "..%2f..%2fetc", "0" * 32, "g" * 32, "x"])
def test_analysis_ids_are_validated(client, bad):
    for path in ("", "/frames", "/dbc", "/signal?name=A.B", "/report.csv", "/findings/F0001"):
        assert client.get(f"/api/analyses/{bad}{path}").status_code == 404


def test_history_list_get_delete(client, analysis):
    aid = analysis["analysis_id"]
    items = client.get("/api/analyses").json()
    assert items[0]["id"] == aid and items[0]["findings"]["high"] >= 1
    assert client.get(f"/api/analyses/{aid}").json()["summary"]["frames"] == analysis["summary"]["frames"]
    assert client.delete(f"/api/analyses/{aid}").status_code == 200
    assert client.get(f"/api/analyses/{aid}").status_code == 404
    assert client.delete(f"/api/analyses/{aid}").status_code == 404


def test_failed_analysis_leaves_no_files_behind(client, tmp_path):
    upload(client, log=bytes(range(256)) * 20)
    data_dir = tmp_path / "data"
    assert not list(data_dir.iterdir()) if data_dir.exists() else True


def test_frames_endpoint_paginates_filters_and_validates(client, analysis):
    aid = analysis["analysis_id"]
    page = client.get(f"/api/analyses/{aid}/frames?limit=5&offset=10&sort=t&order=desc").json()
    assert page["total"] > 1000 and len(page["frames"]) == 5
    assert page["frames"][0]["t"] >= page["frames"][-1]["t"]
    ext = client.get(f"/api/analyses/{aid}/frames?can_id=7FF").json()
    assert ext["total"] == 5 and ext["frames"][0]["status"] == "unknown"
    bms = client.get(f"/api/analyses/{aid}/frames?q=bms&limit=1").json()["frames"][0]
    assert bms["message"] == "BMS_Pack" and "SOC" in bms["signals"]
    assert client.get(f"/api/analyses/{aid}/frames?limit=100000").status_code == 422
    assert client.get(f"/api/analyses/{aid}/frames?sort=evil").status_code == 422
    assert client.get(f"/api/analyses/{aid}/frames?can_id=zz").status_code == 400


def test_signal_endpoint_zoom_returns_more_detail_than_overview(client, analysis):
    aid = analysis["analysis_id"]
    zoom = client.get(f"/api/analyses/{aid}/signal?name=Motor_Status.MotorRPM&t0=1&t1=2").json()
    assert zoom["samples"] == 21 and zoom["stats"]["count"] == 21
    assert client.get(f"/api/analyses/{aid}/signal?name=Nope.X").status_code == 400


def test_finding_detail_includes_related_frames(client, analysis):
    aid = analysis["analysis_id"]
    soc = next(a for a in analysis["anomalies"] if a.get("signal") == "SOC")
    d = client.get(f"/api/analyses/{aid}/findings/{soc['id']}").json()
    assert d["finding"]["worst"] == 105
    assert d["related_frames"] and all(f["message"] == "BMS_Pack" for f in d["related_frames"])
    assert client.get(f"/api/analyses/{aid}/findings/F9999").status_code == 404


def test_dbc_browser_and_inspect(client, analysis):
    aid = analysis["analysis_id"]
    assert client.get(f"/api/analyses/{aid}/dbc").json()["summary"]["messages"] == 3
    r = client.post("/api/inspect", files={"dbc": ("a.dbc", DBC)})
    assert r.status_code == 200 and r.json()["summary"]["signals"] == 9


def test_rules_upload_and_validation(client):
    rules = json.dumps({"thresholds": [{"signal": "VCU_Status.VehicleSpeed", "max": 30, "severity": "low"}]})
    r = client.post("/api/analyze", files={"dbc": ("a.dbc", DBC), "log": ("a.asc", LOG),
                                           "rules": ("r.json", rules.encode())})
    assert r.status_code == 200
    assert any(a["type"] == "out_of_range" and a["signal"] == "VehicleSpeed" for a in r.json()["anomalies"])
    bad = client.post("/api/analyze", files={"dbc": ("a.dbc", DBC), "log": ("a.asc", LOG),
                                             "rules": ("r.json", b'{"bogus": 1}')})
    assert bad.status_code == 422 and "bogus" in bad.json()["detail"]


def test_samples(client):
    assert client.get("/api/sample").json()["summary"]["anomalies"] == 4
    adv = client.get("/api/sample?name=ev_advanced").json()
    assert adv["summary"]["anomalies"] == 8
    assert client.get("/api/sample?name=nope").status_code == 404


def test_compare_endpoint(client):
    a = client.get("/api/sample?name=ev_advanced").json()["analysis_id"]
    b = client.get("/api/sample?name=ev_advanced_clean").json()["analysis_id"]
    c = client.get(f"/api/compare?a={a}&b={b}").json()
    assert {f["status"] for f in c["findings"]} == {"only_in_a"}
    assert client.get(f"/api/compare?a={a}&b={'0' * 32}").status_code == 404


def test_reports_download(client, analysis):
    aid = analysis["analysis_id"]
    csv = client.get(f"/api/analyses/{aid}/report.csv")
    assert csv.headers["content-type"].startswith("text/csv") and "attachment" in csv.headers["content-disposition"]
    assert client.get(f"/api/analyses/{aid}/report.csv?section=messages").status_code == 200
    assert client.get(f"/api/analyses/{aid}/report.csv?section=x").status_code == 400
    html = client.get(f"/api/analyses/{aid}/report.html")
    assert "CAN log analysis report" in html.text and "default-src 'none'" in html.headers["content-security-policy"]
    pdf = client.get(f"/api/analyses/{aid}/report.pdf")
    assert pdf.content.startswith(b"%PDF-") and pdf.headers["content-type"] == "application/pdf"
    assert client.get(f"/api/analyses/{aid}/report.exe").status_code == 404


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_token_auth(client, monkeypatch):
    monkeypatch.setenv("CAN_ANALYZER_TOKEN", "s3cret-token")
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/auth-check").json() == {"auth_required": True}
    assert client.get("/api/analyses").status_code == 401
    assert client.get("/api/analyses", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/analyses", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
    assert client.get("/api/analyses", headers={"X-API-Token": "s3cret-token"}).status_code == 200
    assert upload(client).status_code == 401


def test_unexpected_errors_do_not_leak_details(client, monkeypatch):
    import app.main as m

    def boom(*a, **k):
        raise RuntimeError("secret internal path /srv/private/thing")

    monkeypatch.setattr(m, "analyze", boom)
    r = upload(client)
    assert r.status_code == 500 and "secret" not in r.text and r.json() == {"detail": "Internal server error"}


def test_busy_server_returns_503(client, monkeypatch):
    import app.main as m

    monkeypatch.setenv("CAN_ANALYZER_MAX_CONCURRENT", "1")
    sem = m._slots.setdefault(1, m.threading.BoundedSemaphore(1))
    assert sem.acquire(blocking=False)
    try:
        assert upload(client).status_code == 503
    finally:
        sem.release()


def test_overlap_dbc_over_api(client):
    r = upload(client, dbc=DBC_OVERLAP.encode(), log=(SAMPLE / "ev_demo.asc").read_bytes())
    assert r.status_code == 200 and r.json()["summary"]["unknown_ids"] >= 1
