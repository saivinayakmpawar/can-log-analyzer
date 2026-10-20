import pytest

from app.analyzer import Limits, analyze
from app.errors import LimitExceeded, LogParseError
from tests.conftest import DBC_FD, DBC_OVERLAP, write_asc


def test_can_fd_frames_decode_and_are_excluded_from_bus_load(make, tmp_path):
    dbc = make("fd.dbc", DBC_FD)
    payload = bytes([1] + [0] * 9 + [0, 0xAB][:0] + [0, 0])  # 12 bytes
    payload = bytes([7]) + bytes(9) + bytes([0x2A, 0])
    rows = [(i * 0.01, 512, False, payload) for i in range(20)]
    log = write_asc(tmp_path / "fd.asc", rows, fd=True)
    r = analyze(dbc, log)
    assert r["summary"]["fd_frames"] == 20 and r["summary"]["frames"] == 0
    assert r["signal_stats"]["FdMsg.Early"]["mean"] == 7
    assert r["signal_stats"]["FdMsg.Late"]["mean"] == 0x2A  # byte 10: beyond the 8-byte classical limit
    assert r["bus_load"]["fd_frames_excluded"] == 20 and r["bus_load"]["avg_pct"] == 0
    assert any("FD" in a for a in r["bus_load"]["assumptions"])
    assert r["anomalies"] == []


def test_short_fd_payload_is_a_decode_error(make, tmp_path):
    dbc = make("fd.dbc", DBC_FD)
    log = write_asc(tmp_path / "fd.asc", [(0, 512, False, bytes(8))], fd=True)
    r = analyze(dbc, log)
    assert [a["type"] for a in r["anomalies"]] == ["decode_error"]


def test_frame_limit_is_enforced_while_reading(make, asc):
    dbc = make("o.dbc", DBC_OVERLAP)
    log = asc([(i * 0.01, 0x100, False, bytes(8)) for i in range(500)])
    with pytest.raises(LimitExceeded):
        analyze(dbc, log, limits=Limits(max_frames=100))


def test_analysis_timeout_is_enforced(make, asc):
    dbc = make("o.dbc", DBC_OVERLAP)
    log = asc([(i * 0.001, 0x100, False, bytes(8)) for i in range(20000)])
    with pytest.raises(LimitExceeded):
        analyze(dbc, log, limits=Limits(timeout_s=1e-9))


@pytest.mark.parametrize("name,content", [
    ("g.asc", bytes(range(256)) * 40), ("b.blf", b"not a blf" * 20), ("c.csv", b"hello,world\n1,2\n")])
def test_unreadable_logs_give_safe_errors(make, tmp_path, name, content):
    dbc = make("o.dbc", DBC_OVERLAP)
    p = tmp_path / name
    p.write_bytes(content)
    with pytest.raises(LogParseError) as ei:
        analyze(dbc, p)
    assert "Traceback" not in str(ei.value) and str(tmp_path) not in str(ei.value)


def test_regression_silently_skipped_lines_are_reported(make, tmp_path):
    """python-can drops unparseable lines without notice; the analysis must say so."""
    dbc = make("o.dbc", DBC_OVERLAP)
    p = tmp_path / "h.asc"
    p.write_text("date Sat Oct 17 10:11:25.463 2026\nbase hex  timestamps absolute\n"
                 " 0.000000 1  100  Rx   d 8 00 00 00\n"                      # claims 8 bytes, has 3
                 " 0.100000 1  100  Rx   d 8 00 00 00 00 00 00 00 00\n"
                 " 0.200000 1  100  Rx   d 8 00 00 00 00 00 00 00 00\n")
    r = analyze(dbc, p)
    bad = [a for a in r["anomalies"] if a["type"] == "malformed_input"]
    assert r["summary"]["frames"] == 2 and r["summary"]["skipped_lines"] == 1
    assert len(bad) == 1 and bad[0]["evidence"]["skipped_lines"] == 1


@pytest.mark.slow
def test_large_log_streams_with_bounded_python_memory(make, tmp_path):
    import tracemalloc

    dbc = make("o.dbc", DBC_OVERLAP)
    n = 60_000
    log = write_asc(tmp_path / "big.asc", [(i * 0.001, 0x100, False, bytes([i % 90] + [0] * 7)) for i in range(n)])
    tracemalloc.start()
    r = analyze(dbc, log)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert r["summary"]["frames"] == n
    assert peak < 25 * 1024 * 1024, f"python heap peak {peak / 1e6:.1f} MB"
    assert all(len(s["points"]) <= 1500 for s in r["signals"].values())
