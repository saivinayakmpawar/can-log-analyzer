import pytest

from app.analyzer import analyze, inspect_dbc
from app.errors import DbcError
from tests.conftest import DBC_MUX


def test_regression_multiplexed_message_decodes(make, asc):
    """Original code indexed every signal of the message and raised KeyError for inactive mux signals."""
    dbc = make("m.dbc", DBC_MUX)
    rows = [(i * 0.1, 768, False, bytes([i % 2, 10 + i, 0, 0, 0, 0, 0, 0])) for i in range(10)]
    r = analyze(dbc, asc(rows))
    st = r["signal_stats"]
    assert st["Mux.SigA"]["count"] == 5 and st["Mux.SigB"]["count"] == 5
    assert r["anomalies"] == []


def test_range_violation_only_on_active_multiplexed_signal(make, asc):
    dbc = make("m.dbc", DBC_MUX)
    rows = [(0.0, 768, False, bytes([0, 5, 0, 0, 0, 0, 0, 0])),
            (0.1, 768, False, bytes([1, 200, 0, 0, 0, 0, 0, 0])),
            (0.2, 768, False, bytes([0, 5, 0, 0, 0, 0, 0, 0]))]
    r = analyze(dbc, asc(rows))
    bad = [a for a in r["anomalies"] if a["type"] == "out_of_range"]
    assert len(bad) == 1 and bad[0]["signal"] == "SigB" and bad[0]["worst"] == 200


def test_inspect_reports_multiplexing(make):
    info = inspect_dbc(make("m.dbc", DBC_MUX))
    msg = info["messages"][0]
    assert msg["multiplexed"] is True
    sigs = {s["name"]: s for s in msg["signals"]}
    assert sigs["Sel"]["multiplexer"] is True and sigs["SigB"]["mux_ids"] == [1]


@pytest.mark.parametrize("text", ["", "BO_ not a dbc ((((", "\x00\x01\x02"])
def test_malformed_dbc_raises_safe_error(make, asc, text):
    with pytest.raises(DbcError) as ei:
        analyze(make("bad.dbc", text), asc([(0, 1, False, bytes(8))]))
    assert "Traceback" not in str(ei.value) and "/tmp" not in str(ei.value)
