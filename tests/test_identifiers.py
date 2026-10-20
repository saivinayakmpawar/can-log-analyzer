"""11-bit and 29-bit identifiers that share a numeric value must stay distinct."""
from app.analyzer import analyze
from tests.conftest import DBC_OVERLAP


def _counts(r):
    return {(m["name"]): m["count"] for m in r["messages"]}


def test_standard_and_extended_with_same_number_are_separate_messages(make, asc):
    dbc = make("o.dbc", DBC_OVERLAP)
    rows = []
    for i in range(10):
        rows.append((i * 0.1, 0x100, False, bytes([10, 0, 0, 0, 0, 0, 0, 0])))
        rows.append((i * 0.1 + 0.01, 0x100, True, bytes([20, 0, 0, 0, 0, 0, 0, 0])))
    r = analyze(dbc, asc(rows))
    assert _counts(r) == {"StdMsg": 10, "ExtMsg": 10}
    assert r["signal_stats"]["StdMsg.StdVal"]["mean"] == 10
    assert r["signal_stats"]["ExtMsg.ExtVal"]["mean"] == 20
    assert r["anomalies"] == []


def test_regression_extended_frame_is_not_decoded_as_standard_message(make, asc):
    """Original code looked frames up by numeric ID only, so an extended 0x100 was decoded as the
    standard 0x100 message. Here the DBC has only the standard one."""
    dbc = make("s.dbc", DBC_OVERLAP.split("BO_ 2147483904")[0])
    r = analyze(dbc, asc([(i * 0.1, 0x100, True, bytes(8)) for i in range(10)]))
    assert _counts(r)["StdMsg"] == 0
    unknown = [a for a in r["anomalies"] if a["type"] == "unknown_id"]
    assert len(unknown) == 1 and unknown[0]["message"] == "0x100 (ext)"
    assert unknown[0]["evidence"]["extended"] is True


def test_limits_apply_to_the_right_message_when_ids_overlap(make, asc):
    dbc = make("o.dbc", DBC_OVERLAP)
    # 60 exceeds ExtVal's max (50) but not StdVal's max (100)
    rows = [(0.0, 0x100, False, bytes([60] + [0] * 7)), (0.0, 0x100, True, bytes([60] + [0] * 7))]
    r = analyze(dbc, asc(rows))
    viol = [a for a in r["anomalies"] if a["type"] == "out_of_range"]
    assert [v["message"] for v in viol] == ["ExtMsg"]


def test_message_rows_carry_frame_format(make, asc):
    r = analyze(make("o.dbc", DBC_OVERLAP), asc([(0, 0x100, True, bytes(8))]))
    fmt = {m["name"]: m["extended"] for m in r["messages"]}
    assert fmt == {"StdMsg": False, "ExtMsg": True}
