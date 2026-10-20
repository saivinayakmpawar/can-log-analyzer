import pytest

from app.analyzer import analyze
from app.checksums import crc8_j1850, register_checksum, xor8
from app.errors import RuleError
from app.rules import parse_rules
from tests.conftest import DBC_CYCLIC

DBC_INT = '''VERSION ""
BU_: A
BO_ 200 Frm: 8 A
 SG_ Val : 0|8@1+ (1,0) [0|100] "u" Vector__XXX
 SG_ Cnt : 48|4@1+ (1,0) [0|15] "" Vector__XXX
 SG_ Crc : 56|8@1+ (1,0) [0|255] "" Vector__XXX
BA_DEF_ BO_ "GenMsgCycleTime" INT 0 65535;
BA_DEF_DEF_ "GenMsgCycleTime" 0;
BA_ "GenMsgCycleTime" BO_ 200 10;
'''
RULES = {"counters": [{"message": "Frm", "signal": "Cnt"}],
         "checksums": [{"message": "Frm", "signal": "Crc", "algorithm": "crc8_sae_j1850"}]}


def frame(i, cnt=None, val=10, crc_ok=True):
    cnt = i % 16 if cnt is None else cnt
    p = bytearray([val, 0, 0, 0, 0, 0, cnt, 0])
    p[7] = crc8_j1850(bytes(p[:7])) ^ (0 if crc_ok else 0xFF)
    return (i * 0.01, 200, False, bytes(p))


@pytest.fixture
def dbc(make):
    return make("i.dbc", DBC_INT)


def test_clean_counter_and_checksum_produce_no_findings(dbc, asc):
    assert analyze(dbc, asc([frame(i) for i in range(100)]), rules=RULES)["anomalies"] == []


def test_counter_wraps_modulo_range(dbc, asc):
    r = analyze(dbc, asc([frame(i) for i in range(40)]), rules=RULES)  # wraps 15 -> 0 twice
    assert not [a for a in r["anomalies"] if a["type"] == "counter_error"]


def test_counter_skip_is_a_confirmed_violation_with_evidence(dbc, asc):
    rows = [frame(i) for i in range(10)] + [frame(i, cnt=(i + 3) % 16) for i in range(10, 20)]
    r = analyze(dbc, asc(rows), rules=RULES)
    errs = [a for a in r["anomalies"] if a["type"] == "counter_error"]
    assert len(errs) == 1 and errs[0]["classification"] == "confirmed_violation"
    ev = errs[0]["evidence"]
    assert (ev["previous_value"], ev["value"], ev["expected"]) == (9, 13, 10)
    assert ev["frames_skipped_if_loss"] == 3


def test_counter_not_checked_when_not_configured(dbc, asc):
    rows = [frame(i, cnt=(i * 5) % 16) for i in range(30)]
    assert analyze(dbc, asc(rows))["anomalies"] == []


def test_checksum_mismatch_merges_consecutive_frames(dbc, asc):
    rows = [frame(i, crc_ok=not (5 <= i < 8)) for i in range(20)]
    r = analyze(dbc, asc(rows), rules=RULES)
    errs = [a for a in r["anomalies"] if a["type"] == "checksum_error"]
    assert len(errs) == 1 and errs[0]["evidence"]["failing_frames"] == 3
    assert errs[0]["evidence"]["algorithm"] == "crc8_sae_j1850"


def test_crc8_matches_published_check_value():
    assert crc8_j1850(b"123456789") == 0x4B  # CRC-8/SAE-J1850 catalogue check value


def test_custom_checksum_plugin(dbc, asc):
    @register_checksum("test_plugin_sum")
    def _fn(data: bytes, bias: int = 0) -> int:
        return (sum(data) + bias) & 0xFF

    def row(i):
        p = bytearray([i, 0, 0, 0, 0, 0, 0, 0])
        p[7] = (sum(p[:7]) + 1) & 0xFF
        return (i * 0.01, 200, False, bytes(p))

    rules = {"checksums": [{"message": "Frm", "signal": "Crc", "algorithm": "test_plugin_sum", "params": {"bias": 1}}]}
    assert analyze(dbc, asc([row(i) for i in range(20)]), rules=rules)["anomalies"] == []


def test_xor8_known_value():
    assert xor8(b"\x0f\xf0\xff") == 0x00  # 0x0F ^ 0xF0 ^ 0xFF
    assert xor8(b"\x01\x02") == 0x03


@pytest.mark.parametrize("rules,msg", [
    ({"thresholds": [{"signal": "Frm.Nope", "max": 1}]}, "not in the DBC"),
    ({"thresholds": [{"signal": "Nothing", "max": 1}]}, "Message.Signal"),
    ({"thresholds": [{"signal": "Frm.Val"}]}, "min or a max"),
    ({"messages": {"Ghost": {}}}, "not in the DBC"),
    ({"checksums": [{"message": "Frm", "signal": "Crc", "algorithm": "md5"}]}, "Unknown checksum algorithm"),
    ({"checksums": [{"message": "Frm", "signal": "Cnt", "algorithm": "xor8"}]}, "byte-aligned"),
    ({"unexpected_key": 1}, "unexpected_key"),
    ({"gap_factor": 0.5}, "gap_factor"),
])
def test_invalid_rules_are_rejected_with_clear_errors(dbc, asc, rules, msg):
    with pytest.raises(RuleError) as ei:
        analyze(dbc, asc([frame(0)]), rules=rules)
    assert msg in str(ei.value)


def test_rules_must_be_valid_json():
    with pytest.raises(RuleError):
        parse_rules(b"{not json")
    with pytest.raises(RuleError):
        parse_rules(b"[1,2]")


def test_user_threshold_severity_and_source(dbc, asc):
    rows = [frame(i, val=70 if 3 <= i < 6 else 10) for i in range(10)]
    rules = {"thresholds": [{"signal": "Frm.Val", "max": 50, "severity": "low"}]}
    r = analyze(dbc, asc(rows), rules=rules)
    (v,) = [a for a in r["anomalies"] if a["type"] == "out_of_range"]
    assert v["severity"] == "low" and v["evidence"]["limit_source"] == "rule" and v["evidence"]["max"] == 50
    assert v["evidence"]["violating_frames"] == 3 and v["classification"] == "confirmed_violation"


def test_dbc_limits_can_be_disabled(dbc, asc):
    rows = [frame(i, val=150) for i in range(5)]
    assert analyze(dbc, asc(rows), rules={"use_dbc_limits": False})["anomalies"] == []
    assert analyze(dbc, asc(rows))["anomalies"][0]["severity"] == "high"


def test_dbc_zero_zero_range_is_not_a_limit(make, asc):
    dbc = make("z.dbc", 'VERSION ""\nBU_: A\nBO_ 100 Z: 8 A\n SG_ S : 0|8@1+ (1,0) [0|0] "" Vector__XXX\n')
    assert analyze(dbc, asc([(i * 0.1, 100, False, bytes([50] + [0] * 7)) for i in range(5)]))["anomalies"] == []


def test_boundary_values_are_inside_the_range(dbc, asc):
    rows = [frame(0, val=0), frame(1, val=100)]
    assert analyze(dbc, asc(rows))["anomalies"] == []


def test_findings_are_capped_and_the_cap_is_reported(dbc, asc):
    rows = [frame(i, cnt=(i * 7) % 16) for i in range(600)]
    r = analyze(dbc, asc(rows), rules=RULES)
    assert sum(a["type"] == "counter_error" for a in r["anomalies"]) == 200
    assert r["meta"]["truncated_findings"]["counter_error:Frm.Cnt"] > 0


def test_cyclic_fixture_still_loads(make):
    assert make("c.dbc", DBC_CYCLIC).exists()
