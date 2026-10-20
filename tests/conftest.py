"""Shared helpers: synthetic DBC text and CAN log writers. No external data is used."""
from __future__ import annotations

from pathlib import Path

import can
import pytest

SAMPLE = Path(__file__).resolve().parent.parent / "app" / "sample"

DBC_OVERLAP = '''VERSION ""
BU_: A B
BO_ 256 StdMsg: 8 A
 SG_ StdVal : 0|8@1+ (1,0) [0|100] "u" Vector__XXX
BO_ 2147483904 ExtMsg: 8 B
 SG_ ExtVal : 0|8@1+ (1,0) [0|50] "u" Vector__XXX
BA_DEF_ BO_ "GenMsgCycleTime" INT 0 65535;
BA_DEF_DEF_ "GenMsgCycleTime" 0;
BA_ "GenMsgCycleTime" BO_ 256 100;
BA_ "GenMsgCycleTime" BO_ 2147483904 100;
'''

DBC_MUX = '''VERSION ""
BU_: A
BO_ 768 Mux: 8 A
 SG_ Sel M : 0|4@1+ (1,0) [0|2] "" Vector__XXX
 SG_ SigA m0 : 8|8@1+ (1,0) [0|100] "" Vector__XXX
 SG_ SigB m1 : 8|8@1+ (1,0) [0|100] "" Vector__XXX
'''

DBC_FD = '''VERSION ""
BU_: A
BO_ 512 FdMsg: 12 A
 SG_ Early : 0|8@1+ (1,0) [0|255] "" Vector__XXX
 SG_ Late : 80|8@1+ (1,0) [0|255] "" Vector__XXX
BA_DEF_ BO_ "VFrameFormat" ENUM "StandardCAN","ExtendedCAN","StandardCAN_FD","ExtendedCAN_FD";
BA_DEF_DEF_ "VFrameFormat" "StandardCAN";
BA_ "VFrameFormat" BO_ 512 2;
'''

DBC_CYCLIC = '''VERSION ""
BU_: A
BO_ 100 Cyc: 8 A
 SG_ Speed : 0|8@1+ (1,0) [0|200] "km/h" Vector__XXX
 SG_ Cnt : 8|4@1+ (1,0) [0|15] "" Vector__XXX
BO_ 101 Evt: 8 A
 SG_ X : 0|8@1+ (1,0) [0|255] "" Vector__XXX
BA_DEF_ BO_ "GenMsgCycleTime" INT 0 65535;
BA_DEF_DEF_ "GenMsgCycleTime" 0;
BA_ "GenMsgCycleTime" BO_ 100 10;
'''

Row = tuple[float, int, bool, bytes]


def write_asc(path: Path, rows: list[Row], fd: bool = False) -> Path:
    with can.ASCWriter(path) as w:
        for ts, arb, ext, data in rows:
            w.on_message_received(can.Message(timestamp=ts, arbitration_id=arb, is_extended_id=ext,
                                              data=data, is_fd=fd))
    return path


@pytest.fixture
def make(tmp_path: Path):
    def _make(name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p
    return _make


@pytest.fixture
def asc(tmp_path: Path):
    def _asc(rows: list[Row], name: str = "t.asc", fd: bool = False) -> Path:
        return write_asc(tmp_path / name, rows, fd)
    return _asc


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Every test gets its own data dir so API tests never share state."""
    monkeypatch.setenv("CAN_ANALYZER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("CAN_ANALYZER_TOKEN", raising=False)
