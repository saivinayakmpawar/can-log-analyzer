"""Generate the synthetic 'ev_advanced' logs (30 s).

ev_advanced.asc        normal traffic plus deliberately injected faults
ev_advanced_clean.asc  the same traffic without faults (for the comparison feature)

Everything here is synthetic. Injected faults:
  * 9.0 s    Motor_Cmd rolling counter skips three values
  * 5.0 s    VCU_Status sent with a 4-byte payload (decode error)
  * 8.0-9.0  frames with ID 0x6A0 that is not in the DBC
  * 12.0-13.4 BMS_Pack dropout
  * 15.0-15.4 CellV_A drops to 2.9 V (inside the DBC range, below the 3.0 V rule threshold)
  * 20.0     three Motor_Cmd frames with a corrupted payload byte (checksum mismatch)
  * 20.0-20.3 SOC reported as 105 % (above the DBC maximum)
  * 25.0-25.3 Charger_Status (29-bit ID 0x100, same number as VCU_Status) current 45 A (DBC max 40 A)
"""
import math
import random
import sys
from pathlib import Path

import can
import cantools

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.checksums import crc8_j1850

OUT = Path(__file__).resolve().parent.parent / "app" / "sample"
db = cantools.database.load_file(OUT / "ev_advanced.dbc", strict=False)


def build(faults: bool, seed: int) -> list[tuple[float, int, bytes, bool]]:
    rnd = random.Random(seed)
    rows: list[tuple[float, int, bytes, bool]] = []
    vcu, chg = db.get_message_by_name("VCU_Status"), db.get_message_by_name("Charger_Status")
    motor, pack = db.get_message_by_name("Motor_Cmd"), db.get_message_by_name("BMS_Pack")
    cell = db.get_message_by_name("BMS_CellData")

    def speed(t: float) -> float:
        return max(0.0, min(60.0, 4 * t if t < 15 else 60 - 3 * (t - 15)))

    counter = 0
    for step in range(3000):
        t = step * 0.01
        base = 1000 + t
        if step % 10 == 0:
            data = vcu.encode(dict(VehicleSpeed=speed(t), DriveMode=0 if t < 2 else 1, Handbrake=int(t < 2)), strict=False)
            if faults and step == 500:
                data = data[:4]  # decode error
            rows.append((base, vcu.frame_id, data, False))
            rows.append((base + 0.002, chg.frame_id, chg.encode(dict(
                ChargerVoltage=76.0 + t * 0.02,
                ChargerCurrent=45.0 if faults and 25.0 <= t < 25.3 else 18.0 + rnd.uniform(-0.5, 0.5),
                ChargerState=2 if t < 20 else 3), strict=False), True))
            if not (faults and 12.0 <= t < 13.4):
                soc = 20.0 + t * 0.5 if not (faults and 20.0 <= t < 20.3) else 105
                rows.append((base + 0.004, pack.frame_id, pack.encode(dict(
                    PackVoltage=76.8 - t * 0.03, PackCurrent=speed(t) * 2.1 + rnd.uniform(-3, 3),
                    SOC=soc, MaxCellTemp=31 + t * 0.15), strict=False), False))
            phase = (step // 10) % 3
            if phase == 0:
                vals = {"CellMux": 0, "CellV_A": 2.9 if faults and 15.0 <= t < 15.4 else 3.7 + rnd.uniform(-0.01, 0.01)}
            elif phase == 1:
                vals = {"CellMux": 1, "CellV_B": 3.69 + rnd.uniform(-0.01, 0.01)}
            else:
                vals = {"CellMux": 2, "CellTemp_Max": 33 + t * 0.1}
            rows.append((base + 0.006, cell.frame_id, cell.encode(vals, strict=False), False))
            if faults and 8.0 <= t < 9.0 and step % 50 == 0:
                rows.append((base + 0.008, 0x6A0, bytes(8), False))
        if step % 2 == 0:  # Motor_Cmd, 20 ms
            if faults and step == 900:
                counter = (counter + 3) % 16  # skipped values
            payload = bytearray(motor.encode(dict(
                TorqueCmd=40 * math.sin(t / 3) + rnd.uniform(-1, 1), RegenLimit=30,
                MC_Counter=counter, MC_Checksum=0), strict=False))
            payload[7] = crc8_j1850(bytes(payload[:7]))
            if faults and step in (2000, 2002, 2004):
                payload[4] ^= 0x5A  # corrupt an unused payload byte after the CRC was computed
            rows.append((base + 0.001, motor.frame_id, bytes(payload), False))
            counter = (counter + 1) % 16
    rows.sort(key=lambda r: r[0])
    return rows


def write(path: Path, rows: list[tuple[float, int, bytes, bool]]) -> None:
    with can.ASCWriter(path) as w:
        for ts, arb, data, ext in rows:
            w.on_message_received(can.Message(timestamp=ts, arbitration_id=arb, data=data, is_extended_id=ext))
    print("wrote", path, len(rows), "frames")


if __name__ == "__main__":
    write(OUT / "ev_advanced.asc", build(True, 11))
    write(OUT / "ev_advanced_clean.asc", build(False, 12))
