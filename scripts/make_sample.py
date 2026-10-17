"""Generate the bundled demo log (30 s of EV traffic with planted faults)."""
import math
import random
from pathlib import Path

import can
import cantools

OUT = Path(__file__).resolve().parent.parent / "app" / "sample"
db = cantools.database.load_file(OUT / "ev_demo.dbc")
random.seed(7)


def speed(t):
    return max(0.0, min(60.0, 4 * t if t < 15 else 60 - 3 * (t - 15)))


def frames():
    for step in range(3000):
        t = step * 0.01
        if step % 10 == 0:  # VCU_Status, 100 ms
            mode = 0 if t < 2 else (1 if t < 20 else 3 if t > 28 else 2)
            yield t, "VCU_Status", dict(VehicleSpeed=speed(t), DriveMode=mode, Handbrake=int(t < 2))
        if step % 10 == 0 and not (12.0 <= t < 13.4):  # BMS dropout 12.0-13.4 s
            soc = 92 - t * 0.4
            temp = 31 + t * 0.15
            if 20.0 <= t < 20.3:
                soc = 105          # planted: SOC out of range
            if 24.0 <= t < 25.0:
                temp = 83          # planted: over-temperature
            yield t, "BMS_Pack", dict(PackVoltage=76.8 - t * 0.03, PackCurrent=speed(t) * 2.1 + random.uniform(-3, 3),
                                      SOC=soc, MaxCellTemp=temp)
        if step % 5 == 0:  # Motor_Status, 50 ms
            yield t, "Motor_Status", dict(MotorRPM=speed(t) * 55, MotorTorque=40 * math.sin(t / 3) + random.uniform(-1, 1))


with can.ASCWriter(OUT / "ev_demo.asc") as w:
    for t, name, vals in frames():
        m = db.get_message_by_name(name)
        w.on_message_received(can.Message(timestamp=1000 + t, arbitration_id=m.frame_id,
                                          data=m.encode(vals, strict=False), is_extended_id=False))
        if name == "VCU_Status" and 8.0 <= t < 8.5:  # planted: unknown ID
            w.on_message_received(can.Message(timestamp=1000 + t + 0.003, arbitration_id=0x7FF,
                                              data=bytes(8), is_extended_id=False))
print("wrote", OUT / "ev_demo.asc")
