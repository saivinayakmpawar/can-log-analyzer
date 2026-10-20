import pytest

from app.analyzer import analyze
from app.busload import BusLoad, frame_bits
from app.downsample import MinMaxDecimator
from tests.conftest import DBC_CYCLIC


@pytest.mark.parametrize("ext,n,nominal,worst", [
    (False, 8, 111, 135),   # well-known: max standard frame is 135 bits with stuffing
    (True, 8, 131, 160),    # max extended frame is 160 bits with stuffing
    (False, 0, 47, 55),   # 8*0 + 47 + floor((34-1)/4) = 55
])
def test_frame_bits(ext, n, nominal, worst):
    assert frame_bits(ext, n) == (nominal, worst)


def test_bus_load_percentages_and_window_edges():
    b = BusLoad(500_000)
    for _ in range(100):
        b.add(0.5, False, 8)          # 100 x 111 bits in second 0
    b.add(1.2, True, 8)               # one extended frame in a partial last window
    res = b.result(last_t=1.2)
    assert res["points"][0] == [0, 100, pytest.approx(111 * 100 / 500_000 * 100)]
    # last window is only 0.2 s long, so its capacity is 100 000 bits
    assert res["points"][1][2] == pytest.approx(131 / 100_000 * 100)
    assert res["peak_pct_worst_case"] >= res["peak_pct"]


def test_bus_load_with_zero_duration_does_not_divide_by_zero():
    b = BusLoad(250_000)
    b.add(0.0, False, 8)
    res = b.result(last_t=0.0)
    assert res["avg_pct"] > 0 and len(res["points"]) == 1


def test_remote_frames_add_bits_but_not_frame_count():
    b = BusLoad(500_000)
    b.add(0.1, False, 0, counted=False)
    res = b.result(1.0)
    assert res["points"][0][1] == 0 and res["points"][0][2] > 0


def test_assumptions_are_documented_in_the_result(make, asc):
    r = analyze(make("c.dbc", DBC_CYCLIC), asc([(0, 100, False, bytes(8)), (1, 100, False, bytes(8))]))
    assert any("bit stuffing" in a for a in r["bus_load"]["assumptions"])
    assert r["bus_load"]["avg_pct_worst_case"] > r["bus_load"]["avg_pct"]


def test_decimator_exact_when_small():
    d = MinMaxDecimator(100)
    for i in range(40):
        d.add(i, i % 7)
    assert d.points() == [[i, i % 7] for i in range(40)] and not d.downsampled


def test_decimator_keeps_single_sample_spike_and_stays_bounded():
    d = MinMaxDecimator(200)
    for i in range(100_000):
        d.add(i * 0.001, 999.0 if i == 54_321 else 1.0)
    pts = d.points()
    assert len(pts) <= 200 and d.downsampled
    assert any(p[1] == 999.0 for p in pts) and pts == sorted(pts)


def test_decimator_points_are_time_ordered_and_cover_the_span():
    d = MinMaxDecimator(100)
    for i in range(5000):
        d.add(float(i), float(i % 13))
    ts = [p[0] for p in d.points()]
    assert ts == sorted(ts) and ts[0] == 0 and ts[-1] >= 4900
