import pytest

from app.analyzer import analyze
from app.history import NotFound, Repository
from app.queries import DbcIndex, QueryError, build_filter, correlation, decode_page, signal_series
from app.store import FrameStore
from tests.conftest import DBC_OVERLAP

DBC2 = '''VERSION ""
BU_: A
BO_ 100 Ramp: 8 A
 SG_ Up : 0|8@1+ (1,0) [0|255] "" Vector__XXX
 SG_ Down : 8|8@1+ (1,0) [0|255] "" Vector__XXX
 SG_ Flat : 16|8@1+ (1,0) [0|255] "" Vector__XXX
'''


@pytest.fixture
def analysed(make, asc, tmp_path):
    dbc = make("r.dbc", DBC2)
    rows = [(i * 0.1, 100, False, bytes([i, 200 - i, 7, 0, 0, 0, 0, 0])) for i in range(100)]
    rows.append((10.5, 0x555, False, bytes([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0])))
    store = FrameStore(tmp_path / "frames.sqlite")
    analyze(dbc, asc(rows), store=store)
    return DbcIndex(dbc), store


def test_paging_total_and_sort(analysed):
    idx, store = analysed
    flt = build_filter(idx, t0=None, t1=None, can_id=None, text=None, fmt=None, message=None)
    assert store.count(flt) == 101
    first = store.page(flt, "t", True, 0, 3)
    assert [r[0] for r in first] == [100, 99, 98]
    assert len(store.page(flt, "idx", False, 99, 50)) == 2


def test_filters_by_time_id_name_format_and_payload(analysed):
    idx, store = analysed
    f = lambda **k: build_filter(idx, **{"t0": None, "t1": None, "can_id": None, "text": None, "fmt": None, "message": None, **k})  # noqa: E731
    assert store.count(f(t0=1.0, t1=1.95)) == 10
    assert store.count(f(can_id="0x555")) == 1
    assert store.count(f(can_id="555")) == 1
    assert store.count(f(text="ramp")) == 100
    assert store.count(f(text="DEADBEEF")) == 1
    assert store.count(f(message="Ramp")) == 100
    assert store.count(f(fmt="ext")) == 0 and store.count(f(fmt="std")) == 101


@pytest.mark.parametrize("evil", ["'; DROP TABLE frames;--", "1 OR 1=1", "%' OR '1'='1", "ramp' --"])
def test_search_text_is_never_executed_as_sql(analysed, evil):
    idx, store = analysed
    flt = build_filter(idx, t0=None, t1=None, can_id=None, text=evil, fmt=None, message=None)
    assert store.count(flt) == 0
    assert store.count() == 101  # table intact


def test_bad_filter_values_raise_query_errors(analysed):
    idx, _ = analysed
    with pytest.raises(QueryError):
        build_filter(idx, t0=None, t1=None, can_id="zz", text=None, fmt=None, message=None)
    with pytest.raises(QueryError):
        build_filter(idx, t0=None, t1=None, can_id=None, text=None, fmt="weird", message=None)
    with pytest.raises(QueryError):
        build_filter(idx, t0=None, t1=None, can_id=None, text=None, fmt=None, message="Nope")


def test_unknown_sort_column_falls_back_safely(analysed):
    idx, store = analysed
    flt = build_filter(idx, t0=None, t1=None, can_id=None, text=None, fmt=None, message=None)
    rows = store.page(flt, "idx; DROP TABLE frames", False, 0, 2)
    assert [r[0] for r in rows] == [0, 1]


def test_decode_page_marks_unknown_ids(analysed):
    idx, store = analysed
    flt = build_filter(idx, t0=None, t1=None, can_id="555", text=None, fmt=None, message=None)
    (row,) = decode_page(idx, store.page(flt))
    assert row["status"] == "unknown" and row["message"] is None and row["data"].startswith("DE AD")


def test_signal_range_query_is_exact_and_has_trend(analysed):
    idx, store = analysed
    s = signal_series(idx, store, "Ramp.Up", 2.0, 4.0, 500)
    assert s["samples"] == 21 and not s["downsampled"]
    assert s["stats"]["min"] == 20 and s["stats"]["max"] == 40
    assert s["stats"]["slope_per_s"] == pytest.approx(10.0)  # +1 per 0.1 s


def test_signal_query_validates_inputs(analysed):
    idx, store = analysed
    for name in ("Nope", "Ramp.Nope", "Ghost.Up"):
        with pytest.raises(QueryError):
            signal_series(idx, store, name, None, None, 500)
    with pytest.raises(QueryError):
        signal_series(idx, store, "Ramp.Up", None, None, 5)


def test_correlation_known_values(analysed):
    idx, store = analysed
    assert correlation(idx, store, "Ramp.Up", "Ramp.Down", None, None)["r"] == pytest.approx(-1.0)
    assert correlation(idx, store, "Ramp.Up", "Ramp.Up", None, None)["r"] == pytest.approx(1.0)
    flat = correlation(idx, store, "Ramp.Up", "Ramp.Flat", None, None)
    assert flat["r"] is None and "constant" in flat["note"]
    assert "causation" in flat["method"]


def test_correlation_with_too_few_samples(analysed):
    idx, store = analysed
    r = correlation(idx, store, "Ramp.Up", "Ramp.Down", 0.0, 0.3)
    assert r["r"] is None and r["n"] < 10


def test_median_period_is_exact(make, asc, tmp_path):
    dbc = make("o.dbc", DBC_OVERLAP)
    store = FrameStore(tmp_path / "m.sqlite")
    ts = [0, 0.1, 0.2, 0.3, 1.3]
    analyze(dbc, asc([(t, 0x100, False, bytes(8)) for t in ts]), store=store)
    assert store.median_periods([(0x100, False)])[(0x100, False)] == pytest.approx(0.1)


def test_repository_rejects_path_traversal(tmp_path):
    repo = Repository(tmp_path / "d")
    for bad in ("../x", "..", "a/b", "/etc/passwd", "0" * 31, "g" * 32, ""):
        with pytest.raises(NotFound):
            repo.path(bad)


def test_repository_prunes_oldest(tmp_path):
    repo = Repository(tmp_path / "d", max_items=2)
    for i in range(4):
        aid = repo.new_id()
        repo.workdir(aid)
        repo.save(aid, {"meta": {"analyzed_at": f"2026-01-0{i + 1}T00:00:00", "dbc": {}, "log": {}},
                        "summary": {}, "anomalies": []})
    assert [x["analyzed_at"][:10] for x in repo.list()] == ["2026-01-04", "2026-01-03"]
