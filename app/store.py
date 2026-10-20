"""SQLite-backed frame store.

Frames are streamed into SQLite during ingest so the analysis, the frame viewer
and range-limited signal queries never need the whole log in memory.
Every SQL statement uses bound parameters; user text is never interpolated.
"""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE frames (
    idx    INTEGER PRIMARY KEY,
    t      REAL    NOT NULL,
    id     INTEGER NOT NULL,
    ext    INTEGER NOT NULL,
    fd     INTEGER NOT NULL,
    remote INTEGER NOT NULL,
    dlc    INTEGER NOT NULL,
    data   BLOB    NOT NULL
);
"""
INDEXES = (
    "CREATE INDEX idx_frames_t ON frames(t)",
    "CREATE INDEX idx_frames_key ON frames(id, ext, idx)",
)
SORTABLE = {"idx": "idx", "t": "t", "id": "id", "dlc": "dlc"}
FrameRow = tuple[int, float, int, int, int, int, int, bytes]
_HEX = re.compile(r"[^0-9A-Fa-f]")


@dataclass
class FrameFilter:
    t0: float | None = None
    t1: float | None = None
    keys: list[tuple[int, bool | None]] | None = None  # (id, ext or None for either)
    data_hex: str | None = None
    ext: bool | None = None
    fd: bool | None = None
    extra_keys: list[tuple[int, bool]] = field(default_factory=list)

    def where(self) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if self.t0 is not None:
            clauses.append("t >= ?")
            params.append(self.t0)
        if self.t1 is not None:
            clauses.append("t <= ?")
            params.append(self.t1)
        if self.ext is not None:
            clauses.append("ext = ?")
            params.append(int(self.ext))
        if self.fd is not None:
            clauses.append("fd = ?")
            params.append(int(self.fd))
        if self.data_hex:
            clean = _HEX.sub("", self.data_hex).upper()
            if clean:
                clauses.append("hex(data) LIKE ?")
                params.append(f"%{clean}%")
        if self.keys is not None:
            if not self.keys:
                clauses.append("0")
            else:
                ors = []
                for fid, ext in self.keys:
                    if ext is None:
                        ors.append("id = ?")
                        params.append(fid)
                    else:
                        ors.append("(id = ? AND ext = ?)")
                        params.extend([fid, int(ext)])
                clauses.append("(" + " OR ".join(ors) + ")")
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


class FrameStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # -- writing ---------------------------------------------------------
    def open_for_ingest(self) -> sqlite3.Connection:
        if self.path.exists():
            self.path.unlink()
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA journal_mode=OFF")
        con.execute("PRAGMA synchronous=OFF")
        con.executescript(SCHEMA)
        return con

    @staticmethod
    def insert_many(con: sqlite3.Connection, rows: list[tuple]) -> None:
        con.executemany("INSERT INTO frames VALUES (?,?,?,?,?,?,?,?)", rows)

    @staticmethod
    def finalize(con: sqlite3.Connection) -> None:
        for stmt in INDEXES:
            con.execute(stmt)
        con.commit()

    # -- reading ---------------------------------------------------------
    def _ro(self) -> sqlite3.Connection:
        con = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        return con

    def iter_frames(self, flt: FrameFilter | None = None) -> Iterator[FrameRow]:
        where, params = (flt or FrameFilter()).where()
        with closing(self._ro()) as con:
            cur = con.execute(
                "SELECT idx,t,id,ext,fd,remote,dlc,data FROM frames" + where + " ORDER BY idx", params
            )
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    return
                yield from chunk

    def count(self, flt: FrameFilter | None = None) -> int:
        where, params = (flt or FrameFilter()).where()
        with closing(self._ro()) as con:
            return int(con.execute("SELECT COUNT(*) FROM frames" + where, params).fetchone()[0])

    def page(
        self, flt: FrameFilter, sort: str = "idx", descending: bool = False, offset: int = 0, limit: int = 100
    ) -> list[FrameRow]:
        column = SORTABLE.get(sort, "idx")
        where, params = flt.where()
        order = f"{column} {'DESC' if descending else 'ASC'}, idx ASC"
        with closing(self._ro()) as con:
            return con.execute(
                "SELECT idx,t,id,ext,fd,remote,dlc,data FROM frames" + where + f" ORDER BY {order} LIMIT ? OFFSET ?",
                [*params, int(limit), int(offset)],
            ).fetchall()

    def around(self, key: tuple[int, bool], t: float, before: int = 3, after: int = 3) -> list[FrameRow]:
        """Frames of one message nearest to ``t`` (for fault investigation)."""
        fid, ext = key
        with closing(self._ro()) as con:
            prev = con.execute(
                "SELECT idx,t,id,ext,fd,remote,dlc,data FROM frames WHERE id=? AND ext=? AND t<=? "
                "ORDER BY idx DESC LIMIT ?",
                (fid, int(ext), t, before),
            ).fetchall()
            nxt = con.execute(
                "SELECT idx,t,id,ext,fd,remote,dlc,data FROM frames WHERE id=? AND ext=? AND t>? "
                "ORDER BY idx ASC LIMIT ?",
                (fid, int(ext), t, after),
            ).fetchall()
        return list(reversed(prev)) + nxt

    def median_periods(self, keys: list[tuple[int, bool]]) -> dict[tuple[int, bool], float]:
        """Exact median inter-frame time (strictly positive gaps) for the given messages."""
        out: dict[tuple[int, bool], float] = {}
        with closing(self._ro()) as con:
            for fid, ext in keys:
                dts = [
                    r[0]
                    for r in con.execute(
                        "SELECT dt FROM (SELECT t - LAG(t) OVER (ORDER BY idx) AS dt FROM frames "
                        "WHERE id=? AND ext=?) WHERE dt > 0 ORDER BY dt",
                        (fid, int(ext)),
                    )
                ]
                if dts:
                    n = len(dts)
                    out[(fid, ext)] = dts[n // 2] if n % 2 else (dts[n // 2 - 1] + dts[n // 2]) / 2
        return out
