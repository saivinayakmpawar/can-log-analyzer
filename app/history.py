"""On-disk analysis history: one directory per analysis under the data dir."""
from __future__ import annotations

import json
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from .store import FrameStore

_ID = re.compile(r"^[0-9a-f]{32}$")
_ORPHAN_AGE_S = 3600


class NotFound(Exception):
    pass


class Repository:
    def __init__(self, root: Path, max_items: int = 25) -> None:
        self.root = Path(root)
        self.max_items = max_items
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def valid_id(analysis_id: str) -> bool:
        return bool(_ID.match(analysis_id))

    def new_id(self) -> str:
        return uuid.uuid4().hex

    def path(self, analysis_id: str) -> Path:
        """Directory for an id. Only ids matching a strict pattern are accepted, so
        a request can never name a path outside the data directory."""
        if not self.valid_id(analysis_id):
            raise NotFound(analysis_id)
        return self.root / analysis_id

    def workdir(self, analysis_id: str) -> Path:
        d = self.path(analysis_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def store(self, analysis_id: str) -> FrameStore:
        d = self.path(analysis_id)
        if not (d / "result.json").exists():
            raise NotFound(analysis_id)
        return FrameStore(d / "frames.sqlite")

    def dbc_path(self, analysis_id: str) -> Path:
        d = self.path(analysis_id)
        if not (d / "input.dbc").exists():
            raise NotFound(analysis_id)
        return d / "input.dbc"

    def save(self, analysis_id: str, result: dict[str, Any]) -> None:
        d = self.path(analysis_id)
        tmp = d / "result.json.tmp"
        tmp.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
        tmp.replace(d / "result.json")
        self.prune()

    def load(self, analysis_id: str) -> dict[str, Any]:
        p = self.path(analysis_id) / "result.json"
        if not p.exists():
            raise NotFound(analysis_id)
        data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
        return data

    def discard(self, analysis_id: str) -> None:
        if self.valid_id(analysis_id):
            shutil.rmtree(self.root / analysis_id, ignore_errors=True)

    def delete(self, analysis_id: str) -> None:
        d = self.path(analysis_id)
        if not d.exists():
            raise NotFound(analysis_id)
        shutil.rmtree(d, ignore_errors=True)

    def list(self) -> list[dict[str, Any]]:
        items = []
        for d in self.root.iterdir():
            res = d / "result.json"
            if not (d.is_dir() and self.valid_id(d.name) and res.exists()):
                continue
            try:
                r = json.loads(res.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            sev = {"high": 0, "medium": 0, "low": 0}
            for a in r.get("anomalies", []):
                sev[a["severity"]] = sev.get(a["severity"], 0) + 1
            meta = r.get("meta", {})
            items.append({
                "id": d.name,
                "analyzed_at": meta.get("analyzed_at"),
                "dbc_name": meta.get("dbc", {}).get("name"),
                "log_name": meta.get("log", {}).get("name"),
                "frames": r.get("summary", {}).get("frames"),
                "duration_s": r.get("summary", {}).get("duration_s"),
                "findings": sev,
            })
        items.sort(key=lambda x: x["analyzed_at"] or "", reverse=True)
        return items

    def prune(self) -> None:
        """Keep the newest ``max_items`` analyses and remove abandoned work directories."""
        now = time.time()
        for d in self.root.iterdir():
            if d.is_dir() and not (d / "result.json").exists() and now - d.stat().st_mtime > _ORPHAN_AGE_S:
                shutil.rmtree(d, ignore_errors=True)
        for item in self.list()[self.max_items:]:
            shutil.rmtree(self.root / item["id"], ignore_errors=True)
