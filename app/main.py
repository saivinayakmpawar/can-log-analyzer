"""FastAPI application: upload endpoints, analysis history, queries and reports."""
from __future__ import annotations

import hmac
import logging
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__
from .analyzer import Limits, analyze, inspect_dbc
from .compare import compare_results
from .config import Settings, get_settings
from .errors import AnalysisError
from .history import NotFound, Repository
from .queries import DbcIndex, QueryError, around_finding, build_filter, correlation, decode_page, signal_series
from .reports import findings_csv, messages_csv, report_html, report_pdf
from .rules import parse_rules

log = logging.getLogger("can_analyzer")
BASE = Path(__file__).parent
LOG_TYPES = {".asc", ".log", ".csv", ".blf"}
BITRATES = {125000, 250000, 500000, 1000000}
SAMPLES = {"ev_demo": ("ev_demo.dbc", "ev_demo.asc", None), "ev_advanced": ("ev_advanced.dbc", "ev_advanced.asc", "ev_advanced.rules.json"),
           "ev_advanced_clean": ("ev_advanced.dbc", "ev_advanced_clean.asc", "ev_advanced.rules.json")}
_slots: dict[int, threading.BoundedSemaphore] = {}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class RequestTooLarge(Exception):
    pass


class SecurityMiddleware:
    """Adds security headers and rejects oversized request bodies *while they stream in*,
    before the multipart parser has stored them."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = get_settings().max_body_bytes
        started = False
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            await self._reject(send)
            return
        seen = 0

        async def limited_receive() -> Message:
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise RequestTooLarge()
            return msg

        async def send_with_headers(msg: Message) -> None:
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
                hdrs = list(msg.get("headers", []))
                present = {k.lower() for k, _ in hdrs}
                for k, v in SECURITY_HEADERS.items():
                    if k.lower().encode() not in present:
                        hdrs.append((k.lower().encode(), v.encode()))
                if scope["path"].startswith("/api/"):
                    hdrs.append((b"cache-control", b"no-store"))
                msg["headers"] = hdrs
            await send(msg)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except RequestTooLarge:
            if not started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Upload is too large"}'
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            *[(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]]})
        await send({"type": "http.response.body", "body": body})


app = FastAPI(title="CAN Log Analyzer", version=__version__)
app.add_middleware(SecurityMiddleware)


def settings() -> Settings:
    return get_settings()


def repo(s: Settings = Depends(settings)) -> Repository:
    return Repository(s.data_dir, s.max_analyses)


def require_token(request: Request, s: Settings = Depends(settings)) -> None:
    """Optional shared-secret auth. Enabled only when CAN_ANALYZER_TOKEN is set."""
    if not s.api_token:
        return
    supplied = request.headers.get("x-api-token", "")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        supplied = auth[7:]
    if not hmac.compare_digest(supplied.encode(), s.api_token.encode()):
        raise HTTPException(401, "A valid API token is required", headers={"WWW-Authenticate": "Bearer"})


api_deps = [Depends(require_token)]


@app.exception_handler(AnalysisError)
async def analysis_error_handler(_: Request, exc: AnalysisError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled error")  # full trace goes to the server log only
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


async def _save(upload: UploadFile, dest: Path, max_bytes: int, label: str, started: float, timeout: float) -> int:
    """Copy an upload to disk in chunks, stopping as soon as a limit is crossed."""
    size = 0
    with open(dest, "wb") as out:
        while chunk := await upload.read(1 << 20):
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(413, f"{label} is larger than the {max_bytes // (1024 * 1024) or 1} MB limit")
            if time.monotonic() - started > timeout:
                raise HTTPException(408, "Upload took too long")
            out.write(chunk)
    if size == 0:
        raise HTTPException(400, f"{label} is empty")
    return size


def _acquire(s: Settings) -> threading.BoundedSemaphore:
    sem = _slots.setdefault(s.max_concurrent_analyses, threading.BoundedSemaphore(s.max_concurrent_analyses))
    if not sem.acquire(blocking=False):
        raise HTTPException(503, "The server is busy with other analyses. Try again shortly.")
    return sem


def _run_analysis(repository: Repository, s: Settings, dbc: Path, log_path: Path, bitrate: int,
                  rules: bytes | None, names: tuple[str, str]) -> dict[str, Any]:
    sem = _acquire(s)
    try:
        aid = repository.new_id()
        work = repository.workdir(aid)
        try:
            shutil.copyfile(dbc, work / "input.dbc")
            from .store import FrameStore

            result = analyze(work / "input.dbc", log_path, bitrate=bitrate, rules=rules,
                             store=FrameStore(work / "frames.sqlite"), names=names,
                             limits=Limits(max_frames=s.max_frames, timeout_s=s.analysis_timeout_s))
            result["analysis_id"] = aid
            repository.save(aid, result)
            return result
        except BaseException:
            repository.discard(aid)
            raise
    finally:
        sem.release()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/info", dependencies=api_deps)
def info(s: Settings = Depends(settings)) -> dict[str, Any]:
    from .checksums import available

    return {"version": __version__, "auth_required": bool(s.api_token), "log_types": sorted(LOG_TYPES),
            "bitrates": sorted(BITRATES), "max_log_mb": s.max_log_bytes / 1048576, "max_dbc_mb": s.max_dbc_bytes / 1048576,
            "max_frames": s.max_frames, "max_analyses": s.max_analyses, "timeout_s": s.analysis_timeout_s, "checksum_algorithms": available(),
            "samples": list(SAMPLES)}


@app.get("/api/auth-check")
def auth_check(request: Request, s: Settings = Depends(settings)) -> dict[str, Any]:
    """Tells the UI whether it must ask for a token (does not itself require one)."""
    return {"auth_required": bool(s.api_token)}


@app.post("/api/analyze", dependencies=api_deps)
async def analyze_upload(
    dbc: UploadFile = File(...), log: UploadFile = File(...), rules: UploadFile | None = File(None),
    bitrate: int = Form(500000), s: Settings = Depends(settings), repository: Repository = Depends(repo),
) -> dict[str, Any]:
    if bitrate not in BITRATES:
        raise HTTPException(400, f"Bitrate must be one of {sorted(BITRATES)}")
    ext = Path(log.filename or "").suffix.lower()
    if ext not in LOG_TYPES:
        raise HTTPException(400, f"Log must be one of {', '.join(sorted(LOG_TYPES))}")
    if Path(dbc.filename or "").suffix.lower() != ".dbc":
        raise HTTPException(400, "The database file must have a .dbc extension")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="can-upload-") as d:
        tmp = Path(d)
        # Fixed names: the client-supplied file name is only ever displayed, never used as a path.
        await _save(dbc, tmp / "input.dbc", s.max_dbc_bytes, "DBC file", started, s.upload_timeout_s)
        await _save(log, tmp / f"input{ext}", s.max_log_bytes, "CAN log", started, s.upload_timeout_s)
        rules_bytes = None
        if rules is not None and rules.filename:
            await _save(rules, tmp / "rules.json", s.max_rules_bytes, "Rules file", started, s.upload_timeout_s)
            rules_bytes = (tmp / "rules.json").read_bytes()
            parse_rules(rules_bytes)  # fail fast with a readable message
        return await run_in_threadpool(
            _run_analysis, repository, s, tmp / "input.dbc", tmp / f"input{ext}", bitrate, rules_bytes,
            (Path(dbc.filename or "input.dbc").name[:120], Path(log.filename or "log").name[:120]))


@app.post("/api/inspect", dependencies=api_deps)
async def inspect_upload(dbc: UploadFile = File(...), s: Settings = Depends(settings)) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="can-upload-") as d:
        path = Path(d) / "input.dbc"
        await _save(dbc, path, s.max_dbc_bytes, "DBC file", time.monotonic(), s.upload_timeout_s)
        return await run_in_threadpool(inspect_dbc, path)


@app.get("/api/sample", dependencies=api_deps)
async def sample(name: str = "ev_demo", bitrate: int = 500000, s: Settings = Depends(settings),
                 repository: Repository = Depends(repo)) -> dict[str, Any]:
    if name not in SAMPLES:
        raise HTTPException(404, f"Unknown sample. Available: {', '.join(SAMPLES)}")
    dbc_n, log_n, rules_n = SAMPLES[name]
    rules = (BASE / "sample" / rules_n).read_bytes() if rules_n else None
    return await run_in_threadpool(_run_analysis, repository, s, BASE / "sample" / dbc_n, BASE / "sample" / log_n,
                                   bitrate, rules, (dbc_n, log_n))


# ------------------------------------------------------------------ history

def _load(repository: Repository, analysis_id: str) -> dict[str, Any]:
    try:
        return repository.load(analysis_id)
    except NotFound:
        raise HTTPException(404, "Analysis not found") from None


@app.get("/api/analyses", dependencies=api_deps)
def list_analyses(repository: Repository = Depends(repo)) -> list[dict[str, Any]]:
    return repository.list()


@app.get("/api/analyses/{analysis_id}", dependencies=api_deps)
def get_analysis(analysis_id: str, repository: Repository = Depends(repo)) -> dict[str, Any]:
    return _load(repository, analysis_id)


@app.delete("/api/analyses/{analysis_id}", dependencies=api_deps)
def delete_analysis(analysis_id: str, repository: Repository = Depends(repo)) -> dict[str, str]:
    try:
        repository.delete(analysis_id)
    except NotFound:
        raise HTTPException(404, "Analysis not found") from None
    return {"status": "deleted"}


def _index(repository: Repository, analysis_id: str) -> tuple[DbcIndex, Any]:
    try:
        return DbcIndex(repository.dbc_path(analysis_id)), repository.store(analysis_id)
    except NotFound:
        raise HTTPException(404, "Analysis not found") from None


def _bad(exc: QueryError) -> HTTPException:
    return HTTPException(400, str(exc))


@app.get("/api/analyses/{analysis_id}/dbc", dependencies=api_deps)
def analysis_dbc(analysis_id: str, repository: Repository = Depends(repo)) -> dict[str, Any]:
    try:
        return inspect_dbc(repository.dbc_path(analysis_id))
    except NotFound:
        raise HTTPException(404, "Analysis not found") from None


@app.get("/api/analyses/{analysis_id}/frames", dependencies=api_deps)
def frames(
    analysis_id: str, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
    sort: str = Query("idx", pattern="^(idx|t|id|dlc)$"), order: str = Query("asc", pattern="^(asc|desc)$"),
    t0: float | None = None, t1: float | None = None, can_id: str | None = Query(None, max_length=12),
    q: str | None = Query(None, max_length=64), fmt: str | None = None, message: str | None = Query(None, max_length=64),
    repository: Repository = Depends(repo),
) -> dict[str, Any]:
    idx, store = _index(repository, analysis_id)
    try:
        flt = build_filter(idx, t0=t0, t1=t1, can_id=can_id, text=q, fmt=fmt, message=message)
    except QueryError as exc:
        raise _bad(exc) from None
    total = store.count(flt)
    rows = store.page(flt, sort=sort, descending=order == "desc", offset=offset, limit=limit)
    return {"total": total, "offset": offset, "limit": limit, "frames": decode_page(idx, rows)}


@app.get("/api/analyses/{analysis_id}/signal", dependencies=api_deps)
def signal(analysis_id: str, name: str = Query(..., max_length=140), t0: float | None = None, t1: float | None = None,
           max_points: int = 1500, repository: Repository = Depends(repo)) -> dict[str, Any]:
    idx, store = _index(repository, analysis_id)
    try:
        return signal_series(idx, store, name, t0, t1, max_points)
    except QueryError as exc:
        raise _bad(exc) from None


@app.get("/api/analyses/{analysis_id}/correlation", dependencies=api_deps)
def corr(analysis_id: str, x: str = Query(..., max_length=140), y: str = Query(..., max_length=140),
         t0: float | None = None, t1: float | None = None, repository: Repository = Depends(repo)) -> dict[str, Any]:
    idx, store = _index(repository, analysis_id)
    try:
        return correlation(idx, store, x, y, t0, t1)
    except QueryError as exc:
        raise _bad(exc) from None


@app.get("/api/analyses/{analysis_id}/findings/{finding_id}", dependencies=api_deps)
def finding_detail(analysis_id: str, finding_id: str, repository: Repository = Depends(repo)) -> dict[str, Any]:
    result = _load(repository, analysis_id)
    found = next((a for a in result["anomalies"] if a.get("id") == finding_id), None)
    if found is None:
        raise HTTPException(404, "Finding not found")
    idx, store = _index(repository, analysis_id)
    return {"finding": found, "related_frames": around_finding(idx, store, found)}


@app.get("/api/compare", dependencies=api_deps)
def compare(a: str, b: str, repository: Repository = Depends(repo)) -> dict[str, Any]:
    return compare_results(_load(repository, a), _load(repository, b))


@app.get("/api/analyses/{analysis_id}/report.{ext}", dependencies=api_deps)
def report(analysis_id: str, ext: str, section: str = "findings", repository: Repository = Depends(repo)) -> Response:
    result = _load(repository, analysis_id)
    stem = "".join(c if c.isalnum() or c in "-_" else "_" for c in Path(result["meta"]["log"]["name"]).stem)[:60] or "log"
    date = result["meta"]["analyzed_at"][:10]
    if ext == "csv":
        if section not in ("findings", "messages"):
            raise HTTPException(400, "section must be findings or messages")
        body = findings_csv(result) if section == "findings" else messages_csv(result)
        return Response(body, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="can-{section}-{stem}-{date}.csv"'})
    if ext == "html":
        return Response(report_html(result), media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="can-report-{stem}-{date}.html"',
                                 "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:"})
    if ext == "pdf":
        data = report_pdf(result)
        return Response(data, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="can-report-{stem}-{date}.pdf"'})
    raise HTTPException(404, "Unknown report format; use csv, html or pdf")


app.mount("/", StaticFiles(directory=BASE / "static", html=True), name="static")
