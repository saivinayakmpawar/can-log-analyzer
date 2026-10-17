import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles

from .analyzer import analyze, inspect_dbc

BASE = Path(__file__).parent
MAX_BYTES = 25 * 1024 * 1024
LOG_TYPES = {".asc", ".log", ".csv", ".blf"}
BITRATES = {125000, 250000, 500000, 1000000}

app = FastAPI(title="CAN Log Analyzer")


async def _save(upload: UploadFile, tmp: Path, name: str) -> Path:
    data = await upload.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"{upload.filename} is over 25 MB")
    path = tmp / name
    path.write_bytes(data)
    return path


@app.post("/api/analyze")
async def analyze_upload(dbc: UploadFile = File(...), log: UploadFile = File(...),
                         bitrate: int = Form(500000)):
    if bitrate not in BITRATES:
        raise HTTPException(400, f"Bitrate must be one of {sorted(BITRATES)}")
    ext = Path(log.filename or "").suffix.lower()
    if ext not in LOG_TYPES:
        raise HTTPException(400, f"Log must be one of {', '.join(sorted(LOG_TYPES))}")
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        dbc_path = await _save(dbc, tmp, "input.dbc")
        log_path = await _save(log, tmp, "input" + ext)
        try:
            return analyze(dbc_path, log_path, bitrate=bitrate)
        except Exception as exc:
            raise HTTPException(422, f"Could not analyze files: {exc}")


@app.post("/api/inspect")
async def inspect_upload(dbc: UploadFile = File(...)):
    with tempfile.TemporaryDirectory() as d:
        dbc_path = await _save(dbc, Path(d), "input.dbc")
        try:
            return inspect_dbc(dbc_path)
        except Exception as exc:
            raise HTTPException(422, f"Could not read DBC: {exc}")


@app.get("/api/sample")
def sample():
    return analyze(BASE / "sample" / "ev_demo.dbc", BASE / "sample" / "ev_demo.asc")


app.mount("/", StaticFiles(directory=BASE / "static", html=True), name="static")
