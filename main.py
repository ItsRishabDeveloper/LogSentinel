"""
LogSentinel API
================
An ML-powered web server log anomaly detector.

Upload a server access log -> LogSentinel parses every request,
engineers behavioral features, scores each request with an Isolation
Forest model, and returns the requests most likely to represent
suspicious activity (scanning, brute-force, injection attempts, etc.).
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import init_db, get_db, LogBatch, LogEntry
from app.log_parser import parse_log_file
from app.models.anomaly_detector import detect_anomalies
from app.auth import verify_api_key, generate_api_key
from app.schemas import (
    BatchSummaryOut, BatchDetailOut, LogEntryOut,
    APIKeyCreateRequest, APIKeyCreateResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="LogSentinel",
    description="ML-powered anomaly detection for web server logs.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["meta"])
def health_check():
    return {"status": "ok"}


@app.post("/auth/keys", response_model=APIKeyCreateResponse, tags=["auth"])
def create_api_key(payload: APIKeyCreateRequest, db: Session = Depends(get_db)):
    """Issue a new API key. In production this would sit behind admin auth
    or a signup flow -- open here for demo/testing purposes."""
    raw_key = generate_api_key(db, payload.owner)
    return APIKeyCreateResponse(api_key=raw_key, owner=payload.owner)


@app.post("/logs/upload", response_model=BatchDetailOut, tags=["logs"])
async def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _api_key=Depends(verify_api_key),
):
    """
    Upload a Combined Log Format (.log/.txt) file. LogSentinel will:
      1. Parse every line into structured fields
      2. Engineer behavioral features per request
      3. Score each request with an Isolation Forest model
      4. Persist results and return the top anomalies
    """
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as text")

    parsed = parse_log_file(content)
    if not parsed:
        raise HTTPException(status_code=400, detail="No log lines found in file")

    scored = detect_anomalies(parsed)
    anomaly_count = sum(1 for s in scored if s.is_anomaly)

    batch = LogBatch(
        filename=file.filename,
        total_entries=len(parsed),
        anomaly_count=anomaly_count,
    )
    db.add(batch)
    db.flush()  # get batch.id before inserting children

    entries = []
    for s in scored:
        entry = LogEntry(
            batch_id=batch.id,
            raw_line=s.parsed.raw_line,
            ip_address=s.parsed.ip_address,
            status_code=s.parsed.status_code,
            bytes_sent=s.parsed.bytes_sent,
            request_path=s.parsed.request_path,
            timestamp=s.parsed.timestamp,
            anomaly_score=s.anomaly_score,
            is_anomaly=s.is_anomaly,
        )
        db.add(entry)
        entries.append(entry)

    db.commit()
    db.refresh(batch)

    top_anomalies = sorted(
        [e for e in entries if e.is_anomaly],
        key=lambda e: e.anomaly_score,
    )[:20]

    return BatchDetailOut(
        id=batch.id,
        filename=batch.filename,
        uploaded_at=batch.uploaded_at,
        total_entries=batch.total_entries,
        anomaly_count=batch.anomaly_count,
        top_anomalies=[LogEntryOut.model_validate(e) for e in top_anomalies],
    )


@app.get("/logs/batches", response_model=list[BatchSummaryOut], tags=["logs"])
def list_batches(db: Session = Depends(get_db), _api_key=Depends(verify_api_key)):
    return db.query(LogBatch).order_by(desc(LogBatch.uploaded_at)).all()


@app.get("/logs/batches/{batch_id}/anomalies", response_model=list[LogEntryOut], tags=["logs"])
def get_batch_anomalies(
    batch_id: int,
    db: Session = Depends(get_db),
    _api_key=Depends(verify_api_key),
):
    batch = db.query(LogBatch).filter(LogBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    anomalies = (
        db.query(LogEntry)
        .filter(LogEntry.batch_id == batch_id, LogEntry.is_anomaly == True)  # noqa: E712
        .order_by(LogEntry.anomaly_score)
        .all()
    )
    return anomalies
