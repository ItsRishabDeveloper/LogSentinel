import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

from app.log_parser import parse_line, parse_log_file
from app.models.anomaly_detector import detect_anomalies


# ---------- Log parser tests ----------

def test_parse_valid_clf_line():
    line = '192.168.1.10 - - [12/Jul/2026:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 512'
    result = parse_line(line)
    assert result.parse_ok
    assert result.ip_address == "192.168.1.10"
    assert result.status_code == 200
    assert result.bytes_sent == 512
    assert result.request_path == "/api/users"


def test_parse_handles_dash_bytes():
    line = '10.0.0.1 - - [12/Jul/2026:10:15:32 +0000] "GET / HTTP/1.1" 304 -'
    result = parse_line(line)
    assert result.parse_ok
    assert result.bytes_sent == 0


def test_parse_rejects_garbage_line():
    result = parse_line("this is not a log line")
    assert not result.parse_ok


def test_parse_log_file_skips_blank_lines():
    content = '192.168.1.1 - - [12/Jul/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 100\n\n\n'
    results = parse_log_file(content)
    assert len(results) == 1


# ---------- Anomaly detector tests ----------

def _make_batch(n_normal=100, n_anomalous=5):
    """Builds a synthetic parsed batch: mostly uniform small requests,
    plus a few requests with abnormally large byte counts and error codes."""
    from app.log_parser import ParsedLogLine
    from datetime import datetime, timezone

    entries = []
    for i in range(n_normal):
        entries.append(ParsedLogLine(
            raw_line=f"normal-{i}", ip_address=f"10.0.0.{i % 20}",
            timestamp=datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc),
            method="GET", request_path="/home", status_code=200,
            bytes_sent=500 + (i % 50), parse_ok=True,
        ))
    for i in range(n_anomalous):
        entries.append(ParsedLogLine(
            raw_line=f"anomaly-{i}", ip_address="203.0.113.99",
            timestamp=datetime(2026, 7, 10, 3, 0, tzinfo=timezone.utc),
            method="GET", request_path="/../../etc/passwd" * 3, status_code=500,
            bytes_sent=999999, parse_ok=True,
        ))
    return entries


def test_detector_flags_some_anomalies():
    entries = _make_batch()
    results = detect_anomalies(entries, contamination=0.08)
    assert len(results) == len(entries)
    flagged = [r for r in results if r.is_anomaly]
    assert len(flagged) > 0


def test_detector_ranks_injected_outliers_as_most_anomalous():
    entries = _make_batch(n_normal=100, n_anomalous=5)
    results = detect_anomalies(entries, contamination=0.05)
    # Sort ascending by score (lower score == more anomalous for IsolationForest)
    ranked = sorted(results, key=lambda r: r.anomaly_score)
    top_5_raw_lines = {r.parsed.raw_line for r in ranked[:5]}
    # The 5 injected anomalies should dominate the most-anomalous slice
    injected = {f"anomaly-{i}" for i in range(5)}
    assert len(top_5_raw_lines & injected) >= 3


def test_detector_handles_tiny_batches_gracefully():
    entries = _make_batch(n_normal=2, n_anomalous=0)
    results = detect_anomalies(entries)
    assert all(not r.is_anomaly for r in results)


# ---------- API integration tests ----------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Use an isolated SQLite file per test run
    monkeypatch.chdir(tmp_path)
    import importlib
    import app.database as database
    importlib.reload(database)
    import app.main as main
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def api_key(client):
    resp = client.post("/auth/keys", json={"owner": "test-suite"})
    assert resp.status_code == 200
    return resp.json()["api_key"]


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_upload_requires_api_key(client):
    content = b'10.0.0.1 - - [12/Jul/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 100\n'
    resp = client.post("/logs/upload", files={"file": ("test.log", content)})
    assert resp.status_code in (401, 422)


def test_upload_and_analyze_log_file(client, api_key):
    log_lines = []
    for i in range(30):
        log_lines.append(
            f'10.0.0.{i % 5} - - [12/Jul/2026:10:{i:02d}:00 +0000] "GET /home HTTP/1.1" 200 500'
        )
    # Inject a couple of obvious anomalies
    log_lines.append('203.0.113.1 - - [12/Jul/2026:03:00:00 +0000] "GET /.env HTTP/1.1" 500 999999')
    log_lines.append('203.0.113.1 - - [12/Jul/2026:03:00:01 +0000] "GET /wp-admin HTTP/1.1" 500 999999')

    content = ("\n".join(log_lines)).encode()
    resp = client.post(
        "/logs/upload",
        files={"file": ("test.log", content)},
        headers={"x-api-key": api_key},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_entries"] == len(log_lines)
    assert body["anomaly_count"] >= 1
    assert "top_anomalies" in body


def test_list_batches_and_fetch_anomalies(client, api_key):
    content = b'10.0.0.1 - - [12/Jul/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 100\n' * 20
    upload_resp = client.post(
        "/logs/upload",
        files={"file": ("t.log", content)},
        headers={"x-api-key": api_key},
    )
    batch_id = upload_resp.json()["id"]

    list_resp = client.get("/logs/batches", headers={"x-api-key": api_key})
    assert list_resp.status_code == 200
    assert any(b["id"] == batch_id for b in list_resp.json())

    anomalies_resp = client.get(
        f"/logs/batches/{batch_id}/anomalies", headers={"x-api-key": api_key}
    )
    assert anomalies_resp.status_code == 200
