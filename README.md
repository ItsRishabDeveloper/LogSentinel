# LogSentinel

An ML-powered REST API that detects anomalous / suspicious activity in web server access logs — scanning bots, credential brute-forcing, and data-exfiltration-style requests — without needing any labeled attack data.

Built with **FastAPI**, **scikit-learn (Isolation Forest)**, **SQLAlchemy/SQLite**, and API-key authentication.

## Why

Security teams often only find out about a probing attack after the fact, by manually grepping through gigabytes of access logs. LogSentinel automates the first pass: upload a log file, get back a ranked list of the requests most likely to be malicious, in seconds.

## How it works

1. **Parse** — Combined Log Format (Apache/Nginx style) lines are parsed into structured fields (IP, path, status, response size, timestamp).
2. **Engineer features** — each request is turned into a feature vector: response size, error status, path length, a "looks like a known scan pattern" flag (`.env`, `wp-admin`, `../../`, etc.), the request's share of that IP's total traffic in the batch, and time-of-day.
3. **Score** — an **Isolation Forest** model (unsupervised) scores every request. Isolation Forest works by randomly partitioning the feature space; outliers need far fewer random splits to isolate than normal points, which gives them a shorter path length and a lower anomaly score. This means the model needs zero labeled "attack" examples to work.
4. **Persist & serve** — results are stored in SQLite and exposed via a REST API, with the most anomalous requests ranked first.

## Try it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Generate a synthetic log with realistic normal traffic plus injected attacks (scanning, brute-force, exfiltration):

```bash
python sample_data/generate_sample_log.py
```

Get an API key, then upload the log:

```bash
curl -X POST http://127.0.0.1:8000/auth/keys \
  -H "Content-Type: application/json" \
  -d '{"owner": "demo"}'

curl -X POST http://127.0.0.1:8000/logs/upload \
  -H "x-api-key: <your key>" \
  -F "file=@sample_data/sample_access.log"
```

The response returns the top 20 requests ranked by anomaly score. On the sample data, the model correctly surfaces the injected `.env` / `wp-admin` / `../../etc/passwd` scanning attempts and the 9.8 MB `all_users` export as the most anomalous traffic — ahead of thousands of lines of normal browsing.

Interactive API docs: `http://127.0.0.1:8000/docs`

## Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/auth/keys` | Issue a new API key |
| POST | `/logs/upload` | Upload & analyze a log file |
| GET | `/logs/batches` | List previous analysis runs |
| GET | `/logs/batches/{id}/anomalies` | Get all flagged anomalies for a run |

## Tests

```bash
pytest tests/ -v
```

11 tests covering the log parser, the anomaly-detection model (including that injected outliers actually get ranked as most anomalous), and full API integration (auth, upload, retrieval).

## Possible extensions

- Real-time streaming ingestion (tail -f style) instead of batch upload
- Per-IP reputation scoring across multiple batches over time
- Slack/email alerting when a new batch's anomaly rate spikes
- Swap Isolation Forest for a supervised model once labeled incident data exists

## Stack

Python · FastAPI · scikit-learn · pandas · SQLAlchemy · SQLite · pytest
