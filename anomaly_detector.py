"""
Unsupervised anomaly detection for web server log entries.

Uses an Isolation Forest, which isolates outliers by randomly partitioning
the feature space -- anomalous points require fewer splits to isolate,
so they get a shorter average path length and a lower (more negative)
anomaly score. This is well suited to log data because it needs no
labeled "attack" examples and handles high-dimensional, skewed
distributions (e.g. request-size, status-code frequency) well.

Features engineered per request:
  1. status_code            - raw HTTP status
  2. bytes_sent              - response size
  3. is_error                - 1 if status >= 400
  4. path_length              - length of the requested path (long/odd
                                 paths often indicate scanning or injection attempts)
  5. requests_from_ip_in_window - how many requests that IP made in the batch
                                    (bursty IPs look like brute-force / scraping)
  6. hour_of_day              - cyclical time feature; off-hours traffic is
                                 sometimes more suspicious
"""
from dataclasses import dataclass
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.log_parser import ParsedLogLine

# Path fragments commonly probed by scanners/bots looking for exposed
# config files, admin panels, or credentials. Not exhaustive by design --
# this is a lightweight signal fed into the model, not a signature blocklist.
SUSPICIOUS_PATH_MARKERS = (
    ".env", "wp-admin", "phpmyadmin", ".git", "xmlrpc.php",
    "config.php", "shell", "passwd", "admin", "..",
)


@dataclass
class ScoredEntry:
    parsed: ParsedLogLine
    anomaly_score: float
    is_anomaly: bool


def _looks_like_scan(path: str) -> int:
    path_lower = (path or "").lower()
    return 1 if any(marker in path_lower for marker in SUSPICIOUS_PATH_MARKERS) else 0


def _build_feature_frame(entries: list[ParsedLogLine]) -> pd.DataFrame:
    ip_counts = Counter(e.ip_address for e in entries if e.parse_ok)
    total = max(len(entries), 1)

    rows = []
    for e in entries:
        if not e.parse_ok:
            continue
        rows.append({
            "status_code": e.status_code,
            "bytes_sent": e.bytes_sent,
            "is_error": 1 if e.status_code >= 400 else 0,
            "path_length": len(e.request_path or ""),
            "suspicious_path_pattern": _looks_like_scan(e.request_path),
            # Normalized request share: what fraction of this batch's traffic
            # came from this single IP -- a large share signals scripted/bursty behavior.
            "ip_traffic_share": ip_counts.get(e.ip_address, 1) / total,
            "hour_of_day": e.timestamp.hour if e.timestamp else 12,
        })
    return pd.DataFrame(rows)


def detect_anomalies(
    entries: list[ParsedLogLine],
    contamination: float = 0.08,
    random_state: int = 42,
) -> list[ScoredEntry]:
    """
    Runs Isolation Forest over the parsed batch and returns a score
    and anomaly flag for every successfully-parsed entry.

    `contamination` is the expected proportion of anomalous traffic;
    0.08 is a reasonable default for general web traffic and can be
    tuned per deployment.
    """
    valid_entries = [e for e in entries if e.parse_ok]
    if len(valid_entries) < 5:
        # Not enough data for a meaningful model; flag nothing.
        return [ScoredEntry(e, 0.0, False) for e in valid_entries]

    features = _build_feature_frame(valid_entries)

    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=150,
    )
    model.fit(features)

    raw_scores = model.decision_function(features)   # higher = more normal
    predictions = model.predict(features)              # -1 = anomaly, 1 = normal

    results = []
    for entry, score, pred in zip(valid_entries, raw_scores, predictions):
        results.append(ScoredEntry(
            parsed=entry,
            anomaly_score=float(score),
            is_anomaly=bool(pred == -1),
        ))
    return results
