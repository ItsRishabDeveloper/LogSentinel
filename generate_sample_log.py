"""
Generates a synthetic Combined Log Format file with mostly normal traffic
and a handful of injected anomalies (scanning behavior, brute-force bursts,
and abnormal response sizes) so the detector has something meaningful to find.
"""
import random
from datetime import datetime, timedelta, timezone

random.seed(7)

NORMAL_PATHS = ["/", "/index.html", "/api/users", "/api/products", "/about",
                "/contact", "/static/style.css", "/static/app.js", "/favicon.ico"]
NORMAL_IPS = [f"10.0.0.{i}" for i in range(2, 30)]
SUSPICIOUS_IPS = ["203.0.113.55", "198.51.100.23"]
SCAN_PATHS = ["/wp-admin", "/.env", "/admin/config.php", "/../../etc/passwd",
              "/phpmyadmin", "/.git/config", "/xmlrpc.php", "/shell.php"]

lines = []
base_time = datetime(2026, 7, 10, 0, 0, 0, tzinfo=timezone.utc)

# ~500 lines of normal traffic
for i in range(500):
    ip = random.choice(NORMAL_IPS)
    ts = base_time + timedelta(seconds=i * 12 + random.randint(0, 5))
    path = random.choice(NORMAL_PATHS)
    status = random.choices([200, 304], weights=[97, 3])[0]
    size = random.randint(200, 5000)
    lines.append(
        f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {path} HTTP/1.1" {status} {size}'
    )

# Injected anomaly cluster 1: directory-scanning bot hammering odd paths
scan_start = base_time + timedelta(minutes=90)
for i in range(25):
    ip = SUSPICIOUS_IPS[0]
    ts = scan_start + timedelta(seconds=i * 2)
    path = random.choice(SCAN_PATHS)
    lines.append(
        f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {path} HTTP/1.1" 404 210'
    )

# Injected anomaly cluster 2: brute-force login attempts, same IP, tight burst
brute_start = base_time + timedelta(hours=3)
for i in range(40):
    ip = SUSPICIOUS_IPS[1]
    ts = brute_start + timedelta(seconds=i)
    lines.append(
        f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] "POST /login HTTP/1.1" 401 89'
    )

# Injected anomaly 3: single huge exfiltration-style response
exfil_time = base_time + timedelta(hours=5)
lines.append(
    f'{SUSPICIOUS_IPS[0]} - - [{exfil_time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
    f'"GET /api/export/all_users HTTP/1.1" 200 9834213'
)

random.shuffle(lines)  # interleave anomalies into normal traffic like real logs

with open("sample_data/sample_access.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Wrote {len(lines)} lines to sample_data/sample_access.log")
