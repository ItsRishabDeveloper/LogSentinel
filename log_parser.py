"""
Parses Combined/Common Log Format (CLF) entries, the format used by
Apache, Nginx, and most reverse proxies, e.g.:

192.168.1.10 - - [12/Jul/2026:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 512
"""
import re
from datetime import datetime
from typing import Optional
from dataclasses import dataclass

CLF_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class ParsedLogLine:
    raw_line: str
    ip_address: Optional[str]
    timestamp: Optional[datetime]
    method: Optional[str]
    request_path: Optional[str]
    status_code: Optional[int]
    bytes_sent: Optional[int]
    parse_ok: bool


def parse_line(line: str) -> ParsedLogLine:
    line = line.strip()
    match = CLF_PATTERN.search(line)
    if not match:
        return ParsedLogLine(line, None, None, None, None, None, None, parse_ok=False)

    groups = match.groupdict()
    try:
        ts = datetime.strptime(groups["timestamp"], TIMESTAMP_FORMAT)
    except ValueError:
        ts = None

    bytes_sent = 0 if groups["bytes"] == "-" else int(groups["bytes"])

    return ParsedLogLine(
        raw_line=line,
        ip_address=groups["ip"],
        timestamp=ts,
        method=groups["method"],
        request_path=groups["path"],
        status_code=int(groups["status"]),
        bytes_sent=bytes_sent,
        parse_ok=True,
    )


def parse_log_file(content: str) -> list[ParsedLogLine]:
    return [parse_line(l) for l in content.splitlines() if l.strip()]
