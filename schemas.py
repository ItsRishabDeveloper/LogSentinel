from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional


class LogEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: Optional[str]
    status_code: Optional[int]
    bytes_sent: Optional[int]
    request_path: Optional[str]
    timestamp: Optional[datetime]
    anomaly_score: Optional[float]
    is_anomaly: bool
    raw_line: str


class BatchSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    uploaded_at: datetime
    total_entries: int
    anomaly_count: int


class BatchDetailOut(BatchSummaryOut):
    top_anomalies: list[LogEntryOut]


class APIKeyCreateRequest(BaseModel):
    owner: str


class APIKeyCreateResponse(BaseModel):
    api_key: str
    owner: str
    note: str = "Store this key now -- it will not be shown again."
