"""
Lightweight API key authentication.

Keys are generated with `secrets.token_urlsafe`, and only their SHA-256
hash is ever stored -- the raw key is shown to the caller exactly once
at creation time, the same pattern used by services like Stripe and GitHub
for personal access tokens.
"""
import hashlib
import secrets
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database import get_db, APIKey


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key(db: Session, owner: str) -> str:
    raw_key = f"ls_{secrets.token_urlsafe(32)}"
    record = APIKey(key_hash=hash_key(raw_key), owner=owner)
    db.add(record)
    db.commit()
    return raw_key  # only returned once


def verify_api_key(
    x_api_key: str = Header(..., description="Your LogSentinel API key"),
    db: Session = Depends(get_db),
) -> APIKey:
    record = db.query(APIKey).filter(
        APIKey.key_hash == hash_key(x_api_key),
        APIKey.active == True,  # noqa: E712
    ).first()
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return record
