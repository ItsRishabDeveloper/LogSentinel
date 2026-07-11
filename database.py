"""
Database layer for LogSentinel.
Uses SQLAlchemy ORM over SQLite for zero-config local persistence.
"""
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime, timezone

DATABASE_URL = "sqlite:///./logsentinel.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class LogBatch(Base):
    """Represents one uploaded log file / analysis run."""
    __tablename__ = "log_batches"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    total_entries = Column(Integer, default=0)
    anomaly_count = Column(Integer, default=0)

    entries = relationship("LogEntry", back_populates="batch", cascade="all, delete-orphan")


class LogEntry(Base):
    """A single parsed log line and its anomaly score."""
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(Integer, ForeignKey("log_batches.id"))
    raw_line = Column(String, nullable=False)
    ip_address = Column(String, index=True)
    status_code = Column(Integer)
    bytes_sent = Column(Integer)
    request_path = Column(String)
    timestamp = Column(DateTime, nullable=True)

    anomaly_score = Column(Float)       # lower (more negative) = more anomalous
    is_anomaly = Column(Boolean, default=False, index=True)

    batch = relationship("LogBatch", back_populates="entries")


class APIKey(Base):
    """Simple API key store for authenticating clients."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, nullable=False)
    owner = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    active = Column(Boolean, default=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
