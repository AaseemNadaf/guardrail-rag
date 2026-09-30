"""
SQLAlchemy engine and session management for the audit log.

SQLite needs check_same_thread=False because FastAPI serves requests from
a thread pool - the connection gets used from a different thread than the
one that created it, which SQLite rejects by default.
"""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _connect_args() -> dict:
    return {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}


# The SQLite file lives under ./data, which docker-compose bind-mounts, so the
# audit log survives container restarts. Create the directory if it's missing -
# SQLite won't create parent dirs itself and fails with an unhelpful
# "unable to open database file".
if settings.database_url.startswith("sqlite:///./"):
    Path(settings.database_url.replace("sqlite:///./", "").rsplit("/", 1)[0]).mkdir(
        parents=True, exist_ok=True
    )

engine = create_engine(settings.database_url, connect_args=_connect_args())
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Creates tables if they don't exist. Called at app startup."""
    from app.models import audit  # noqa: F401 - registers the model on Base.metadata

    Base.metadata.create_all(bind=engine)


def get_session():
    """FastAPI dependency yielding a session that always closes."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
