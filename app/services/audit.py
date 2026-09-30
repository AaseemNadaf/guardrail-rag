"""
Audit log write/read service.

Writes are best-effort by design: a failed audit insert logs a warning and
returns None rather than raising. Losing an audit row is bad, but failing a
legitimate answered query because the log table is locked is worse, and
SQLite does lock under concurrent writes. If audit durability ever becomes
a hard requirement, that's a Postgres migration, not a try/except tweak.
"""
import logging

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.audit import AuditLog

logger = logging.getLogger("guardrail.audit")


def record_query(
    session: Session,
    *,
    username: str,
    role: str,
    allowed_classifications: list[str],
    question: str,
    retrieved_count: int = 0,
    kept_count: int = 0,
    top_score: float | None = None,
    pii_redacted: bool = False,
    refused: bool = False,
    refusal_reason: str | None = None,
    grounded: bool | None = None,
    response_time_sec: float = 0.0,
) -> AuditLog | None:
    entry = AuditLog(
        username=username,
        role=role,
        allowed_classifications=",".join(allowed_classifications),
        question=question,
        retrieved_count=retrieved_count,
        kept_count=kept_count,
        top_score=top_score,
        pii_redacted=pii_redacted,
        refused=refused,
        refusal_reason=refusal_reason,
        grounded=grounded,
        response_time_sec=response_time_sec,
    )
    try:
        session.add(entry)
        session.commit()
        session.refresh(entry)
        return entry
    except Exception as e:
        session.rollback()
        logger.warning("Audit write failed (query still served): %s", e)
        return None


def list_entries(
    session: Session,
    *,
    limit: int = 100,
    username: str | None = None,
    role: str | None = None,
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
    if username:
        stmt = stmt.where(AuditLog.username == username)
    if role:
        stmt = stmt.where(AuditLog.role == role)
    return list(session.scalars(stmt))
