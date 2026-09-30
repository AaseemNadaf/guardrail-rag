"""
Audit log model.

Records what each layer DECIDED, not what it saw. Deliberately stores no
retrieved chunk text and no redacted content: an audit trail that contains
the PII it was meant to protect is a liability, and it would let anyone with
audit access read documents above their own clearance. The question text is
stored because it's the user's own input and is needed to interpret the
decision trail.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )

    # Layer 1: who asked, and what they were cleared to see
    username: Mapped[str] = mapped_column(String(128), index=True)
    role: Mapped[str] = mapped_column(String(64))
    allowed_classifications: Mapped[str] = mapped_column(String(256))  # comma-separated
    question: Mapped[str] = mapped_column(Text)

    # Retrieval + relevance floor
    retrieved_count: Mapped[int] = mapped_column(Integer, default=0)
    kept_count: Mapped[int] = mapped_column(Integer, default=0)
    top_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Layer 2 / Layer 3 outcomes
    pii_redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    refused: Mapped[bool] = mapped_column(Boolean, default=False)
    refusal_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    grounded: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    response_time_sec: Mapped[float] = mapped_column(Float, default=0.0)

    def to_dict(self) -> dict:
        """Shape matches what the audit-viewer UI consumes."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user": self.username,
            "role": self.role,
            "question": self.question,
            "allowed_classifications": (
                self.allowed_classifications.split(",") if self.allowed_classifications else []
            ),
            "retrieved_count": self.retrieved_count,
            "source_count": self.kept_count,
            "top_score": self.top_score,
            "pii_redacted": self.pii_redacted,
            "refused": self.refused,
            "refusal_reason": self.refusal_reason,
            "grounded": self.grounded,
            "response_time_sec": round(self.response_time_sec, 2),
        }
