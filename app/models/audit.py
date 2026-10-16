"""
Audit log model.

Records what each layer DECIDED, not what it saw. Deliberately stores no
retrieved chunk text and no redacted content: an audit trail that contains
the PII it was meant to protect is a liability, and it would let anyone with
audit access read documents above their own clearance. The question text is
stored because it's the user's own input and is needed to interpret the
decision trail.
"""
import json
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

    # What came back, as JSON: [{"file", "classification", "score", "kept"}].
    # Counts alone cannot support the paper's headline Layer 1 claim - proving
    # zero unauthorised retrievals requires knowing WHICH documents were
    # returned and at what classification, per query.
    #
    # Filenames are metadata, not content, so this does not reintroduce the
    # problem the no-document-text rule exists to prevent. It is a narrower
    # exception than it looks, but it is an exception: a filename can itself
    # be disclosive ("2026_layoff_list.txt"), so audit read access stays
    # scoped exactly as before.
    retrieved_docs: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Chunks returned whose classification exceeded the caller's clearance.
    # Computed at write time rather than derived later so a non-zero value is
    # visible immediately in the log and the audit UI, instead of surfacing
    # weeks later when the results are compiled.
    unauthorized_retrieved: Mapped[int] = mapped_column(Integer, default=0)

    # Layer 1 injection screening. Score and matched pattern names are kept so
    # a block can be justified after the fact and the threshold re-swept from
    # logged data without re-running the corpus.
    injection_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    injection_patterns: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Layer 2 / Layer 3 outcomes
    pii_redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    refused: Mapped[bool] = mapped_column(Boolean, default=False)
    refusal_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    grounded: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    response_time_sec: Mapped[float] = mapped_column(Float, default=0.0)

    # Per-stage latency in milliseconds. A single total cannot produce the
    # "overhead per layer" table - that needs each stage measured separately.
    # Nullable because a refused query never reaches generation, and a null
    # must stay distinguishable from a genuine zero when averaging.
    t_embed_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    t_retrieve_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    t_floor_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    t_redact_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    t_generate_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    t_guardrails_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Which evaluation arm produced this row (see Settings.condition_label).
    # Without it the baseline and full-pipeline runs are indistinguishable in
    # the database and cannot be compared.
    condition: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)

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
            "unauthorized_retrieved": self.unauthorized_retrieved,
            "injection_score": self.injection_score,
            "injection_patterns": (
                self.injection_patterns.split(",") if self.injection_patterns else []
            ),
            "retrieved_docs": json.loads(self.retrieved_docs) if self.retrieved_docs else [],
            "condition": self.condition,
            "stage_ms": {
                "embed": self.t_embed_ms,
                "retrieve": self.t_retrieve_ms,
                "floor": self.t_floor_ms,
                "redact": self.t_redact_ms,
                "generate": self.t_generate_ms,
                "guardrails": self.t_guardrails_ms,
            },
        }
