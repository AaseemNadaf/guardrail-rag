"""
Tests for audit logging: writes, reads, filters, and the access-scoping rule.

Uses a temp SQLite file rather than the real data/guardrail.db so tests
never touch or depend on live audit data.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.audit import AuditLog
from app.services.audit import list_entries, record_query


@pytest.fixture
def session(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/test_audit.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


# --- writes ---

def test_record_query_persists_entry(session):
    entry = record_query(
        session,
        username="bob",
        role="engineer",
        allowed_classifications=["Public", "Internal"],
        question="What are the salary bands?",
        retrieved_count=3,
        kept_count=2,
        top_score=0.6440,
        pii_redacted=True,
        response_time_sec=4.21,
    )
    assert entry is not None
    assert entry.id is not None
    assert session.query(AuditLog).count() == 1


def test_refusal_is_recorded_with_reason(session):
    """
    Refusals are the most important entries to have on record - they're the
    evidence that access control actually denied something.
    """
    entry = record_query(
        session,
        username="carol",
        role="intern",
        allowed_classifications=["Public"],
        question="List the senior engineers and their contact details.",
        retrieved_count=3,
        kept_count=0,
        top_score=0.5554,
        refused=True,
        refusal_reason="no_relevant_authorized_context",
        response_time_sec=0.18,
    )
    assert entry.refused is True
    assert entry.refusal_reason == "no_relevant_authorized_context"
    assert entry.kept_count == 0


def test_write_failure_returns_none_without_raising(session, monkeypatch):
    """
    Audit writes are best-effort: a failed insert must not fail the query that
    was already answered successfully. SQLite does lock under concurrent
    writes, so this path is reachable in practice, not hypothetical.

    Note: session.close() does NOT simulate this - SQLAlchemy 2.x silently
    reopens a connection on next use. The commit itself has to fail.
    """
    def boom():
        raise RuntimeError("database is locked")

    monkeypatch.setattr(session, "commit", boom)

    entry = record_query(
        session,
        username="bob",
        role="engineer",
        allowed_classifications=["Public"],
        question="anything",
    )
    assert entry is None  # logged a warning, did not raise


# --- serialisation ---

def test_to_dict_shape_matches_ui_contract(session):
    """
    The audit-viewer UI was built against this shape. Pins the field names so
    a model change can't silently break the frontend.
    """
    record_query(
        session,
        username="alice",
        role="hr_manager",
        allowed_classifications=["Public", "Internal", "Confidential"],
        question="What is the promotion policy?",
        retrieved_count=3,
        kept_count=3,
        pii_redacted=False,
        response_time_sec=5.678,
    )
    d = list_entries(session)[0].to_dict()
    for field in [
        "timestamp", "user", "role", "question", "allowed_classifications",
        "source_count", "pii_redacted", "response_time_sec", "refused",
    ]:
        assert field in d, f"missing field: {field}"
    assert d["allowed_classifications"] == ["Public", "Internal", "Confidential"]
    assert d["response_time_sec"] == 5.68  # rounded for display


# --- reads and filters ---

def test_list_entries_filters_by_username(session):
    for user, role in [("bob", "engineer"), ("carol", "intern"), ("bob", "engineer")]:
        record_query(
            session, username=user, role=role,
            allowed_classifications=["Public"], question="q",
        )
    assert len(list_entries(session, username="bob")) == 2
    assert len(list_entries(session, username="carol")) == 1


def test_list_entries_respects_limit(session):
    for i in range(5):
        record_query(
            session, username="bob", role="engineer",
            allowed_classifications=["Public"], question=f"q{i}",
        )
    assert len(list_entries(session, limit=2)) == 2


def test_no_retrieved_content_is_stored(session):
    """
    The audit trail must not contain document text. An audit log holding the
    PII it exists to protect is a liability, and would let anyone with audit
    access read content above their own clearance.
    """
    record_query(
        session, username="bob", role="engineer",
        allowed_classifications=["Public", "Internal"],
        question="What are the salary bands?",
    )
    entry = list_entries(session)[0]
    stored = " ".join(str(v) for v in entry.to_dict().values())
    assert "Arjun Mehta" not in stored
    assert "<PERSON>" not in stored
    assert not hasattr(entry, "retrieved_text")
    assert not hasattr(entry, "answer")
