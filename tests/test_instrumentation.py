"""
Tests for the evaluation instrumentation added in step A.

The failure mode these guard against is a silent one: an evaluation run that
completes and produces numbers which do not describe the configuration that
actually ran. A wrong condition label or a missing unauthorised-retrieval
count does not crash anything - it just makes the results wrong.
"""
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings
from app.core.database import Base
from app.services.audit import iter_all, list_entries, record_query


@pytest.fixture
def session(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/test_instr.db", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _settings(**over):
    base = dict(jwt_secret_key="test")
    base.update(over)
    return Settings(**base)


# --- condition labelling ---

def test_default_condition_label_describes_a_secure_run():
    s = _settings()
    assert s.condition_label == "rbac=1,floor=0.56,redact=1,ground=0"
    assert s.security_layers_disabled == []


def test_condition_label_tracks_disabled_layers():
    """
    The label is derived, not typed, so it cannot disagree with the config that
    produced the run. This is the whole point: a hand-written label survives a
    config change and silently mislabels every row after it.
    """
    s = _settings(enable_rbac_filter=False, enable_pii_redaction=False)
    assert s.condition_label == "rbac=0,floor=0.56,redact=0,ground=0"


def test_condition_label_reflects_floor_being_off():
    s = _settings(enable_relevance_floor=False)
    assert "floor=off" in s.condition_label


def test_explicit_override_wins():
    s = _settings(eval_condition="baseline_vanilla_rag")
    assert s.condition_label == "baseline_vanilla_rag"


def test_security_layers_disabled_lists_every_off_layer():
    s = _settings(
        enable_rbac_filter=False, enable_relevance_floor=False, enable_pii_redaction=False
    )
    assert set(s.security_layers_disabled) == {"rbac_filter", "relevance_floor", "pii_redaction"}


def test_all_toggles_default_to_secure():
    """Regression guard: a careless default here silently weakens every deployment."""
    s = _settings()
    assert s.enable_rbac_filter is True
    assert s.enable_relevance_floor is True
    assert s.enable_pii_redaction is True


# --- retrieved-doc capture ---

def test_retrieved_docs_round_trip_through_json(session):
    docs = [
        {"file": "hr_salary_bands.txt", "classification": "Internal",
         "score": 0.644, "authorized": True, "kept": True},
        {"file": "it_policy.txt", "classification": "Internal",
         "score": 0.5588, "authorized": True, "kept": False},
    ]
    record_query(
        session, username="bob", role="engineer",
        allowed_classifications=["Public", "Internal"], question="q",
        retrieved_count=2, kept_count=1, retrieved_docs=docs,
    )
    out = list_entries(session)[0].to_dict()["retrieved_docs"]
    assert out == docs
    assert out[1]["kept"] is False


def test_unauthorized_retrieval_is_recorded(session):
    """
    The headline Layer 1 number. Stored per row so a non-zero value is visible
    immediately rather than surfacing weeks later during compilation.
    """
    record_query(
        session, username="carol", role="intern",
        allowed_classifications=["Public"], question="q",
        retrieved_count=1, kept_count=1,
        retrieved_docs=[{"file": "salary_bands.txt", "classification": "Confidential",
                         "score": 0.7, "authorized": False, "kept": True}],
        unauthorized_retrieved=1,
    )
    entry = list_entries(session)[0]
    assert entry.unauthorized_retrieved == 1
    assert entry.to_dict()["retrieved_docs"][0]["authorized"] is False


def test_missing_retrieved_docs_is_empty_list_not_none(session):
    """The compilation script iterates this field; None would crash the pass."""
    record_query(
        session, username="bob", role="engineer",
        allowed_classifications=["Public"], question="q",
    )
    assert list_entries(session)[0].to_dict()["retrieved_docs"] == []


# --- stage timings ---

def test_stage_timings_are_stored_and_exposed(session):
    record_query(
        session, username="bob", role="engineer",
        allowed_classifications=["Public"], question="q",
        stage_ms={"embed": 120.5, "retrieve": 8.2, "floor": 0.3,
                  "redact": 44.0, "generate": 4210.0, "guardrails": 51.1},
    )
    stages = list_entries(session)[0].to_dict()["stage_ms"]
    assert stages["embed"] == 120.5
    assert stages["generate"] == 4210.0


def test_absent_stages_stay_null_not_zero(session):
    """
    A refused query never reaches generation. Null must stay distinguishable
    from a real zero, or averaging generation latency over a run containing
    refusals silently biases the result downward.
    """
    record_query(
        session, username="carol", role="intern",
        allowed_classifications=["Public"], question="q",
        refused=True, refusal_reason="no_relevant_authorized_context",
        stage_ms={"embed": 110.0, "retrieve": 7.0, "floor": 0.2},
    )
    stages = list_entries(session)[0].to_dict()["stage_ms"]
    assert stages["generate"] is None
    assert stages["guardrails"] is None
    assert stages["embed"] == 110.0


# --- condition filtering and full iteration ---

def test_entries_can_be_filtered_by_condition(session):
    for cond in ["baseline", "full", "baseline"]:
        record_query(
            session, username="bob", role="engineer",
            allowed_classifications=["Public"], question="q", condition=cond,
        )
    assert len(list_entries(session, condition="baseline")) == 2
    assert len(list_entries(session, condition="full")) == 1


def test_iter_all_is_not_capped_at_the_ui_limit(session):
    """
    list_entries() caps at 100 because it backs a UI. An analysis pass that
    inherited that cap would compute every rate over a truncated run and give
    a confidently wrong answer.
    """
    for i in range(150):
        record_query(
            session, username="bob", role="engineer",
            allowed_classifications=["Public"], question=f"q{i}", condition="full",
        )
    assert len(list_entries(session)) == 100
    assert len(iter_all(session)) == 150


def test_iter_all_is_oldest_first(session):
    for i in range(3):
        record_query(
            session, username="bob", role="engineer",
            allowed_classifications=["Public"], question=f"q{i}",
        )
    questions = [e.question for e in iter_all(session)]
    assert questions == ["q0", "q1", "q2"]
