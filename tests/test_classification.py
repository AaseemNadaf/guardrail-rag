"""
Tests for classification handling and RBAC clearance boundaries.

These cover the logic that the stale-index bug exposed: a document's
classification must be authoritative, and clearance must be strictly
bounded. No Qdrant/Ollama needed.
"""
from app.services.users import CLASSIFICATION_ORDER, get_allowed_classifications


def test_intern_cannot_reach_internal():
    """
    The exact failure seen in testing: an intern retrieved Internal-classified
    content (eng_onboarding.txt) because stale Public-tagged points from an
    earlier ingest were still in Qdrant. The clearance logic itself was
    correct - this pins that down so a future change can't quietly widen it.
    """
    allowed = get_allowed_classifications("intern")
    assert "Internal" not in allowed
    assert "Confidential" not in allowed
    assert "Restricted" not in allowed
    assert allowed == ["Public"]


def test_engineer_reaches_internal_but_not_confidential():
    allowed = get_allowed_classifications("engineer")
    assert "Internal" in allowed
    assert "Confidential" not in allowed
    assert "Restricted" not in allowed


def test_hr_manager_reaches_confidential_but_not_restricted():
    allowed = get_allowed_classifications("hr_manager")
    assert "Confidential" in allowed
    assert "Restricted" not in allowed


def test_clearance_is_always_a_prefix_of_the_hierarchy():
    """
    Clearance must be contiguous from Public upward - no role should ever
    get a higher level while missing a lower one.
    """
    for role in ["intern", "engineer", "hr_manager", "admin"]:
        allowed = get_allowed_classifications(role)
        assert allowed == CLASSIFICATION_ORDER[: len(allowed)], f"{role} clearance is not contiguous"


def test_every_classification_level_is_covered_by_some_role():
    """
    Guards against a level existing in the data that no role can ever read,
    which would silently make those documents unreachable.
    """
    reachable = set()
    for role in ["intern", "engineer", "hr_manager", "admin"]:
        reachable.update(get_allowed_classifications(role))
    assert reachable == set(CLASSIFICATION_ORDER)
