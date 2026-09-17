"""
Tests for Layer 2: PII redaction. Pure logic tests, no Qdrant/Ollama needed.
"""
from app.services.redaction import redact_text


def test_redacts_email_and_name():
    text = "Contact Priya Sharma (priya.sharma@guardrailcorp.com) for approval."
    redacted = redact_text(text)
    assert "priya.sharma@guardrailcorp.com" not in redacted
    assert "Priya Sharma" not in redacted
    assert "<EMAIL_ADDRESS>" in redacted
    assert "<PERSON>" in redacted


def test_redacts_phone_number():
    text = "Her phone is 987-654-3210."
    redacted = redact_text(text)
    assert "987-654-3210" not in redacted


def test_leaves_non_pii_text_unchanged():
    text = "All full-time employees are entitled to 18 days of paid annual leave."
    redacted = redact_text(text)
    assert redacted == text


def test_empty_string_returns_empty():
    assert redact_text("") == ""


def test_does_not_over_redact_common_words():
    """
    Regression check: the unrestricted Presidio default entity set
    flags ordinary words like "annually" as DATE_TIME. Confirms our
    restricted entity list doesn't do that.
    """
    text = "Senior Engineers are banded at a fixed salary annually."
    redacted = redact_text(text)
    assert "annually" in redacted


def test_multi_name_list_does_not_miss_names():
    """
    Regression test for a real bug found in production testing: spaCy's
    statistical PERSON recognizer missed "Sneha Iyer" entirely in this
    exact multi-line list context, while identical neighboring entries
    (Arjun Mehta, Rohan Desai) were caught fine. The miss was silent -
    no error, just an unredacted name in the LLM's output. This test
    would have caught it before it reached a live query.
    """
    text = (
        "Current Senior Engineers on record:\n"
        "- Arjun Mehta (arjun.mehta@guardrailcorp.com), Employee ID: EMP-1042, Contact: 912-345-6780\n"
        "- Sneha Iyer (sneha.iyer@guardrailcorp.com), Employee ID: EMP-1087, Contact: 987-654-3210\n"
        "- Rohan Desai (rohan.desai@guardrailcorp.com), Employee ID: EMP-1093, Contact: 911-222-3344"
    )
    redacted = redact_text(text)
    assert "Arjun Mehta" not in redacted
    assert "Sneha Iyer" not in redacted
    assert "Rohan Desai" not in redacted


def test_pattern_recognizer_does_not_flag_document_titles():
    """
    Regression check for a false positive introduced while fixing the
    Sneha Iyer gap: an earlier, looser version of the pattern fix
    (name before ANY parenthesis) incorrectly flagged ordinary
    title-case document names as PERSON. The fix requires an actual
    email format inside the parentheses, not just any parenthetical.
    """
    text = (
        "Employee Handbook (updated 2026) covers all policies. "
        "Annual Report (Q4 2025) is attached. "
        "Data Classification Policy (see appendix) applies here."
    )
    redacted = redact_text(text)
    assert redacted == text
