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
