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
    assert "987-654-3210" not in redact_text("Her phone is 987-654-3210.")


def test_leaves_non_pii_text_unchanged():
    text = "All full-time employees are entitled to 18 days of paid annual leave."
    assert redact_text(text) == text


def test_empty_string_returns_empty():
    assert redact_text("") == ""


def test_does_not_over_redact_common_words():
    """
    The unrestricted Presidio default entity set flags ordinary words like
    "annually" as DATE_TIME. Confirms the restricted entity list doesn't.
    """
    assert "annually" in redact_text("Senior Engineers are banded at a fixed salary annually.")


def test_multi_name_list_does_not_miss_names():
    """
    spaCy's statistical PERSON model silently missed "Sneha Iyer" in this
    exact list context while catching the entries above and below it.
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


def test_redaction_does_not_delete_surrounding_text():
    """
    Regression test for a silent data-loss bug. A custom PatternRecognizer
    registered to fix the Sneha Iyer gap greedily matched job titles, and
    Presidio's overlap resolution expanded that span backwards into the
    preceding email address - deleting everything between. The phrase
    "or reach out to" vanished from the redacted output entirely, with no
    error raised. Redaction must replace PII, never remove context.
    """
    text = (
        "For access-related issues during onboarding, contact IT Support at "
        "it.support@guardrailcorp.com or reach out to Onboarding Coordinator "
        "Vikram Joshi (vikram.joshi@guardrailcorp.com)."
    )
    redacted = redact_text(text)
    assert "or reach out to" in redacted
    assert "Vikram Joshi" not in redacted
    assert redacted.count("<EMAIL_ADDRESS>") == 2


def test_second_pass_does_not_flag_document_titles():
    """
    The second pass requires an <EMAIL_ADDRESS> placeholder specifically,
    not any parenthetical - so ordinary title-case document names are safe.
    """
    text = (
        "Employee Handbook (updated 2026) covers all policies. "
        "Annual Report (Q4 2025) is attached."
    )
    assert redact_text(text) == text
