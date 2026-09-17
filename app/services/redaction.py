"""
Layer 2 (post-retrieval) — PII redaction.

Applied to retrieved chunks AFTER RBAC filtering but BEFORE generation,
so the LLM never sees unredacted PII even for chunks it's cleared to
retrieve. Defense in depth: Layer 1 being correctly scoped is not
assumed.

Entity list is deliberately restricted (not Presidio's full default
set) - the defaults include region-specific recognizers (e.g. UK_NHS)
that false-positive on generic phone formats, and a DATE_TIME
recognizer that flags ordinary words like "annually".

Two-pass design, and the reason matters:

Pass 1 is standard Presidio.

Pass 2 catches a real gap - spaCy's statistical PERSON model silently
missed "Sneha Iyer" inside a "- Name (email)" list while catching the
identical entries above and below it. An earlier fix registered a
custom PatternRecognizer for this, and it caused a WORSE bug: the
regex greedily matched job titles ("Onboarding Coordinator Vikram
Joshi"), and Presidio's overlap resolution then expanded that span
backwards into the preceding email address, deleting the innocent text
between them. "contact IT Support at it.support@... or reach out to
Onboarding Coordinator Vikram Joshi (...)" silently became "contact IT
Support at <EMAIL_ADDRESS><PERSON> (<EMAIL_ADDRESS>)". Redaction that
deletes surrounding content degrades answers without anyone noticing.

So pass 2 runs on the ALREADY-ANONYMIZED text instead, matching a name
immediately before an <EMAIL_ADDRESS> placeholder. Because it operates
on final output as plain string replacement, it cannot conflict with
Presidio spans or delete anything outside its own match.
"""
import re

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

_analyzer = AnalyzerEngine()
_anonymizer = AnonymizerEngine()

REDACTION_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
]

# A capitalised multi-word name sitting immediately before an already-redacted
# email placeholder. Requiring the placeholder (not a bare parenthesis) is what
# keeps ordinary titles like "Employee Handbook (updated 2026)" untouched.
_NAME_BEFORE_REDACTED_EMAIL = re.compile(
    r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+(?=\s*\(<EMAIL_ADDRESS>\))"
)


def redact_text(text: str) -> str:
    """Detects and replaces PII in `text` with entity-type placeholders (e.g. <PERSON>)."""
    if not text:
        return text

    results = _analyzer.analyze(text=text, language="en", entities=REDACTION_ENTITIES)
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=results).text

    return _NAME_BEFORE_REDACTED_EMAIL.sub("<PERSON>", anonymized)
