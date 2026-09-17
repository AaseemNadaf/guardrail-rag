"""
Layer 2 (post-retrieval) — PII redaction.

Applied to retrieved chunks AFTER RBAC filtering but BEFORE generation,
so the LLM never sees unredacted PII even for chunks it's cleared to
retrieve. This is the layer that catches PII regardless of whether
RBAC filtering was correctly scoped - defense in depth.

Entity list is deliberately restricted (not Presidio's full default
set) - the full default set includes region-specific recognizers
(e.g. UK_NHS) that false-positive match on generic phone number
formats, and a DATE_TIME recognizer that flags ordinary words like
"annually". Restricting to entities relevant to our dataset avoids
that noise.
"""
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine

_analyzer = AnalyzerEngine()
_anonymizer = AnonymizerEngine()

# Supplemental pattern-based recognizer. spaCy's statistical PERSON recognizer
# has real, confirmed gaps - e.g. "Sneha Iyer" went undetected entirely in a
# "Current Senior Engineers on record: - Name (email)" list, while identical
# neighboring entries (Arjun Mehta, Rohan Desai) were caught fine, and "Sneha
# Iyer" alone in isolation was also caught fine. The miss was context-specific
# to the multi-line list structure - a spaCy model limitation, not a
# Presidio confidence-threshold issue, so lowering the threshold doesn't help.
#
# Fix: a name immediately followed by a parenthesized email is a reliable
# structural signal regardless of what the statistical model decides.
# Deliberately requires an actual email format inside the parentheses (not
# just any parenthetical) - an earlier looser version of this pattern
# false-positived on ordinary title-case document names like
# "Employee Handbook (updated 2026)".
_name_before_email_pattern = Pattern(
    name="name_before_parenthesized_email",
    regex=r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+(?=\s*\([\w.\-]+@[\w.\-]+\.\w+\))",
    score=0.9,
)
_analyzer.registry.add_recognizer(
    PatternRecognizer(supported_entity="PERSON", patterns=[_name_before_email_pattern])
)

REDACTION_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
]


def redact_text(text: str) -> str:
    """Detects and replaces PII in `text` with entity-type placeholders (e.g. <PERSON>)."""
    if not text:
        return text
    results = _analyzer.analyze(text=text, language="en", entities=REDACTION_ENTITIES)
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text
