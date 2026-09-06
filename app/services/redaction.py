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
that noise. Extend this list if M3's dataset needs categories not
covered here.
"""
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


def redact_text(text: str) -> str:
    """Detects and replaces PII in `text` with entity-type placeholders (e.g. <PERSON>)."""
    if not text:
        return text
    results = _analyzer.analyze(text=text, language="en", entities=REDACTION_ENTITIES)
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text
