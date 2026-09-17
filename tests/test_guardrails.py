"""
Tests for Layer 3: output guardrails. No Qdrant/Ollama needed - the
groundedness tests use a fake judge LLM.
"""
from app.services.guardrails import (
    GuardrailResult,
    apply_output_guardrails,
    check_groundedness,
    has_context,
    scrub_output_pii,
)


class FakeLLM:
    """Stands in for Ollama. Returns a canned verdict, or raises if told to."""

    def __init__(self, verdict: str = "GROUNDED", raises: bool = False):
        self.verdict = verdict
        self.raises = raises
        self.calls = 0

    def complete(self, prompt: str):
        self.calls += 1
        if self.raises:
            raise RuntimeError("simulated LLM failure")
        return self.verdict


class FakeNode:
    def __init__(self, text: str):
        self._text = text

    def get_content(self):
        return self._text


class FakeNodeWithScore:
    def __init__(self, text: str):
        self.node = FakeNode(text)


# --- empty-context gate ---

def test_has_context_false_for_empty_list():
    assert has_context([]) is False


def test_has_context_true_when_nodes_present():
    assert has_context([FakeNodeWithScore("some text")]) is True


# --- output PII re-scan ---

def test_scrub_output_pii_catches_leaked_name_and_email():
    answer = "You should contact Priya Sharma (priya.sharma@guardrailcorp.com) about this."
    scrubbed, leaked = scrub_output_pii(answer)
    assert leaked is True
    assert "Priya Sharma" not in scrubbed
    assert "priya.sharma@guardrailcorp.com" not in scrubbed


def test_scrub_output_pii_leaves_clean_answer_untouched():
    answer = "Employees receive 18 days of paid annual leave per year."
    scrubbed, leaked = scrub_output_pii(answer)
    assert leaked is False
    assert scrubbed == answer


# --- groundedness check ---

def test_groundedness_accepts_grounded_verdict():
    assert check_groundedness("answer", "context", FakeLLM("GROUNDED")) is True


def test_groundedness_rejects_ungrounded_verdict():
    assert check_groundedness("answer", "context", FakeLLM("UNGROUNDED")) is False


def test_groundedness_fails_open_when_judge_errors():
    """
    A flaky judge must not block a legitimate answer. Only the PII and
    access-control checks fail closed - those protect against real
    data exposure, whereas a failed grounding check just means we
    couldn't verify.
    """
    assert check_groundedness("answer", "context", FakeLLM(raises=True)) is True


def test_groundedness_fails_open_on_unparseable_verdict():
    assert check_groundedness("answer", "context", FakeLLM("maybe? I'm not sure")) is True


def test_ungrounded_substring_not_confused_with_grounded():
    """
    'UNGROUNDED' contains 'GROUNDED' as a substring - a naive
    `if "GROUNDED" in verdict` check would wrongly pass it. Confirms
    the UNGROUNDED branch is evaluated first.
    """
    assert check_groundedness("a", "c", FakeLLM("Verdict: UNGROUNDED")) is False


# --- orchestration ---

def test_apply_guardrails_skips_grounding_when_disabled():
    llm = FakeLLM("GROUNDED")
    result = apply_output_guardrails(
        answer="Employees get 18 days of leave.",
        nodes=[FakeNodeWithScore("Employees get 18 days of leave.")],
        llm=llm,
        check_grounding=False,
    )
    assert result.grounded is None
    assert llm.calls == 0  # no second LLM round-trip when disabled


def test_apply_guardrails_runs_grounding_when_enabled():
    llm = FakeLLM("GROUNDED")
    result = apply_output_guardrails(
        answer="Employees get 18 days of leave.",
        nodes=[FakeNodeWithScore("Employees get 18 days of leave.")],
        llm=llm,
        check_grounding=True,
    )
    assert result.grounded is True
    assert llm.calls == 1


def test_apply_guardrails_flags_and_scrubs_leaked_pii():
    result = apply_output_guardrails(
        answer="Contact Priya Sharma (priya.sharma@guardrailcorp.com).",
        nodes=[FakeNodeWithScore("some context")],
        llm=None,
        check_grounding=False,
    )
    assert result.pii_leaked is True
    assert "Priya Sharma" not in result.answer
    assert isinstance(result, GuardrailResult)
