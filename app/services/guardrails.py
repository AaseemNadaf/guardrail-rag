"""
Layer 3 (post-generation) — output guardrails.

Runs AFTER the LLM produces an answer, before it reaches the user.
Three independent checks:

1. Empty-context refusal (pre-generation gate). If RBAC filtering left
   zero retrieved chunks, the LLM must not answer at all - otherwise it
   answers from parametric knowledge, which is an actual access-control
   bypass: an unauthorized user gets a plausible answer that never
   touched the knowledge base. This is the check that closes that hole.

2. Output PII re-scan. Re-runs Presidio on the generated answer. Layer 2
   redacts retrieved chunks, but the LLM can still emit PII it inferred,
   reconstructed, or pulled from its own weights. Catching it here is
   defense in depth - Layer 2 failing shouldn't mean PII reaches the user.

3. Groundedness check (LLM-as-judge). Asks the model whether the answer
   is supported by the retrieved context. Catches hallucination.
   Costs a second LLM round-trip, so it's config-toggleable - see
   ENABLE_GROUNDEDNESS_CHECK in app/core/config.py.

Deliberately NOT built on Guardrails AI: its hub ships with zero
bundled validators, and installing any of them requires network access
to hub.api.guardrailsai.com plus a configured auth token. That breaks
offline/reproducible Docker builds, which matters both for the team and
for the paper's reproducibility claims. These checks use Presidio
(already a dependency) and the local Ollama model instead.
"""
import logging
from dataclasses import dataclass

from app.services.redaction import redact_text

logger = logging.getLogger("guardrail.layer3")

REFUSAL_MESSAGE = (
    "I don't have access to any documents that can answer this question. "
    "This may be because the relevant material is outside your access level."
)

_GROUNDEDNESS_PROMPT = """You are a strict fact-checker. Below is a CONTEXT and an ANSWER.

Decide whether every factual claim in the ANSWER is supported by the CONTEXT.
Redaction placeholders like <PERSON> or <EMAIL_ADDRESS> in the CONTEXT are
expected and should not count as unsupported.

Reply with exactly one word: GROUNDED or UNGROUNDED.

CONTEXT:
{context}

ANSWER:
{answer}

Verdict:"""


@dataclass
class GuardrailResult:
    """Outcome of Layer 3. `answer` is the text safe to return to the user."""

    answer: str
    blocked: bool = False
    block_reason: str | None = None
    pii_leaked: bool = False
    grounded: bool | None = None  # None when the groundedness check is disabled


def has_context(nodes) -> bool:
    """False when RBAC filtering left nothing to answer from."""
    return bool(nodes)


def scrub_output_pii(answer: str) -> tuple[str, bool]:
    """
    Re-runs redaction on the generated answer.
    Returns (scrubbed_answer, pii_was_found).
    """
    scrubbed = redact_text(answer)
    return scrubbed, scrubbed != answer


def check_groundedness(answer: str, context: str, llm) -> bool:
    """
    LLM-as-judge groundedness check. Returns True if the answer is
    supported by the context.

    Fails OPEN (returns True) if the judge call errors or returns an
    unparseable verdict - a flaky judge shouldn't block a legitimate
    answer. The PII and access-control checks are the ones that fail
    closed, because those protect against actual data exposure.
    """
    prompt = _GROUNDEDNESS_PROMPT.format(context=context, answer=answer)
    try:
        verdict = str(llm.complete(prompt)).strip().upper()
    except Exception as e:
        logger.warning("Groundedness check failed, defaulting to grounded: %s", e)
        return True

    if "UNGROUNDED" in verdict:
        return False
    if "GROUNDED" in verdict:
        return True

    logger.warning("Unparseable groundedness verdict %r, defaulting to grounded", verdict)
    return True


def apply_output_guardrails(
    answer: str,
    nodes,
    llm=None,
    check_grounding: bool = False,
) -> GuardrailResult:
    """
    Runs the post-generation checks. `nodes` are the retrieved (already
    redacted) nodes the answer was generated from.
    """
    scrubbed, pii_leaked = scrub_output_pii(answer)
    if pii_leaked:
        logger.warning("Layer 3 caught PII in generated output that Layer 2 did not remove")

    grounded = None
    if check_grounding and llm is not None:
        context = "\n\n".join(n.node.get_content() for n in nodes)
        grounded = check_groundedness(scrubbed, context, llm)
        if not grounded:
            logger.warning("Layer 3 flagged answer as ungrounded in retrieved context")

    return GuardrailResult(
        answer=scrubbed,
        pii_leaked=pii_leaked,
        grounded=grounded,
    )
