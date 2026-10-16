"""
Layer 1 (pre-retrieval) — prompt injection screening.

Runs on the incoming question BEFORE embedding or retrieval. A blocked query
never reaches the vector store or the LLM, so a successful block costs one
regex pass rather than a round-trip.

Deterministic by design. The project's whole argument is that security
decisions belong in code rather than in a model's judgement, and an
LLM-as-judge screener would reintroduce exactly the dependency the
architecture rejects. The cost is that a paraphrase the patterns don't cover
gets through; that is a measurable limitation, not a hidden one.

PATTERN PROVENANCE - this matters for the evaluation to mean anything.
These patterns are written from the general prompt-injection taxonomy
(instruction override, persona reassignment, system impersonation, delimiter
escape, prompt disclosure, output-control override, code-execution framing).
They are deliberately NOT written by reading the project's own attack corpus.
Fitting patterns to the test set would make the defence score ~100% by
construction and the resulting number would be meaningless. Expect the
measured catch rate to be well below 100%.

Scoring rather than a binary match: a single strong signal ("ignore all
previous instructions") blocks on its own, while weaker signals that also
occur in legitimate questions ("verbatim", "word for word") need to co-occur
before they block. The threshold is configurable so the precision/recall
trade-off can be swept, the same way the retrieval floor is.
"""
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger("guardrail.injection")

# (name, weight, pattern). Weight >= 1.0 blocks alone at the default threshold.
# Weights below 1.0 are signals that are individually ambiguous - they occur in
# benign questions too - and must co-occur with something else to block.
PATTERNS: list[tuple[str, float, re.Pattern]] = [
    # --- instruction override -------------------------------------------
    ("instruction_override", 1.0, re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}"
        r"\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}"
        r"\b(instruction|rule|directive|prompt|constraint|guideline|polic)",
        re.I)),
    ("instruction_override_short", 1.0, re.compile(
        r"\b(ignore|disregard)\b[^.\n]{0,20}\b(access control|security|redaction|filter)",
        re.I)),

    # --- system / operator impersonation --------------------------------
    ("system_impersonation", 1.0, re.compile(
        r"(^|\n)\s*(#{2,}|<\|?|\[)?\s*(system|operator|admin(istrator)?)\s*"
        r"(override|prompt|instruction|message|:|\||>|#)",
        re.I)),
    ("fake_config_directive", 1.0, re.compile(
        r"\b(redaction|safety|filter|guard(rail)?s?|access[_ ]control|rbac)\w*\s*"
        r"(=|:)\s*(false|off|disabled|0)\b",
        re.I)),
    ("claimed_authorisation", 0.6, re.compile(
        r"\b(you (now )?have permission|you are (now )?authoris?zed|grant(ing)? "
        r"(me )?(restricted|elevated|admin|full)|elevate my access)\b",
        re.I)),

    # --- persona reassignment -------------------------------------------
    ("persona_reassignment", 1.0, re.compile(
        r"\byou are (now|no longer)\b|\b(act|behave|respond) as (if you are |an? )?"
        r"(unrestricted|uncensored|jailbroken|dan\b)|\bpretend (that )?you (are|have)\b",
        re.I)),
    ("roleplay_framing", 0.6, re.compile(
        r"\b(role[- ]?play|let us play|let's play|simulate being|you are a bot called|"
        r"as [A-Z]\w*Bot\b)",
        re.I)),
    ("mode_switch", 1.0, re.compile(
        r"\b(debug|developer|dev|god|maintenance|diagnostic)\s*mode\b",
        re.I)),

    # --- delimiter / context escape -------------------------------------
    ("delimiter_escape", 1.0, re.compile(
        r"</?\s*(context|system|instruction|prompt|document)s?\s*>|"
        r"\[/?(INST|SYS)\]|<\|(im_start|im_end|endoftext)\|>",
        re.I)),

    # --- prompt / context disclosure ------------------------------------
    ("prompt_disclosure", 0.8, re.compile(
        r"\b(repeat|print|show|output|reveal|quote|display)\b[^.\n]{0,40}"
        r"\b(system prompt|your instructions|everything above|all text above|"
        r"initial prompt|the prompt you)",
        re.I)),
    ("context_dump", 0.8, re.compile(
        r"\b(raw|full|entire|complete|unmodified|unfiltered|original)\s+"
        r"(context|chunk|document|retrieved|source text)",
        re.I)),
    ("verbatim_request", 0.4, re.compile(
        r"\b(verbatim|word[- ]for[- ]word|exactly as (it )?(appears|written)|"
        r"character for character)\b",
        re.I)),

    # --- output-control override ----------------------------------------
    ("redaction_override", 1.0, re.compile(
        r"\b(do not|don't|without|no need to|skip|disable|remove|turn off)\b"
        r"[^.\n]{0,25}\b(redact|anonymi[sz]|mask|censor|placeholder)",
        re.I)),
    ("preserve_pii", 0.8, re.compile(
        r"\b(keep|preserve|retain|include|leave)\b[^.\n]{0,40}"
        r"\b(names?|emails?|phone numbers?|proper nouns?|contact details?)\b"
        r"[^.\n]{0,25}\b(intact|unchanged|as (is|written)|exactly)\b",
        re.I)),
    ("redaction_is_a_bug", 0.8, re.compile(
        r"\b(placeholder|redaction|<PERSON>|<EMAIL|masking)\w*\b[^.\n]{0,40}"
        r"\b(bug|glitch|error|mistake|corrupt|broken|malfunction)",
        re.I)),
    ("exempt_claim", 0.6, re.compile(
        r"\b(exempt from|not subject to|excluded from)\b[^.\n]{0,25}"
        r"\b(redaction|filtering|access control|this polic)",
        re.I)),

    # --- encoding evasion -----------------------------------------------
    ("encoding_evasion", 0.6, re.compile(
        r"\b(base64|rot13|hex[- ]?encode|url[- ]?encode|caesar cipher)\b|"
        r"\bspell(ed)? (it |them )?out\b[^.\n]{0,30}\b(letter|character)",
        re.I)),

    # --- code-execution framing -----------------------------------------
    ("code_execution_framing", 0.8, re.compile(
        r"\b(print|exec|eval|console\.log|System\.out)\s*\(\s*[\w.\[\]'\"]*"
        r"(context|chunk|prompt|document|retrieved)",
        re.I)),
]

DEFAULT_THRESHOLD = 1.0

BLOCK_MESSAGE = (
    "This request was blocked because it appears to contain instructions aimed at "
    "overriding the system's security controls. If this was a legitimate question, "
    "please rephrase it."
)


@dataclass
class InjectionResult:
    blocked: bool
    score: float
    matches: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return ",".join(self.matches)


def detect_injection(text: str, threshold: float = DEFAULT_THRESHOLD) -> InjectionResult:
    """
    Scores `text` against the pattern set. Blocks when the summed weight of
    distinct matched patterns reaches `threshold`.

    Weights are summed rather than maxed so that several individually weak
    signals - each of which appears in ordinary questions - can together
    indicate an attempt, without any one of them blocking on its own.
    """
    if not text:
        return InjectionResult(blocked=False, score=0.0)

    score = 0.0
    matched: list[str] = []
    for name, weight, pattern in PATTERNS:
        if pattern.search(text):
            matched.append(name)
            score += weight

    blocked = score >= threshold
    if blocked:
        logger.warning(
            "Prompt injection blocked (score=%.1f, threshold=%.1f, patterns=%s)",
            score, threshold, matched,
        )
    elif matched:
        logger.info(
            "Prompt injection signals below threshold (score=%.1f < %.1f, patterns=%s)",
            score, threshold, matched,
        )

    return InjectionResult(blocked=blocked, score=round(score, 2), matches=matched)
