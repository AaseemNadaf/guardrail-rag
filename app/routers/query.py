"""
All three guardrail layers are live on this endpoint, and every request is
written to the audit log - including refusals, which are the most important
entries to have a record of.

Layer 1 (pre-retrieval): JWT auth + RBAC metadata filter.
Layer 2 (post-retrieval): PII redaction before the LLM sees anything.
Layer 3 (post-generation): relevance floor + empty-context refusal, output
PII re-scan, optional groundedness check.

Retrieval and generation are separate steps (not one query_engine.query()
call) specifically so Layers 2 and 3 can sit between and after them.

The query embedding is computed explicitly rather than left to the retriever,
so embedding time and vector-search time are measured separately. LlamaIndex
reuses a QueryBundle's embedding when one is supplied, so this costs nothing
and is not a duplicate call.

Each layer can be switched off for an evaluation baseline arm (see the
EVALUATION TOGGLES block in app/core/config.py). Toggles are read per request
and recorded on every audit row, so a row always states the configuration
that produced it.
"""
import json
import logging
import time

import qdrant_client
from fastapi import APIRouter, Depends, HTTPException
from llama_index.core import Settings
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.response_synthesizers import get_response_synthesizer
from llama_index.core.schema import QueryBundle
from llama_index.core.vector_stores import MetadataFilter, MetadataFilters, FilterOperator
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_session
from app.core.dependencies import get_current_user
from app.services.audit import record_query
from app.services.guardrails import (
    REFUSAL_MESSAGE,
    apply_output_guardrails,
    has_context,
)
from app.services.ingestion import build_index, get_existing_index
from app.services.injection import BLOCK_MESSAGE as INJECTION_BLOCK_MESSAGE
from app.services.injection import detect_injection
from app.services.redaction import redact_text
from app.services.users import get_allowed_classifications

router = APIRouter()
logger = logging.getLogger("guardrail.query")

SIMILARITY_TOP_K = 3


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    source_count: int
    allowed_classifications: list[str]
    pii_redacted: bool = False
    grounded: bool | None = None


def _describe_nodes(nodes, allowed: list[str], kept_ids: set[str] | None = None) -> list[dict]:
    """
    One record per retrieved chunk: file, classification, score, and whether it
    survived the relevance floor. This is the evidence behind the paper's
    Layer 1 claim - counts alone cannot show that nothing above clearance was
    ever returned.
    """
    out = []
    for n in nodes:
        classification = n.node.metadata.get("classification")
        out.append({
            "file": n.node.metadata.get("file_name"),
            "classification": classification,
            "score": round(n.score, 4) if n.score is not None else None,
            "authorized": classification in allowed,
            "kept": None if kept_ids is None else (n.node.node_id in kept_ids),
        })
    return out


@router.post("/ingest")
def ingest_documents():
    """One-time (or repeatable) trigger to (re)build the Qdrant index from data/mock_docs."""
    try:
        build_index()
        return {"status": "ok", "message": "Documents ingested into Qdrant."}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/query", response_model=QueryResponse)
def query(
    request: QueryRequest,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """RBAC-filtered retrieval -> relevance floor -> redaction -> generation -> output guardrails."""
    started = time.perf_counter()
    stage_ms: dict[str, float] = {}

    client = qdrant_client.QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)
    collections = [c.name for c in client.get_collections().collections]
    if settings.qdrant_collection_name not in collections:
        raise HTTPException(status_code=400, detail="No index found. Call POST /ingest first.")

    # Clearance is computed even when the RBAC filter is disabled: in the
    # baseline arm we still need to know what the user SHOULD have been able
    # to see, or there is nothing to measure unauthorised retrieval against.
    allowed = get_allowed_classifications(current_user["role"])

    # --- Layer 1: prompt injection screening ---
    # Deliberately first. A blocked query never reaches the embedder, the
    # vector store or the LLM, so the block costs one regex pass instead of a
    # retrieval and a generation. Screening is also scored and recorded even
    # when the defence is switched off, so the baseline arm still produces the
    # data needed to compare the two.
    t0 = time.perf_counter()
    injection = detect_injection(request.question, settings.injection_score_threshold)
    stage_ms["injection"] = (time.perf_counter() - t0) * 1000

    if injection.blocked and settings.enable_injection_defence:
        logger.warning(
            "Layer 1 injection block — user=%s score=%.1f patterns=%s",
            current_user["username"], injection.score, injection.matches,
        )
        record_query(
            session,
            username=current_user["username"],
            role=current_user["role"],
            allowed_classifications=allowed,
            question=request.question,
            retrieved_count=0,
            kept_count=0,
            refused=True,
            refusal_reason="prompt_injection_detected",
            condition=settings.condition_label,
            injection_score=injection.score,
            injection_patterns=injection.summary,
            response_time_sec=time.perf_counter() - started,
            stage_ms=stage_ms,
        )
        return QueryResponse(
            answer=INJECTION_BLOCK_MESSAGE,
            source_count=0,
            allowed_classifications=allowed,
        )

    rbac_filter = None
    if settings.enable_rbac_filter:
        rbac_filter = MetadataFilters(
            filters=[MetadataFilter(key="classification", value=allowed, operator=FilterOperator.IN)]
        )

    index = get_existing_index()

    # --- embedding (timed separately from the vector search) ---
    t0 = time.perf_counter()
    query_embedding = Settings.embed_model.get_query_embedding(request.question)
    stage_ms["embed"] = (time.perf_counter() - t0) * 1000
    query_bundle = QueryBundle(query_str=request.question, embedding=query_embedding)

    # --- Layer 1: RBAC-filtered retrieval ---
    t0 = time.perf_counter()
    retriever = index.as_retriever(similarity_top_k=SIMILARITY_TOP_K, filters=rbac_filter)
    nodes = retriever.retrieve(query_bundle)
    stage_ms["retrieve"] = (time.perf_counter() - t0) * 1000

    retrieved_count = len(nodes)
    top_score = max((n.score for n in nodes if n.score is not None), default=None)
    retrieved_before_floor = list(nodes)

    unauthorized = [n for n in nodes if n.node.metadata.get("classification") not in allowed]
    if unauthorized:
        # Never expected with the filter on. Logged at WARNING so it is visible
        # without reading the audit table, because in a secured run this means
        # Layer 1 has failed.
        logger.warning(
            "ACCESS CONTROL: %d chunk(s) above clearance returned for user=%s (clearance=%s, rbac=%s): %s",
            len(unauthorized), current_user["username"], allowed,
            "on" if settings.enable_rbac_filter else "OFF",
            [n.node.metadata.get("file_name") for n in unauthorized],
        )

    logger.info(
        "Retrieval scores (user=%s, clearance=%s, cutoff=%.2f, condition=%s, q=%r):\n%s",
        current_user["username"], allowed, settings.retrieval_similarity_cutoff,
        settings.condition_label, request.question,
        "\n".join(
            f"  score={n.score:.4f} classification={n.node.metadata.get('classification')} "
            f"file={n.node.metadata.get('file_name')}"
            for n in nodes
        ) or "  (no nodes retrieved)",
    )

    # --- relevance floor ---
    # Vector search returns nearest neighbours regardless of how weak the match
    # is, so without this the system always has "context" and refusal falls to
    # the LLM - the LLM-as-gatekeeper pattern this architecture rejects.
    t0 = time.perf_counter()
    if settings.enable_relevance_floor:
        nodes = SimilarityPostprocessor(
            similarity_cutoff=settings.retrieval_similarity_cutoff
        ).postprocess_nodes(nodes)
    stage_ms["floor"] = (time.perf_counter() - t0) * 1000
    logger.info(
        "Relevance floor kept %d/%d nodes at cutoff %.2f (floor=%s)",
        len(nodes), retrieved_count, settings.retrieval_similarity_cutoff,
        "on" if settings.enable_relevance_floor else "OFF",
    )

    kept_ids = {n.node.node_id for n in nodes}
    retrieved_docs = _describe_nodes(retrieved_before_floor, allowed, kept_ids)

    audit_common = dict(
        username=current_user["username"],
        role=current_user["role"],
        allowed_classifications=allowed,
        question=request.question,
        retrieved_count=retrieved_count,
        top_score=top_score,
        retrieved_docs=retrieved_docs,
        unauthorized_retrieved=len(unauthorized),
        condition=settings.condition_label,
        injection_score=injection.score,
        injection_patterns=injection.summary,
    )

    # --- Layer 3 (pre-generation gate) ---
    # With no authorized, relevant context the LLM must not answer at all -
    # otherwise it answers from its own weights, handing the user a plausible
    # answer that never touched the knowledge base. That is an access-control
    # bypass, not a UX detail.
    if not has_context(nodes):
        logger.info(
            "Layer 3 refusal — no authorized relevant context for user=%s (clearance=%s)",
            current_user["username"], allowed,
        )
        record_query(
            session,
            kept_count=0,
            refused=True,
            refusal_reason="no_relevant_authorized_context",
            response_time_sec=time.perf_counter() - started,
            stage_ms=stage_ms,
            **audit_common,
        )
        return QueryResponse(
            answer=REFUSAL_MESSAGE,
            source_count=0,
            allowed_classifications=allowed,
        )

    # --- Layer 2: redact PII before the LLM sees any chunk ---
    t0 = time.perf_counter()
    if settings.enable_pii_redaction:
        for i, node_with_score in enumerate(nodes):
            original = node_with_score.node.get_content()
            redacted = redact_text(original)
            node_with_score.node.set_content(redacted)
            # DEBUG: visible via `docker-compose logs api`, never returned in a
            # response and never written to the audit log. Remove or gate behind
            # a DEBUG flag once redaction is no longer being actively verified.
            logger.info(
                "Layer 2 redaction — node %d/%d (user=%s):\n--- BEFORE ---\n%s\n--- AFTER ---\n%s",
                i + 1, len(nodes), current_user["username"], original, redacted,
            )
    else:
        logger.warning("Layer 2 redaction is OFF — chunks reach the LLM unredacted")
    stage_ms["redact"] = (time.perf_counter() - t0) * 1000

    # --- generation, using only the (redacted) nodes ---
    t0 = time.perf_counter()
    synthesizer = get_response_synthesizer(llm=Settings.llm)
    response = synthesizer.synthesize(request.question, nodes=nodes)
    stage_ms["generate"] = (time.perf_counter() - t0) * 1000

    # --- Layer 3 (post-generation): re-scan output, optionally check grounding ---
    t0 = time.perf_counter()
    result = apply_output_guardrails(
        answer=str(response),
        nodes=nodes,
        llm=Settings.llm,
        check_grounding=settings.enable_groundedness_check,
    )
    stage_ms["guardrails"] = (time.perf_counter() - t0) * 1000

    record_query(
        session,
        kept_count=len(nodes),
        pii_redacted=result.pii_leaked,
        refused=False,
        grounded=result.grounded,
        response_time_sec=time.perf_counter() - started,
        stage_ms=stage_ms,
        **audit_common,
    )

    return QueryResponse(
        answer=result.answer,
        source_count=len(nodes),
        allowed_classifications=allowed,
        pii_redacted=result.pii_leaked,
        grounded=result.grounded,
    )
