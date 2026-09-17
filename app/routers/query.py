"""
All three guardrail layers are live on this endpoint.

Layer 1 (pre-retrieval): JWT auth + RBAC. The caller's role determines
their classification clearance, which becomes a Qdrant metadata filter -
chunks above their clearance are never retrieved.

Layer 2 (post-retrieval): PII redaction on retrieved chunks, BEFORE the
LLM sees them.

Layer 3 (post-generation): relevance floor + empty-context refusal,
output PII re-scan, and an optional groundedness check.

Retrieval and generation are separate steps (not one query_engine.query()
call) specifically so Layers 2 and 3 can sit between and after them.
"""
import logging

import qdrant_client
from fastapi import APIRouter, Depends, HTTPException
from llama_index.core import Settings
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.response_synthesizers import get_response_synthesizer
from llama_index.core.vector_stores import MetadataFilter, MetadataFilters, FilterOperator
from pydantic import BaseModel

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.services.guardrails import (
    REFUSAL_MESSAGE,
    apply_output_guardrails,
    has_context,
)
from app.services.ingestion import build_index, get_existing_index
from app.services.redaction import redact_text
from app.services.users import get_allowed_classifications

router = APIRouter()
logger = logging.getLogger("guardrail.query")


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    source_count: int
    allowed_classifications: list[str]
    pii_redacted: bool = False
    grounded: bool | None = None


@router.post("/ingest")
def ingest_documents():
    """One-time (or repeatable) trigger to (re)build the Qdrant index from data/mock_docs."""
    try:
        build_index()
        return {"status": "ok", "message": "Documents ingested into Qdrant."}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/query", response_model=QueryResponse)
def query(request: QueryRequest, current_user: dict = Depends(get_current_user)):
    """RBAC-filtered retrieval -> relevance floor -> redaction -> generation -> output guardrails."""
    client = qdrant_client.QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)
    collections = [c.name for c in client.get_collections().collections]
    if settings.qdrant_collection_name not in collections:
        raise HTTPException(status_code=400, detail="No index found. Call POST /ingest first.")

    allowed = get_allowed_classifications(current_user["role"])
    rbac_filter = MetadataFilters(
        filters=[MetadataFilter(key="classification", value=allowed, operator=FilterOperator.IN)]
    )

    index = get_existing_index()

    # Layer 1: RBAC-filtered retrieval
    retriever = index.as_retriever(similarity_top_k=3, filters=rbac_filter)
    nodes = retriever.retrieve(request.question)

    # Log every score BEFORE filtering. This is the data needed to tune
    # retrieval_similarity_cutoff - guessing a threshold without seeing the
    # real score distribution for this embedding model is how you end up
    # with a cutoff that either refuses everything or nothing.
    logger.info(
        "Retrieval scores (user=%s, clearance=%s, cutoff=%.2f, q=%r):\n%s",
        current_user["username"], allowed, settings.retrieval_similarity_cutoff,
        request.question,
        "\n".join(
            f"  score={n.score:.4f} classification={n.node.metadata.get('classification')} "
            f"file={n.node.metadata.get('file_name')}"
            for n in nodes
        ) or "  (no nodes retrieved)",
    )

    # Relevance floor. Vector search returns nearest neighbours regardless of
    # how weak the match is, so without this the system always has "context"
    # and refusal falls to the LLM - the exact LLM-as-gatekeeper pattern this
    # architecture rejects. Dropping weak matches makes the refusal below a
    # deterministic control instead.
    retrieved_count = len(nodes)
    nodes = SimilarityPostprocessor(
        similarity_cutoff=settings.retrieval_similarity_cutoff
    ).postprocess_nodes(nodes)
    logger.info(
        "Relevance floor kept %d/%d nodes at cutoff %.2f",
        len(nodes), retrieved_count, settings.retrieval_similarity_cutoff,
    )

    # Layer 3 (pre-generation gate): with no authorized, relevant context the
    # LLM must not answer at all - otherwise it answers from its own weights,
    # handing the user a plausible answer that never touched the knowledge
    # base. That is an access-control bypass, not a UX detail.
    if not has_context(nodes):
        logger.info(
            "Layer 3 refusal — no authorized relevant context for user=%s (clearance=%s)",
            current_user["username"], allowed,
        )
        return QueryResponse(
            answer=REFUSAL_MESSAGE,
            source_count=0,
            allowed_classifications=allowed,
        )

    # Layer 2: redact PII in each retrieved chunk before the LLM sees any of it
    for i, node_with_score in enumerate(nodes):
        original = node_with_score.node.get_content()
        redacted = redact_text(original)
        node_with_score.node.set_content(redacted)
        # DEBUG: visible via `docker-compose logs api`, never returned in a
        # response. Remove or gate behind a DEBUG flag once redaction is
        # no longer being actively verified.
        logger.info(
            "Layer 2 redaction — node %d/%d (user=%s):\n--- BEFORE ---\n%s\n--- AFTER ---\n%s",
            i + 1, len(nodes), current_user["username"], original, redacted,
        )

    # Generation, using only the redacted nodes
    synthesizer = get_response_synthesizer(llm=Settings.llm)
    response = synthesizer.synthesize(request.question, nodes=nodes)

    # Layer 3 (post-generation): re-scan output for PII, optionally check grounding
    result = apply_output_guardrails(
        answer=str(response),
        nodes=nodes,
        llm=Settings.llm,
        check_grounding=settings.enable_groundedness_check,
    )

    return QueryResponse(
        answer=result.answer,
        source_count=len(nodes),
        allowed_classifications=allowed,
        pii_redacted=result.pii_leaked,
        grounded=result.grounded,
    )
