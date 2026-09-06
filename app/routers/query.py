"""
Layer 1 (pre-retrieval auth + RBAC) and Layer 2 (post-retrieval PII
redaction) are both live on this endpoint.

/query requires a valid JWT. The caller's role determines their
classification clearance (Layer 1), which becomes a Qdrant metadata
filter - chunks above their clearance are never retrieved. Retrieved
chunks are then redacted for PII (Layer 2) BEFORE the LLM ever sees
them, regardless of whether RBAC already scoped them correctly -
defense in depth, not a single point of failure.

Retrieval and generation are done as separate steps (not one
query_engine.query() call) specifically so redaction can happen in
between - the LLM only ever sees post-redaction text.

Still missing: Layer 3 (output guardrails).
"""
import qdrant_client
from fastapi import APIRouter, Depends, HTTPException
from llama_index.core import Settings
from llama_index.core.response_synthesizers import get_response_synthesizer
from llama_index.core.vector_stores import MetadataFilter, MetadataFilters, FilterOperator
from pydantic import BaseModel

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.services.ingestion import build_index, get_existing_index
from app.services.redaction import redact_text
from app.services.users import get_allowed_classifications

router = APIRouter()


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    source_count: int
    allowed_classifications: list[str]


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
    """RBAC-filtered retrieval -> PII redaction -> generation. No output guardrails yet."""
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

    # Layer 2: redact PII in each retrieved chunk before the LLM sees any of it
    for node_with_score in nodes:
        redacted = redact_text(node_with_score.node.get_content())
        node_with_score.node.set_content(redacted)

    # Generation, using only the redacted nodes
    synthesizer = get_response_synthesizer(llm=Settings.llm)
    response = synthesizer.synthesize(request.question, nodes=nodes)

    return QueryResponse(
        answer=str(response),
        source_count=len(nodes),
        allowed_classifications=allowed,
    )

