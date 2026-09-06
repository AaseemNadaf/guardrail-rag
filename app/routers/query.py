"""
Layer 1 (pre-retrieval auth + RBAC) is now live on this endpoint.

/query requires a valid JWT. The caller's role determines their
classification clearance, which becomes a Qdrant metadata filter -
chunks above their clearance are never retrieved, let alone seen by
the LLM. This is enforcement at the retrieval layer, not a check
bolted on after the fact.

Still missing (coming later): Layer 2 (PII redaction) and Layer 3
(output guardrails) - both M2's work.
"""
import qdrant_client
from fastapi import APIRouter, Depends, HTTPException
from llama_index.core.vector_stores import MetadataFilter, MetadataFilters, FilterOperator
from pydantic import BaseModel

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.services.ingestion import build_index, get_existing_index
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
    """Retrieves RBAC-filtered chunks and generates an answer. No redaction/guardrails yet."""
    client = qdrant_client.QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)
    collections = [c.name for c in client.get_collections().collections]
    if settings.qdrant_collection_name not in collections:
        raise HTTPException(status_code=400, detail="No index found. Call POST /ingest first.")

    allowed = get_allowed_classifications(current_user["role"])
    rbac_filter = MetadataFilters(
        filters=[MetadataFilter(key="classification", value=allowed, operator=FilterOperator.IN)]
    )

    index = get_existing_index()
    query_engine = index.as_query_engine(similarity_top_k=3, filters=rbac_filter)
    response = query_engine.query(request.question)

    return QueryResponse(
        answer=str(response),
        source_count=len(response.source_nodes),
        allowed_classifications=allowed,
    )
