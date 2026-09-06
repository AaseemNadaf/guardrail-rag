"""
GuardRail RAG — FastAPI entrypoint.

Layer ownership:
  - Layer 1 (auth/RBAC)        -> app/routers/auth.py, app/services/rbac.py   (M2)
  - Retrieval + generation      -> app/services/ingestion.py, app/routers/query.py (M1) [Week 2: done]
  - Layer 2 (PII redaction)    -> app/services/redaction.py                   (M2)
  - Layer 3 (output guardrails)-> app/services/guardrails.py                  (M2)
  - Audit logging              -> app/services/audit.py                      (M1/M4)
"""
from fastapi import FastAPI

from app.core.config import settings
from app.core.llm_settings import configure_llama_index
from app.routers import query

app = FastAPI(
    title="GuardRail RAG",
    description="Zero-Trust middleware for secure, PII-safe RAG.",
    version="0.2.0",
)


@app.on_event("startup")
def startup_event():
    """Points LlamaIndex's global Settings at Ollama before any requests come in."""
    configure_llama_index()


@app.get("/health")
def health_check():
    """Basic liveness check — confirms the API is up and config loaded."""
    return {
        "status": "ok",
        "qdrant_collection": settings.qdrant_collection_name,
        "llm_model": settings.ollama_llm_model,
    }


app.include_router(query.router)
