"""
GuardRail RAG — FastAPI entrypoint.

This is intentionally minimal for Week 1. Each layer gets built out
by its owner in later sprints:
  - Layer 1 (auth/RBAC)        -> app/routers/auth.py, app/services/rbac.py   (M2)
  - Retrieval                  -> app/services/retrieval.py                   (M1)
  - Layer 2 (PII redaction)    -> app/services/redaction.py                   (M2)
  - Generation                 -> app/services/generation.py                  (M1)
  - Layer 3 (output guardrails)-> app/services/guardrails.py                  (M2)
  - Audit logging              -> app/services/audit.py                      (M1/M4)
"""
from fastapi import FastAPI

from app.core.config import settings

app = FastAPI(
    title="GuardRail RAG",
    description="Zero-Trust middleware for secure, PII-safe RAG.",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    """Basic liveness check — confirms the API is up and config loaded."""
    return {
        "status": "ok",
        "qdrant_collection": settings.qdrant_collection_name,
        "llm_model": settings.ollama_llm_model,
    }


# Routers get registered here as each layer is built, e.g.:
# from app.routers import query
# app.include_router(query.router)
