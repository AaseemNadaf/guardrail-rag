"""
GuardRail RAG — FastAPI entrypoint.

Layer ownership:
  - Layer 1 (auth/RBAC)        -> app/routers/auth.py, app/core/security.py,
                                   app/core/dependencies.py, app/services/users.py  [done]
  - Retrieval + generation     -> app/services/ingestion.py, app/routers/query.py  [done]
  - Layer 2 (PII redaction)    -> app/services/redaction.py                        (M2)
  - Layer 3 (output guardrails)-> app/services/guardrails.py                       (M2)
  - Audit logging              -> app/services/audit.py                           (M1)
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import settings
from app.core.llm_settings import configure_llama_index
from app.routers import auth, query


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Points LlamaIndex's global Settings at Ollama before any requests come in."""
    configure_llama_index()
    yield


app = FastAPI(
    title="GuardRail RAG",
    description="Zero-Trust middleware for secure, PII-safe RAG.",
    version="0.3.1",
    lifespan=lifespan,
)


@app.get("/health")
def health_check():
    """Basic liveness check — confirms the API is up and config loaded."""
    return {
        "status": "ok",
        "qdrant_collection": settings.qdrant_collection_name,
        "llm_model": settings.ollama_llm_model,
    }


app.include_router(auth.router)
app.include_router(query.router)
