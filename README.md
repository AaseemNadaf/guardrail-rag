# GuardRail RAG

Zero-Trust middleware for RAG pipelines: JWT-based RBAC, NER-driven PII
redaction, and output validation.

## Current State (this package)

- ✅ Ingestion pipeline (LlamaIndex + Qdrant), with classification metadata
- ✅ Layer 1: JWT auth + RBAC-filtered retrieval
- ⏳ Layer 2: PII redaction (Presidio) — not yet built
- ⏳ Layer 3: Output guardrails (Guardrails AI) — not yet built
- ⏳ Real Streamlit UI — placeholder only, Mac teammate's file goes in `streamlit_app/app.py`
- ⏳ Real dataset — only 2 sample docs, LOQ teammate's dataset goes in `data/mock_docs/`

## Setup

1. `cp .env.example .env`, set `JWT_SECRET_KEY` to any random string
2. IdeaPad/no-GPU users: point `OLLAMA_BASE_URL` at your Colab/tunnel URL instead of the local `ollama` service
3. `docker-compose up --build qdrant api streamlit` (add `ollama` to the command if you have a local GPU)
4. Check `http://localhost:8000/docs`, `http://localhost:8501`, `http://localhost:6333/dashboard`

## Testing the Pipeline

1. `POST /auth/login` with `{"username": "bob", "password": "password123"}` → copy the `access_token`
2. Click **Authorize** in `/docs`, paste the token
3. `POST /ingest`
4. `POST /query` with `{"question": "What's the leave policy?"}`

Demo users (`app/services/users.py`): `alice` (hr_manager), `bob` (engineer), `carol` (intern), `admin` (admin) — all password `password123`.

## Running Tests

```bash
pip install -r requirements.txt
pytest
```

## Project Structure

```
app/
  main.py              # FastAPI entrypoint, registers routers
  routers/
    auth.py             # POST /auth/login
    query.py            # POST /ingest, POST /query (RBAC-filtered)
  services/
    ingestion.py         # Loads docs, tags classification, embeds, upserts to Qdrant
    users.py             # Mock user store + role->clearance mapping
  core/
    config.py            # pydantic-settings
    security.py          # JWT + password hashing
    dependencies.py      # get_current_user auth guard
    llm_settings.py       # Points LlamaIndex at Ollama
streamlit_app/app.py     # Frontend (placeholder — Mac teammate's real file replaces this)
data/mock_docs/          # Sample docs + classifications.json (LOQ teammate extends this)
tests/                   # pytest suite
```

## Ownership

| Area | Owner |
|---|---|
| Backend (pipeline, auth, RBAC, redaction, guardrails) | You + Claude |
| UI | Mac teammate |
| Synthetic dataset | LOQ teammate |
| Research paper | Victus teammate |
