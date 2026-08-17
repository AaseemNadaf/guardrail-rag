# GuardRail RAG

Zero-Trust middleware for RAG pipelines: JWT-based RBAC, NER-driven PII
redaction, and output validation.

## Week 1 Setup (do this first, everyone)

1. **Clone the repo** and `cd` into it.
2. **Copy the env template:**
   ```bash
   cp .env.example .env
   ```
   Fill in `JWT_SECRET_KEY` with any random string for now (real key rotation comes later).
3. **IdeaPad Slim 5i only:** edit `OLLAMA_BASE_URL` in `.env` to point at
   either the reference machine's LAN IP or your Colab/ngrok tunnel,
   instead of the local `ollama` container.
4. **Start everything:**
   ```bash
   docker-compose up --build
   ```
5. **Verify it worked:**
   - API health check: http://localhost:8000/health
   - Streamlit UI: http://localhost:8501 (click "Check API connection")
   - Qdrant dashboard: http://localhost:6333/dashboard

6. **Pull the models** (on whichever machine runs Ollama):
   ```bash
   docker exec -it guardrail-ollama ollama pull llama3.1:8b-instruct-q4_K_M
   docker exec -it guardrail-ollama ollama pull nomic-embed-text
   ```

7. **Run the test suite** to confirm your local setup is correct:
   ```bash
   pip install -r requirements.txt
   pytest
   ```

## Project Structure

```
app/
  main.py          # FastAPI entrypoint
  routers/         # API route handlers (M1 owns retrieval/query routes, M2 owns auth)
  services/         # Business logic: retrieval, redaction, generation, guardrails, audit
  models/          # Pydantic schemas / DB models
  core/            # Config, shared utilities
streamlit_app/
  app.py           # Frontend (M4)
tests/             # pytest suite (M3)
data/mock_docs/    # Synthetic dataset goes here (M3)
```

## Ownership Map

| Area | Owner |
|---|---|
| FastAPI routing, RAG pipeline, retrieval | M1 |
| JWT auth, PII redaction, output guardrails | M2 |
| Datasets, tests, red-teaming | M3 |
| Streamlit UI, audit log viewer, paper | M4 |

See `GuardRail_RAG_Sprint_Plan.md` for the full 16-week schedule.
