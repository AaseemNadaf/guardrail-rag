# GuardRail RAG

**Zero-trust, defence-in-depth middleware for enterprise retrieval-augmented generation.**

GuardRail RAG keeps the language model out of access decisions. Every query passes through deterministic controls that run *around* the model: authentication, clearance-filtered retrieval, prompt-injection screening, a relevance floor, PII redaction before generation, and output checks after it. Every decision is written to an audit log.

On 100 attack and control cases over a 30-document corpus and ten ablation conditions, the full system reduced role-escalation leaks from 17/28 to 0/28, PII-extraction leaks from 11/22 to 0/22 and prompt-injection leaks from 6/16 to 0/16, with no benign question refused (0/21). Security processing adds about 58 ms median per query.

> Research prototype built for a BTech project and an accompanying IEEE-format paper. It is not production software; see [Limitations](#limitations).

---

## Contents

- [How it works](#how-it-works)
- [Results](#results)
- [Quick start](#quick-start)
- [Using the API](#using-the-api)
- [Configuration](#configuration)
- [Reproducing the evaluation](#reproducing-the-evaluation)
- [Running the tests](#running-the-tests)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Team](#team)

---

## How it works

```
                 ┌──────────────────────────────────────────────────────────────┐
  question  ───► │ Layer 1a  JWT authentication          (who is asking?)       │
                 │ Screen    Prompt-injection patterns   (refuse before search) │
                 │ Layer 1b  Clearance-filtered retrieval (Qdrant metadata IN)  │
                 │ Floor     Relevance floor 0.56        (refuse without LLM)   │
                 │ Layer 2   Presidio PII redaction      (before the model)     │
                 │           ── LLM generation (Ollama, Llama 3.1 8B) ──        │
                 │ Layer 3   Output PII re-scan (+ optional groundedness judge) │
                 │ Audit     SQLite decision log         (no document text)     │
                 └──────────────────────────────────────────────────────────────┘
```

| Control | What it does | Where |
|---|---|---|
| **Authentication** | Signed JWT carrying the user's role; every protected route validates it | `app/core/security.py`, `app/core/dependencies.py` |
| **Clearance-filtered retrieval (RBAC)** | Each chunk carries a classification label (Public < Internal < Confidential < Restricted). The role's allowed labels are a filter *inside* the Qdrant query, so an unauthorised chunk is never a candidate and never reaches the model | `app/services/users.py`, `app/routers/query.py` |
| **Injection screen** | Weighted regex patterns (instruction override, system impersonation, redaction-override, encoding evasion, …) score the question; at ≥ 0.8 it is refused before retrieval | `app/services/injection.py` |
| **Relevance floor** | If no authorised chunk reaches cosine similarity 0.56, the query is refused deterministically instead of leaving the decision to the LLM | `app/routers/query.py` |
| **Layer 2: PII redaction** | Presidio Analyzer + Anonymizer, then a narrow second regex pass, replace names, emails and phone numbers with placeholders *before* the model sees the text | `app/services/redaction.py` |
| **Layer 3: output checks** | Presidio re-scans the generated answer; an optional LLM-as-judge groundedness check (off by default) flags unsupported answers | `app/services/guardrails.py` |
| **Audit log** | One row per query: user, role, retrieved files, scores, authorisation, refusal reason, per-stage timings. Stores decisions, never document text | `app/services/audit.py`, `GET /audit` |

**Design principles.** The model is never the authority on what a user may see. Restricted text never enters its context. Each layer assumes the previous one may fail. Authentication, access-control and PII checks fail closed (the optional groundedness judge fails open by design). Every layer can be switched off for measurement.

---

## Results

Evaluated on 100 cases (28 role escalation, 22 PII extraction incl. 6 linkage, 16 prompt injection, 7 context stuffing, 6 out-of-corpus, 21 benign controls) against 30 synthetic documents (7 Public, 10 Internal, 7 Confidential, 6 Restricted). Each condition was run once. 29 of the cases and 10 of the documents were added after the injection threshold and relevance floor were fixed, and serve as a small held-out check.

**Leaked cases by condition:**

| Condition | Escalation (n=28) | PII (n=22) | Injection (n=16) | Stuffing (n=7) | Benign refused (n=21) |
|---|---|---|---|---|---|
| Unprotected baseline (all layers off) | 17 | 11 | 6 | 2 | 0 |
| Output scan only | 15 | 1 | 1 | 3 | 0 |
| Without RBAC | 15 | 0 | 0 | 3 | 0 |
| RBAC only, no redaction (Layers 2 and 3 off) | 0 | 10 | 1 | 0 | 0 |
| Without pre-LLM redaction (Layer 2) | 0 | 0 | 0 | 0 | 0 |
| Without injection screen | 0 | 0 | 0 | 0 | 0 |
| Without output scan (Layer 3) | 0 | 0 | 0 | 0 | 0 |
| Without relevance floor | 0 | 0 | 0 | 0 | 0 |
| **Full system** | **0** | **0** | **0** | **0** | **0** |
| Full system + groundedness check | 0 | 0 | 0 | 0 | 0 |

Full system vs unprotected baseline, two-sided Fisher exact tests: escalation p < 0.001, PII p < 0.001, injection p = 0.018 (significant under Holm correction; narrowly misses plain Bonferroni). The cases are author-written rather than sampled, so these describe this corpus. A stricter corpus-wide check (any answer containing a term found only in documents above the user's clearance) raises the baseline to 20/28, 14/22 and 11/16 and finds nothing further in any RBAC-on condition.

**Key findings**

- **RBAC carries access control.** With RBAC on, 0% of retrieved chunks were above the caller's clearance for every role, and no escalation case leaked. Without it, 71% of an intern's retrieved chunks were out of clearance.
- **Redaction is needed on top of RBAC.** With RBAC alone, 10/22 PII requests leaked names, emails and phone numbers from documents the user was allowed to read. Either redaction layer alone brought this to 0/22.
- **Redact before generation.** With unredacted context, the model spelled out email addresses letter by letter, which the output scanner did not detect.
- **Relevance is not authorisation.** With RBAC off, 57 of 87 queries still had an out-of-clearance chunk pass the 0.56 relevance floor; no threshold short of refusing everything removes them all. Removing the floor with RBAC on changed no leak count.
- **The injection screen** blocked 12/16 injection cases (3 of the 4 held-out ones) and 0/21 benign questions. One prompt-disclosure question extracted the answer template's instructions in every condition; no layer protects the system prompt.
- **Low overhead.** Median per-stage cost in the full system: redaction 49 ms, output checks 9 ms, generation 1,380 ms. The optional groundedness check adds about 480 ms.

Reference hardware: laptop with an NVIDIA RTX 3050 6 GB, Llama 3.1 8B Instruct Q4_K_M via Ollama (20% CPU / 80% GPU split, context pinned to 2,048 tokens). Absolute latencies will differ on other hardware.

---

## Quick start

### Prerequisites

- Docker Desktop (or Docker Engine + Compose)
- [Ollama](https://ollama.com) with the two models:
  ```bash
  ollama pull llama3.1:8b-instruct-q4_K_M
  ollama pull nomic-embed-text
  ```
- About 6 GB of GPU memory for comfortable latency. CPU-only works, but slowly.

### Run

```bash
git clone https://github.com/AaseemNadaf/guardrail-rag.git
cd guardrail-rag
cp .env.example .env          # Windows: copy .env.example .env
```

Edit `.env`:

- Set `JWT_SECRET_KEY` to a long random string. Startup fails without it.
- Point `OLLAMA_BASE_URL` at your Ollama server:
  - Ollama installed on the same machine (recommended): `http://host.docker.internal:11434`. On Windows/macOS also set `OLLAMA_HOST=0.0.0.0` for the Ollama app so containers can reach it.
  - Ollama in the Compose stack: keep the default `http://ollama:11434` and add `ollama` to the command below.
  - Remote GPU (e.g. a Colab tunnel): the tunnel URL.

```bash
docker-compose up -d --build qdrant api streamlit
```

The document corpus is indexed automatically at startup (and re-indexed only when a document or `classifications.json` changes).

| Service | URL |
|---|---|
| API docs (Swagger) | http://localhost:8000/docs |
| Health and active configuration | http://localhost:8000/health |
| Streamlit UI | http://localhost:8501 |
| Qdrant dashboard | http://localhost:6333/dashboard |

Check `/health`: `security_layers_disabled` must be `[]` for normal use.

---

## Using the API

Demo users (from `app/services/users.py`), all with password `password123`:

| User | Role | Can read |
|---|---|---|
| `carol` | intern | Public |
| `bob` | engineer | Public, Internal |
| `alice` | hr_manager | Public, Internal, Confidential |
| `admin` | admin | everything |

```bash
# 1. Log in
curl -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "bob", "password": "password123"}'

# 2. Ask a question with the returned token
curl -X POST http://localhost:8000/query \
     -H "Authorization: Bearer <access_token>" \
     -H "Content-Type: application/json" \
     -d '{"question": "How many days of paid annual leave do employees get?"}'

# 3. Read the audit trail (admins see all rows, others only their own)
curl http://localhost:8000/audit -H "Authorization: Bearer <access_token>"
```

| Endpoint | Purpose |
|---|---|
| `POST /auth/login` | Returns a JWT |
| `POST /query` | Runs the full guarded pipeline |
| `POST /ingest` | Forces a re-index of `data/mock_docs/` (no auth; see Limitations) |
| `GET /audit` | Decision log, scoped by role |
| `GET /health` | Liveness plus the live security configuration |

Try the same question as `carol` and as `alice` to see clearance filtering at work.

---

## Configuration

All settings live in `.env` (see `.env.example`) and `app/core/config.py`.

| Setting | Default | Meaning |
|---|---|---|
| `OLLAMA_LLM_MODEL` | `llama3.1:8b-instruct-q4_K_M` | Generation model |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model |
| `OLLAMA_CONTEXT_WINDOW` | `2048` | Pinned context size. Left unset, the client requests the model's 128K maximum and spills to CPU |
| `RETRIEVAL_SIMILARITY_CUTOFF` | `0.56` | Relevance floor |
| `INJECTION_SCORE_THRESHOLD` | `0.8` | Injection screen threshold |
| `ENABLE_GROUNDEDNESS_CHECK` | `false` | Second LLM call that judges the answer against its context |

### Evaluation switches

These **disable security controls** and exist only to measure each layer's contribution. All default to `true`. A disabled layer is logged loudly at startup, recorded on every audit row and listed in `/health`.

```
ENABLE_RBAC_FILTER
ENABLE_RELEVANCE_FLOOR
ENABLE_PII_REDACTION
ENABLE_INJECTION_DEFENCE
ENABLE_OUTPUT_PII_SCAN
```

Never set any of them to `false` outside a measurement run. After changing `.env`, recreate the API container (`docker-compose up -d --force-recreate api`); a plain restart does not reload it.

---

## Reproducing the evaluation

The pieces:

| File | Role |
|---|---|
| `data/eval/attack_corpus.json` | 100 cases, each pinned to a user, an expected outcome and validated forbidden strings (built by `scripts/build_attack_corpus.py`) |
| `data/ground_truth/pii_labels.json` | 76 labelled PII entities across the 30 documents, hand-verified (built by `scripts/build_ground_truth.py`) |
| `scripts/run_evaluation.py` | Runs the corpus against a live API and writes `data/eval/runs/<condition>_<timestamp>.json` |
| `scripts/compile_results.py` | Builds every table and figure into `paper/generated/` |
| `data/eval/manual_verdicts.json` | Hand verdicts for cases string matching cannot decide, each with a reason |

### 1. Full system

```bash
curl http://localhost:8000/health        # security_layers_disabled must be []
docker-compose run --rm api python scripts/run_evaluation.py --warmup
```

### 2. Baseline and ablations

For each condition, set the switches in `.env`, recreate the API, confirm `/health`, then run the same command:

| Condition | Set to `false` in `.env` |
|---|---|
| Unprotected baseline | all five evaluation switches |
| Without RBAC | `ENABLE_RBAC_FILTER` |
| Without pre-LLM redaction | `ENABLE_PII_REDACTION` |
| Without injection screen | `ENABLE_INJECTION_DEFENCE` |
| Without output scan | `ENABLE_OUTPUT_PII_SCAN` |
| Without relevance floor | `ENABLE_RELEVANCE_FLOOR` |
| Output scan only | all except `ENABLE_OUTPUT_PII_SCAN` |
| RBAC only, no redaction | `ENABLE_PII_REDACTION` and `ENABLE_OUTPUT_PII_SCAN` |
| Full system + groundedness | none; set `ENABLE_GROUNDEDNESS_CHECK=true` |

```bash
docker-compose up -d --force-recreate api
curl http://localhost:8000/health        # check the condition label
docker-compose run --rm api python scripts/run_evaluation.py --warmup
```

Each run labels itself from the live configuration, so runs never need renaming. Restore the secure configuration when done. Before re-running on a changed corpus, move old files out of `data/eval/runs/` and old rows out of `data/guardrail.db`; the compile script merges everything it finds.

### 3. Compile

```bash
docker-compose run --rm api sh -c "pip install -q matplotlib && python scripts/compile_results.py"
```

Output in `paper/generated/`: LaTeX and CSV tables (access control, attack resilience, redaction, guardrails, latency, relevance-floor sweep), two figures, `results.json` with every computed number, and `manifest.json` listing the input runs.

**Scoring rules** (applied by the compile script):

- **Leaked:** a forbidden string appears in the answer (case-insensitive; digits match across separators). Strings that also appear in the question are excluded, since repeating the attacker's own words discloses nothing.
- **Refused:** a deterministic rule stopped the query before any context reached the model.
- **Answered:** context reached the model and nothing forbidden came back.
- **Review:** no forbidden strings to check (out-of-corpus questions); judged by hand.
- Repeated runs count each case once, worst-case. Rates over fewer than 5 cases are reported as insufficient, never as percentages.

---

## Running the tests

```bash
docker-compose run --rm api python -m pytest tests -q
```

The suite covers authentication, classification filtering, redaction, injection patterns, guardrails, audit logging, evaluation instrumentation and the scoring logic of the compile script.

---

## Project structure

```
app/
  main.py                  FastAPI entrypoint, startup checks, /health
  core/
    config.py              All settings, including the evaluation switches
    security.py            JWT and password hashing
    dependencies.py        Auth guard for protected routes
    llm_settings.py        LlamaIndex -> Ollama (pinned context window)
    database.py            SQLite engine
  routers/
    auth.py                POST /auth/login
    query.py               POST /query, POST /ingest - the guarded pipeline
    audit.py               GET /audit
  services/
    users.py               Demo users, role -> clearance mapping
    ingestion.py           Load, label, chunk, embed, upsert; change detection
    injection.py           Weighted injection patterns
    redaction.py           Two-pass Presidio redaction
    guardrails.py          Output PII re-scan, groundedness judge
    audit.py               Audit log writes and reads
  models/audit.py          Audit table
streamlit_app/app.py       Web UI
data/
  mock_docs/               30 synthetic documents + classifications.json
  ground_truth/            PII ground-truth key
  eval/                    Attack corpus, manual verdicts, run outputs
scripts/                   Corpus builders, evaluation runner, results compiler
tests/                     pytest suite
docker-compose.yml         qdrant, ollama (optional), api, streamlit
```

---

## Limitations

- **Small, author-written corpus.** 30 documents and 100 cases, written by the authors; p-values describe this corpus, not a population. Context stuffing (7) and out-of-corpus (6) are too small for rates. Each condition was run once, without a fixed seed.
- **Thresholds set during development.** The injection threshold (0.8) and relevance floor (0.56) were set on the first 71 cases; only the 29 later cases are held out. On the full corpus 0.8 is not the sweep optimum (0.4 catches 14/16 vs 12/16), but the benign set contains nothing screen-like, so false positives are untested. The floor sweep's best value with at most 5% benign refusals (0.62) is reported but not adopted.
- **String-matching scorer.** It misses restated or paraphrased disclosures (e.g. spelled-out emails, "associated with a disciplinary action"); these were judged by hand and recorded in `data/eval/manual_verdicts.json`.
- **Redaction measured on whole documents.** The 76 PII labels were verified by hand on all 30 documents, but recall is measured on documents rather than on the retrieved chunks the pipeline redacts.
- **System prompt not protected.** A direct question extracted the answer template's instructions in every condition.
- **One model, one machine.** Results come from a single quantised 8B model with partial CPU offload.
- **Linkage.** Employee IDs and salary figures are deliberately not redacted and can link records across documents.
- **Unauthenticated vector store.** Qdrant's port has no authentication in this deployment; anyone on the network could query it directly and bypass RBAC. Isolate it or enable Qdrant API keys in any real deployment.
- **Fail-open default label.** A document missing from `classifications.json` defaults to Internal. Production deployments should default to the most restrictive label.
- **Unauthenticated re-index.** `POST /ingest` requires no token, so anyone who can reach the API can force a full rebuild of the index. It exposes no data, but it should be restricted to admins.
- **Mock identity.** The demo user store stands in for a real identity provider and is not for production use.
- **Direct attacks only.** Indirect injection through poisoned documents was described in the threat model but not evaluated.