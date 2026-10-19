"""
Centralized, type-safe configuration.
Reads from environment variables / .env — never hardcode secrets here.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # JWT
    # No default on purpose - startup should fail loudly if it's unset rather
    # than silently signing tokens with a predictable key.
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Qdrant
    qdrant_host: str = "qdrant"
    qdrant_port: int = 6333
    qdrant_collection_name: str = "guardrail_docs"

    # Ollama
    ollama_base_url: str = "http://ollama:11434"
    ollama_llm_model: str = "llama3.1:8b-instruct-q4_K_M"
    ollama_embed_model: str = "nomic-embed-text"

    # Context window requested from Ollama on every generation call.
    #
    # MUST be set explicitly. When left unset, LlamaIndex's Ollama client asks
    # the server for the model's MAXIMUM context length and sends that as
    # num_ctx - 131,072 tokens for Llama 3.1. Ollama then allocates a KV cache
    # sized for 128K tokens (~16 GB at fp16) on every request, which cannot fit
    # a consumer GPU, so most of the model spills to CPU and every latency
    # measurement silently describes a degraded configuration.
    #
    # 2048 is sized to the workload: three retrieved chunks from this corpus
    # (largest document ~860 bytes) plus the QA template and question come to
    # well under 1,000 tokens, leaving ~1,000 for the answer. Raise it if the
    # corpus gains longer documents - Ollama truncates an over-long prompt from
    # the START, which would drop retrieved context without any error.
    #
    # 4096 was the first choice, but measured on the reference RTX 3050 (6 GB)
    # it still spilled 25% of the model to CPU - Windows reserves part of the
    # VRAM, so the usable budget is nearer 5.3 GB than 6.
    ollama_context_window: int = 2048

    # Retrieval
    # Vector search returns nearest neighbours, not relevant ones - with no
    # floor, similarity_top_k always returns k documents no matter how poorly
    # they match. That left refusal up to the LLM, which is the
    # LLM-as-gatekeeper pattern this architecture exists to avoid.
    #
    # 0.56 was fitted to a single query pair with a ~0.003 margin between
    # relevant and irrelevant clusters. It is NOT a tuned value - collect more
    # query/role samples before relying on it, and consider a relative
    # threshold (drop nodes far below the top hit) if the clusters overlap.
    retrieval_similarity_cutoff: float = 0.56

    # Layer 1 — prompt injection screening
    # Runs on the question before embedding, so a block costs one regex pass
    # rather than a retrieval and a generation.
    #
    # 0.8 chosen from a sweep over the 71-case attack corpus: 75% of injection
    # cases caught, zero false positives on the 16 benign controls. Lower
    # thresholds catch more (92% at 0.4) but start changing the outcome of
    # other hostile cases; higher ones lose recall fast (58% at 1.0). Patterns
    # were written from the general injection taxonomy, NOT fitted to the
    # corpus, so this recall figure is a real measurement.
    enable_injection_defence: bool = True
    injection_score_threshold: float = 0.8

    # Ingestion
    # Auto-ingest at startup, change-detected via a content hash of the corpus
    # plus classifications.json - a no-op when nothing changed. Set false to
    # manage the index purely through POST /ingest.
    auto_ingest_on_startup: bool = True

    # Layer 3 guardrails
    # The groundedness check costs a second LLM round-trip, roughly doubling
    # /query latency. Default OFF so day-to-day dev stays fast; turn it on for
    # red-teaming runs and for the paper's latency-overhead measurements.
    enable_groundedness_check: bool = False

    # --- EVALUATION TOGGLES -------------------------------------------------
    # These DISABLE SECURITY CONTROLS. They exist solely so the evaluation can
    # run a baseline ("vanilla RAG") arm to measure the guardrails against -
    # without a baseline there is no overhead figure and no attack-success
    # delta, so the paper has nothing to compare. Every one defaults to the
    # secure setting, each disabled layer is logged loudly at startup and
    # recorded on every audit row, and /health reports the live values so a
    # run can never be mistaken for a secured one after the fact.
    #
    # NEVER set these false outside a measurement run.
    enable_rbac_filter: bool = True
    enable_relevance_floor: bool = True
    enable_pii_redaction: bool = True
    # Layer 3's output PII re-scan. Without this toggle a "baseline" arm still
    # scrubbed PII from every answer, so it measured Layer 3 alone rather than
    # an unprotected pipeline - and Layer 2 showed no benefit over it.
    enable_output_pii_scan: bool = True

    # Label for the evaluation arm this process represents, stamped onto every
    # audit row so the compilation script can group runs. Left unset, a label
    # is derived from the toggles above, which is safer than a hand-typed one:
    # a derived label cannot disagree with the configuration that produced it.
    eval_condition: str | None = None

    # Database
    database_url: str = "sqlite:///./data/guardrail.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def security_layers_disabled(self) -> list[str]:
        """Names of the controls currently switched off. Empty in a secure run."""
        off = []
        if not self.enable_rbac_filter:
            off.append("rbac_filter")
        if not self.enable_relevance_floor:
            off.append("relevance_floor")
        if not self.enable_pii_redaction:
            off.append("pii_redaction")
        if not self.enable_injection_defence:
            off.append("injection_defence")
        if not self.enable_output_pii_scan:
            off.append("output_pii_scan")
        return off

    @property
    def condition_label(self) -> str:
        """
        The evaluation arm label. Derived from live config unless overridden,
        so it always describes the run that actually happened.
        """
        if self.eval_condition:
            return self.eval_condition
        return (
            f"rbac={int(self.enable_rbac_filter)}"
            f",floor={self.retrieval_similarity_cutoff if self.enable_relevance_floor else 'off'}"
            f",redact={int(self.enable_pii_redaction)}"
            f",ground={int(self.enable_groundedness_check)}"
            f",inject={self.injection_score_threshold if self.enable_injection_defence else 'off'}"
            # Appended only when off, so labels of runs recorded before this
            # toggle existed still group with new secure runs.
            + ("" if self.enable_output_pii_scan else ",out=0")
        )


settings = Settings()
