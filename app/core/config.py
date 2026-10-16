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
        )


settings = Settings()
