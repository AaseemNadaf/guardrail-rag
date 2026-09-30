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

    # Database
    database_url: str = "sqlite:///./data/guardrail.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
