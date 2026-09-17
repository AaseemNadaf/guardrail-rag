"""
Centralized, type-safe configuration.
Reads from environment variables / .env — never hardcode secrets here.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # JWT
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
    # they match. That left refusal up to the LLM ("the context doesn't
    # mention that"), which is the LLM-as-gatekeeper pattern this whole
    # architecture exists to avoid. This cutoff drops weak matches so the
    # Layer 3 empty-context refusal fires deterministically instead.
    #
    # NEEDS EMPIRICAL TUNING against the real dataset. Too high and valid
    # queries get refused; too low and it does nothing. Sweeping this value
    # and measuring the precision/recall tradeoff is a paper-worthy
    # experiment in its own right.
    retrieval_similarity_cutoff: float = 0.4

    # Layer 3 guardrails
    # The groundedness check costs a second LLM round-trip, roughly doubling
    # /query latency. Default OFF so day-to-day dev stays fast; turn it on
    # for red-teaming runs and for the paper's latency-overhead measurements.
    enable_groundedness_check: bool = False

    # Database
    database_url: str = "sqlite:///./data/guardrail.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
