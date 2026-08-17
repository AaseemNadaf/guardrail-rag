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

    # Database
    database_url: str = "sqlite:///./data/guardrail.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
