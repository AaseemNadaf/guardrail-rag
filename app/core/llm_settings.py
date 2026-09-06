"""
Configures the global LlamaIndex Settings object to use our local/tunneled
Ollama instance for both generation and embeddings.
"""
from llama_index.core import Settings
from llama_index.llms.ollama import Ollama
from llama_index.embeddings.ollama import OllamaEmbedding

from app.core.config import settings as app_settings


def configure_llama_index() -> None:
    Settings.llm = Ollama(
        model=app_settings.ollama_llm_model,
        base_url=app_settings.ollama_base_url,
        request_timeout=180.0,
    )
    Settings.embed_model = OllamaEmbedding(
        model_name=app_settings.ollama_embed_model,
        base_url=app_settings.ollama_base_url,
        client_kwargs={"timeout": 180.0},
    )