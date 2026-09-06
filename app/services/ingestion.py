"""
Loads documents from data/mock_docs, tags each with a classification
level, chunks + embeds them via Ollama, and upserts into Qdrant.

Classification comes from data/mock_docs/classifications.json, a
filename -> classification mapping. M3 maintains this file alongside
the documents they generate. Any file not listed there defaults to
"Internal" — safer default than leaving it unclassified/public.

Owner: M1 (backend). Trigger via POST /ingest, or run directly:
    python -m app.services.ingestion
"""
import json
from pathlib import Path

import qdrant_client
from llama_index.core import SimpleDirectoryReader, VectorStoreIndex, StorageContext
from llama_index.vector_stores.qdrant import QdrantVectorStore

from app.core.config import settings
from app.core.llm_settings import configure_llama_index

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "mock_docs"
CLASSIFICATION_MAP_FILE = DATA_DIR / "classifications.json"
DEFAULT_CLASSIFICATION = "Internal"


def get_qdrant_client() -> qdrant_client.QdrantClient:
    return qdrant_client.QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)


def load_classification_map() -> dict:
    if CLASSIFICATION_MAP_FILE.exists():
        return json.loads(CLASSIFICATION_MAP_FILE.read_text())
    return {}


def build_index() -> VectorStoreIndex:
    """Reads docs in data/mock_docs, tags classification, embeds, and upserts to Qdrant."""
    configure_llama_index()  # ensure Settings.llm/embed_model are set regardless of call path

    txt_files = sorted(DATA_DIR.glob("*.txt"))
    if not txt_files:
        raise RuntimeError(
            f"No .txt documents found in {DATA_DIR}. Add at least one before ingesting."
        )

    documents = SimpleDirectoryReader(input_files=[str(f) for f in txt_files]).load_data()

    classification_map = load_classification_map()
    for doc in documents:
        filename = Path(doc.metadata.get("file_name", "")).name
        doc.metadata["classification"] = classification_map.get(filename, DEFAULT_CLASSIFICATION)

    client = get_qdrant_client()
    vector_store = QdrantVectorStore(client=client, collection_name=settings.qdrant_collection_name)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)

    index = VectorStoreIndex.from_documents(documents, storage_context=storage_context)
    return index


def get_existing_index() -> VectorStoreIndex:
    """Loads the index from the existing Qdrant collection without re-ingesting."""
    configure_llama_index()  # ensure Settings.llm/embed_model are set regardless of call path

    client = get_qdrant_client()
    vector_store = QdrantVectorStore(client=client, collection_name=settings.qdrant_collection_name)
    return VectorStoreIndex.from_vector_store(vector_store)


if __name__ == "__main__":
    build_index()
    print(f"Ingested documents from {DATA_DIR} into Qdrant collection '{settings.qdrant_collection_name}'.")
