"""
Loads documents from data/mock_docs, tags each with a classification level,
chunks + embeds them via Ollama, and upserts into Qdrant.

Classification comes from data/mock_docs/classifications.json, a filename ->
classification mapping. Any file not listed there defaults to "Internal" -
a safer default than leaving it effectively public.

Ingestion is idempotent and change-detected: ensure_index() hashes the
document contents plus the classification map and skips the rebuild when
nothing has changed, so it's cheap to call on every startup. POST /ingest
still forces an unconditional rebuild when you want one.
"""
import hashlib
import json
import logging
from pathlib import Path

import qdrant_client
from llama_index.core import SimpleDirectoryReader, VectorStoreIndex, StorageContext
from llama_index.vector_stores.qdrant import QdrantVectorStore

from app.core.config import settings
from app.core.llm_settings import configure_llama_index

logger = logging.getLogger("guardrail.ingestion")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "mock_docs"
CLASSIFICATION_MAP_FILE = DATA_DIR / "classifications.json"
MANIFEST_FILE = DATA_DIR.parent / ".ingest_manifest"
DEFAULT_CLASSIFICATION = "Internal"


def get_qdrant_client() -> qdrant_client.QdrantClient:
    return qdrant_client.QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)


def load_classification_map() -> dict:
    if CLASSIFICATION_MAP_FILE.exists():
        return json.loads(CLASSIFICATION_MAP_FILE.read_text())
    return {}


def compute_manifest_hash() -> str:
    """
    Fingerprints the corpus: every document's name and content, plus the
    classification map.

    Hashes CONTENT rather than mtime deliberately - a git checkout or a
    container rebuild rewrites mtimes without changing anything, and that
    would trigger a pointless 20+ second re-embed of the whole corpus.
    Content hashing also catches the case that matters most: a document
    edited in place with the same name and size.
    """
    h = hashlib.sha256()
    for path in sorted(DATA_DIR.glob("*.txt")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    # Classification changes must invalidate the index even when no document
    # text changed - that's exactly the reclassification case where stale
    # metadata would keep granting access at the old level.
    h.update(json.dumps(load_classification_map(), sort_keys=True).encode())
    return h.hexdigest()


def _read_stored_manifest() -> str | None:
    if MANIFEST_FILE.exists():
        return MANIFEST_FILE.read_text().strip() or None
    return None


def _write_manifest(digest: str) -> None:
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(digest)


def build_index() -> VectorStoreIndex:
    """
    Rebuilds the Qdrant collection from scratch, unconditionally.

    The collection is DROPPED first, deliberately. VectorStoreIndex.from_documents()
    appends to an existing collection rather than replacing it, so without this
    every ingest leaves the previous run's points in place. That is a security
    bug, not just wasted space: a document reclassified from Public to
    Confidential keeps its old Public-tagged chunks in the index, and a
    low-clearance user still retrieves them. Reclassification must actually
    revoke access, so the index has to be authoritative rather than cumulative.
    """
    configure_llama_index()  # ensure Settings.llm/embed_model are set regardless of call path

    txt_files = sorted(DATA_DIR.glob("*.txt"))
    if not txt_files:
        raise RuntimeError(
            f"No .txt documents found in {DATA_DIR}. Add at least one before ingesting."
        )

    documents = SimpleDirectoryReader(input_files=[str(f) for f in txt_files]).load_data()

    classification_map = load_classification_map()
    unmapped = []
    for doc in documents:
        filename = Path(doc.metadata.get("file_name", "")).name
        if filename not in classification_map:
            unmapped.append(filename)
        doc.metadata["classification"] = classification_map.get(filename, DEFAULT_CLASSIFICATION)

    if unmapped:
        # Worth surfacing loudly: an unmapped file silently defaults to Internal,
        # so a document intended as Restricted becomes readable by every engineer.
        logger.warning(
            "%d document(s) missing from classifications.json, defaulted to %s: %s",
            len(unmapped), DEFAULT_CLASSIFICATION, ", ".join(sorted(set(unmapped))),
        )

    client = get_qdrant_client()
    if client.collection_exists(settings.qdrant_collection_name):
        client.delete_collection(settings.qdrant_collection_name)
        logger.info(
            "Dropped existing collection '%s' before rebuild (stale classifications "
            "would otherwise survive re-ingest)",
            settings.qdrant_collection_name,
        )

    vector_store = QdrantVectorStore(client=client, collection_name=settings.qdrant_collection_name)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)
    index = VectorStoreIndex.from_documents(documents, storage_context=storage_context)

    _write_manifest(compute_manifest_hash())
    logger.info("Ingested %d documents into '%s'", len(documents), settings.qdrant_collection_name)
    return index


def index_needs_rebuild() -> tuple[bool, str]:
    """
    Returns (needs_rebuild, reason).

    Checks Qdrant state first, then the manifest. Neither alone is sufficient:
    the collection can be gone while the manifest survives (Qdrant volume
    wiped, bind-mounted data dir intact), and the manifest can be gone while
    the collection survives.
    """
    if not list(DATA_DIR.glob("*.txt")):
        return False, "no documents to ingest"

    try:
        client = get_qdrant_client()
        if not client.collection_exists(settings.qdrant_collection_name):
            return True, "collection does not exist"
    except Exception as e:
        return False, f"qdrant unreachable ({e})"

    stored = _read_stored_manifest()
    if stored is None:
        return True, "no stored manifest"
    if stored != compute_manifest_hash():
        return True, "documents or classifications changed"
    return False, "up to date"


def ensure_index() -> bool:
    """
    Ingests only if needed. Returns True if a rebuild ran.

    Never raises. Called at startup, where a failure must not stop the API
    from booting - the Ollama instance is frequently a Colab tunnel that
    isn't up yet, and an embedding failure there would otherwise leave the
    whole service unavailable rather than merely un-indexed. POST /ingest is
    always available to retry once Ollama is reachable.
    """
    try:
        needed, reason = index_needs_rebuild()
        if not needed:
            logger.info("Index check: %s — skipping ingest", reason)
            return False

        logger.info("Index check: %s — rebuilding", reason)
        build_index()
        return True
    except Exception as e:
        logger.warning(
            "Auto-ingest failed (%s). API will start anyway; call POST /ingest to retry "
            "once Ollama is reachable.", e,
        )
        return False


def get_existing_index() -> VectorStoreIndex:
    """Loads the index from the existing Qdrant collection without re-ingesting."""
    configure_llama_index()  # ensure Settings.llm/embed_model are set regardless of call path

    client = get_qdrant_client()
    vector_store = QdrantVectorStore(client=client, collection_name=settings.qdrant_collection_name)
    return VectorStoreIndex.from_vector_store(vector_store)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    build_index()
