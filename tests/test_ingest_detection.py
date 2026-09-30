"""
Tests for ingest change detection.

The failure mode that matters here is a FALSE SKIP - deciding the index is
up to date when it isn't. For the classification case that's a security bug,
not a staleness annoyance: the old, more permissive classification stays
live in the index.
"""
import json

import pytest

from app.services import ingestion


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    """Points the ingestion module at a temp corpus instead of the real one."""
    docs = tmp_path / "mock_docs"
    docs.mkdir()
    (docs / "a.txt").write_text("Alpha document content.")
    (docs / "b.txt").write_text("Beta document content.")
    (docs / "classifications.json").write_text(json.dumps({"a.txt": "Public", "b.txt": "Internal"}))

    monkeypatch.setattr(ingestion, "DATA_DIR", docs)
    monkeypatch.setattr(ingestion, "CLASSIFICATION_MAP_FILE", docs / "classifications.json")
    monkeypatch.setattr(ingestion, "MANIFEST_FILE", tmp_path / ".ingest_manifest")
    return docs


def test_hash_is_stable_across_calls(corpus):
    assert ingestion.compute_manifest_hash() == ingestion.compute_manifest_hash()


def test_hash_changes_when_document_content_changes(corpus):
    before = ingestion.compute_manifest_hash()
    (corpus / "a.txt").write_text("Alpha document content, edited.")
    assert ingestion.compute_manifest_hash() != before


def test_hash_changes_when_document_added(corpus):
    before = ingestion.compute_manifest_hash()
    (corpus / "c.txt").write_text("Gamma document.")
    assert ingestion.compute_manifest_hash() != before


def test_hash_changes_when_document_removed(corpus):
    before = ingestion.compute_manifest_hash()
    (corpus / "b.txt").unlink()
    assert ingestion.compute_manifest_hash() != before


def test_hash_changes_when_classification_changes(corpus):
    """
    The security-critical case. Document text is untouched, only the
    classification map changed - if the hash missed this, the index would keep
    serving the document at its old, more permissive level.
    """
    before = ingestion.compute_manifest_hash()
    (corpus / "classifications.json").write_text(
        json.dumps({"a.txt": "Restricted", "b.txt": "Internal"})
    )
    after = ingestion.compute_manifest_hash()
    assert after != before, "reclassification must invalidate the index"


def test_hash_ignores_mtime_only_changes(corpus):
    """
    Touching a file without changing content must NOT invalidate - otherwise
    every git checkout or container rebuild triggers a full re-embed.
    """
    before = ingestion.compute_manifest_hash()
    (corpus / "a.txt").write_text((corpus / "a.txt").read_text())  # rewrite, same content
    assert ingestion.compute_manifest_hash() == before


def test_manifest_roundtrip(corpus):
    assert ingestion._read_stored_manifest() is None
    digest = ingestion.compute_manifest_hash()
    ingestion._write_manifest(digest)
    assert ingestion._read_stored_manifest() == digest


def test_no_documents_means_no_rebuild(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(ingestion, "DATA_DIR", empty)
    monkeypatch.setattr(ingestion, "MANIFEST_FILE", tmp_path / ".ingest_manifest")
    needed, reason = ingestion.index_needs_rebuild()
    assert needed is False
    assert "no documents" in reason


def test_qdrant_unreachable_does_not_request_rebuild(corpus, monkeypatch):
    """
    With Qdrant down we can't tell whether the collection exists, so claiming
    a rebuild is needed would just fail. Report not-needed and let POST /ingest
    handle it once Qdrant is back.
    """
    def boom():
        raise ConnectionError("qdrant down")

    monkeypatch.setattr(ingestion, "get_qdrant_client", boom)
    needed, reason = ingestion.index_needs_rebuild()
    assert needed is False
    assert "unreachable" in reason


def test_ensure_index_never_raises(corpus, monkeypatch):
    """
    Startup must survive any ingest failure - the Ollama tunnel is often down
    when the API boots, and an un-indexed API is far better than one that
    won't start.
    """
    def boom():
        raise RuntimeError("catastrophic failure")

    monkeypatch.setattr(ingestion, "index_needs_rebuild", boom)
    assert ingestion.ensure_index() is False  # returned, did not raise
