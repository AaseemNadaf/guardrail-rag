"""
Tests for the relevance floor applied after RBAC retrieval.

This is the control that makes the Layer 3 empty-context refusal
deterministic rather than leaving refusal to the LLM.
"""
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.schema import NodeWithScore, TextNode

from app.services.guardrails import has_context

CUTOFF = 0.4


def _floor(nodes):
    return SimilarityPostprocessor(similarity_cutoff=CUTOFF).postprocess_nodes(nodes)


def test_weak_matches_are_dropped():
    nodes = [
        NodeWithScore(node=TextNode(text="strong"), score=0.81),
        NodeWithScore(node=TextNode(text="weak"), score=0.22),
    ]
    kept = _floor(nodes)
    assert [n.node.text for n in kept] == ["strong"]


def test_all_weak_matches_yields_no_context():
    """
    The case that matters: an intern asks about Confidential material.
    RBAC leaves only unrelated Public docs, which vector search still
    returns as nearest neighbours. The floor drops them, so the refusal
    fires as a deterministic control instead of depending on the LLM
    deciding to decline.
    """
    nodes = [
        NodeWithScore(node=TextNode(text="unrelated public doc"), score=0.19),
        NodeWithScore(node=TextNode(text="another unrelated one"), score=0.11),
        NodeWithScore(node=TextNode(text="third unrelated one"), score=0.08),
    ]
    assert has_context(_floor(nodes)) is False


def test_strong_matches_survive_and_allow_answering():
    nodes = [
        NodeWithScore(node=TextNode(text="relevant policy text"), score=0.74),
        NodeWithScore(node=TextNode(text="also relevant"), score=0.63),
    ]
    kept = _floor(nodes)
    assert has_context(kept) is True
    assert len(kept) == 2


def test_score_exactly_at_cutoff_is_kept():
    """Pins the boundary so a future cutoff change can't silently flip it."""
    nodes = [NodeWithScore(node=TextNode(text="borderline"), score=CUTOFF)]
    assert len(_floor(nodes)) == 1
