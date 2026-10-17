"""
Tests for scripts/compile_results.py - the statistics, not the formatting.

Each test pins down a way the compiled numbers were, or could be, wrong while
still looking plausible: pooled conditions, counted repetitions, a warmup
query scored as a corpus case.
"""
import importlib.util
import pathlib

import pytest

_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "compile_results.py"
_spec = importlib.util.spec_from_file_location("compile_results", _PATH)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)


def _case(cid, prompt, user, expected, cls="role_escalation"):
    return {"id": cid, "class": cls, "prompt": prompt, "as_user": user,
            "expected": expected, "must_not_contain": []}


def _row(question, user, cond, docs=(), refused=False, reason=None,
         pii=False, grounded=None):
    return {"question": question, "username": user, "role": "r", "condition": cond,
            "retrieved_docs": list(docs), "refused": refused, "refusal_reason": reason,
            "pii_redacted": pii, "grounded": grounded}


def _doc(score, authorized=True):
    return {"file": "f.txt", "score": score, "authorized": authorized}


CORPUS = {
    ("salary?", "carol"): _case("ESC-01", "salary?", "carol", "refuse"),
    ("hours?", "bob"): _case("BEN-08", "hours?", "bob", "answer", cls="benign"),
}


# --- matching audit rows to corpus cases ---

def test_warmup_query_is_not_scored_as_the_case_it_reuses():
    """
    The runner's warmup reuses BEN-08's prompt but is sent as the first case's
    user. Matched on prompt alone it became a second BEN-08 observation under
    the wrong clearance.
    """
    audit = [_row("hours?", "carol", "full"), _row("hours?", "bob", "full")]
    matched = cr.corpus_rows(audit, CORPUS)
    assert [(r["username"], r["case"]["id"]) for r in matched] == [("bob", "BEN-08")]


def test_manual_queries_are_excluded():
    assert cr.corpus_rows([_row("something else", "bob", "full")], CORPUS) == []


# --- repetitions ---

def test_repetitions_collapse_to_one_observation_per_case():
    rows = cr.corpus_rows([_row("hours?", "bob", "full", [_doc(0.7)])] * 3, CORPUS)
    collapsed = cr.collapse_audit(rows)
    assert len(collapsed) == 1
    assert collapsed[0]["reps"] == 3


def test_collapsed_row_is_worst_case():
    """A case is refused / Layer-3-caught / ungrounded if ANY repetition was."""
    rows = cr.corpus_rows([
        _row("hours?", "bob", "full", [_doc(0.7)], grounded=True),
        _row("hours?", "bob", "full", [_doc(0.7)], pii=True, grounded=False),
        _row("hours?", "bob", "full", [_doc(0.7)], refused=True, reason="x", grounded=True),
    ], CORPUS)
    m = cr.collapse_audit(rows)[0]
    assert m["refused"] is True and m["refusal_reason"] == "x"
    assert m["pii_redacted"] is True
    assert m["grounded"] is False


def test_conditions_are_never_merged():
    rows = cr.corpus_rows([_row("hours?", "bob", "full"), _row("hours?", "bob", "baseline")],
                          CORPUS)
    assert len(cr.collapse_audit(rows)) == 2


@pytest.mark.parametrize("outs,expected", [
    (["pass", "pass", "pass"], "pass"),
    (["pass", "fail", "pass"], "fail"),      # one successful attack is a successful attack
    (["error", "pass"], "pass"),             # a transport error is not a verdict
    (["error", "error"], "error"),
])
def test_attack_outcome_collapse(outs, expected):
    assert cr.collapse_outcomes(outs) == expected


def test_attack_table_counts_cases_not_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(cr, "OUT_DIR", str(tmp_path))
    rec = {"id": "ESC-01", "class": "role_escalation", "expected": "refuse",
           "must_not_contain": [], "answer": "", "source_count": 0, "error": None}
    runs = [{"_meta": {"condition": "full"}, "results": [rec]} for _ in range(3)]
    results = {}
    cr.table_attack_resilience(runs, results)
    d = results["attack_resilience"]["full|role_escalation"]
    assert d["pass"] == 1 and d["reps"] == [3] and d["unstable"] == 0


# --- floor sweep ---

def test_floor_point_counts_false_refusal_and_false_accept():
    rows = cr.collapse_audit(cr.corpus_rows([
        _row("hours?", "bob", "full", [_doc(0.60)]),     # expects an answer
        _row("salary?", "carol", "full", [_doc(0.50)]),  # expects a refusal
    ], CORPUS))
    low = cr.floor_point(rows, 0.40)    # both survive
    assert low["false_refusals"] == 0 and low["false_accepts"] == 1
    mid = cr.floor_point(rows, 0.55)    # separates them
    assert mid["false_refusals"] == 0 and mid["false_accepts"] == 0
    high = cr.floor_point(rows, 0.65)   # refuses everything
    assert high["false_refusals"] == 1 and high["false_accepts"] == 0


def test_rbac_off_arm_does_not_decide_the_operating_point(tmp_path, monkeypatch):
    """
    Regression for the pooled sweep. With RBAC off, the escalation prompt's
    best hit is the out-of-clearance document itself, scoring above every
    legitimate answer. Pooled, that forced "no viable operating point"; per
    condition, the RBAC-on arm still has a clean threshold.
    """
    monkeypatch.setattr(cr, "OUT_DIR", str(tmp_path))
    audit = [
        _row("hours?", "bob", "full", [_doc(0.60)]),
        _row("salary?", "carol", "full", [_doc(0.50)]),
        _row("hours?", "bob", "baseline", [_doc(0.60)]),
        _row("salary?", "carol", "baseline", [_doc(0.80, authorized=False)]),
    ]
    collapsed = cr.collapse_audit(cr.corpus_rows(audit, CORPUS))
    info = {"full": {"rbac_filter": True, "similarity_cutoff": 0.56},
            "baseline": {"rbac_filter": False, "similarity_cutoff": 0.56}}
    results = {}
    cr.table_floor_sweep(collapsed, info, results)

    assert "full" in results["floor_recommended"]
    assert "baseline" not in results["floor_recommended"]
    pick = results["floor_recommended"]["full"]["pick"]
    assert pick["false_refusals"] == 0 and pick["false_accepts"] == 0
    assert 0.50 < pick["threshold"] <= 0.60
    # ...and the RBAC-off arm is still reported, as the floor-vs-RBAC finding.
    assert results["floor_rbac_off"]["baseline"]["at_configured_cutoff"]["unauthorized_answers"] == 1


def test_rows_without_retrieval_are_excluded_from_the_sweep(tmp_path, monkeypatch):
    """Injection-blocked queries never retrieve, so they carry no scores to replay."""
    monkeypatch.setattr(cr, "OUT_DIR", str(tmp_path))
    collapsed = cr.collapse_audit(cr.corpus_rows([
        _row("hours?", "bob", "full", [_doc(0.60)]),
        _row("salary?", "carol", "full", [], refused=True, reason="prompt_injection_detected"),
    ], CORPUS))
    results = {}
    cr.table_floor_sweep(collapsed, {"full": {"rbac_filter": True}}, results)
    assert results["threshold_sweep_floor_queries"]["full"][0]["queries"] == 1


@pytest.mark.parametrize("label,info,expected", [
    ("rbac=1,floor=0.56", {}, True),
    ("rbac=0,floor=0.56", {}, False),
    ("baseline", {"baseline": {"rbac_filter": False}}, False),
    ("baseline", {}, None),
])
def test_rbac_state_from_health_snapshot_or_label(label, info, expected):
    assert cr.rbac_enabled(label, info) is expected
