"""
Runs the attack corpus against a live GuardRail RAG instance and records the
results for compilation.

Writes data/eval/runs/<condition>_<timestamp>.json containing, per case, the
question, the full answer text, the response fields and wall-clock timing.

Why answers are stored here and not in the audit log: the audit table
deliberately holds decisions, not content, so that audit access is not a second
read path around RBAC. Scoring an attack needs the answer text, so it lives in
the evaluation artifact instead - which is a file the team controls, not an API
anyone can query.

Usage, from the repo root:
    python scripts/run_evaluation.py
    python scripts/run_evaluation.py --classes prompt_injection,benign
    python scripts/run_evaluation.py --api http://localhost:8000 --label baseline

The condition label is read from /health so the run file always records the
configuration the server actually had, rather than one passed on the command
line and possibly wrong.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import httpx

CORPUS = "data/eval/attack_corpus.json"
RUNS_DIR = "data/eval/runs"
PASSWORD = "password123"


def login(client: httpx.Client, api: str, username: str) -> str:
    r = client.post(f"{api}/auth/login", json={"username": username, "password": PASSWORD})
    r.raise_for_status()
    return r.json()["access_token"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.getenv("API_BASE_URL", "http://localhost:8000"))
    ap.add_argument("--classes", help="comma-separated subset, e.g. benign,prompt_injection")
    ap.add_argument("--ids", help="comma-separated case ids, e.g. INJ-01,INJ-02")
    ap.add_argument("--label", help="override the condition label recorded in the run file")
    ap.add_argument("--timeout", type=float, default=240.0)
    ap.add_argument("--warmup", action="store_true",
                    help="send one throwaway query first so model load time does not "
                         "land on the first measured case")
    args = ap.parse_args()

    if not os.path.exists(CORPUS):
        sys.exit(f"{CORPUS} not found - build the attack corpus first (step C).")
    corpus = json.load(open(CORPUS, encoding="utf-8"))
    cases = corpus["cases"]

    if args.classes:
        keep = {c.strip() for c in args.classes.split(",")}
        cases = [c for c in cases if c["class"] in keep]
    if args.ids:
        keep = {c.strip() for c in args.ids.split(",")}
        cases = [c for c in cases if c["id"] in keep]
    if not cases:
        sys.exit("No cases selected.")

    with httpx.Client(timeout=args.timeout) as client:
        try:
            health = client.get(f"{args.api}/health").json()
        except httpx.RequestError as e:
            sys.exit(f"Cannot reach the API at {args.api}: {e}")

        condition = args.label or health.get("condition", "unknown")
        disabled = health.get("security_layers_disabled", [])

        print(f"API       : {args.api}")
        print(f"condition : {condition}")
        print(f"model     : {health.get('llm_model')}")
        if disabled:
            print(f"WARNING   : security layers disabled -> {disabled}")
        print(f"cases     : {len(cases)}\n")

        tokens = {}
        for user in sorted({c["as_user"] for c in cases}):
            try:
                tokens[user] = login(client, args.api, user)
            except httpx.HTTPStatusError as e:
                sys.exit(f"Login failed for {user}: {e.response.status_code}")

        if args.warmup:
            print("warmup query (not recorded)...", end=" ", flush=True)
            t0 = time.perf_counter()
            try:
                client.post(f"{args.api}/query", json={"question": "What are the standard working hours?"},
                            headers={"Authorization": f"Bearer {tokens[cases[0]['as_user']]}"})
                print(f"{time.perf_counter() - t0:.1f}s\n")
            except httpx.RequestError as e:
                print(f"failed ({e}); continuing\n")

        results, failures = [], 0
        started = datetime.now(timezone.utc)

        for i, case in enumerate(cases, 1):
            print(f"[{i:3d}/{len(cases)}] {case['id']:8s} {case['as_user']:6s} ", end="", flush=True)
            t0 = time.perf_counter()
            record = {
                "id": case["id"],
                "class": case["class"],
                "as_user": case["as_user"],
                "as_role": case["as_role"],
                "question": case["prompt"],
                "expected": case["expected"],
                "must_not_contain": case["must_not_contain"],
            }
            try:
                r = client.post(
                    f"{args.api}/query",
                    json={"question": case["prompt"]},
                    headers={"Authorization": f"Bearer {tokens[case['as_user']]}"},
                )
                elapsed = time.perf_counter() - t0
                record["http_status"] = r.status_code
                record["wall_sec"] = round(elapsed, 3)
                if r.status_code == 200:
                    body = r.json()
                    record.update({
                        "answer": body.get("answer", ""),
                        "source_count": body.get("source_count"),
                        "allowed_classifications": body.get("allowed_classifications"),
                        "pii_redacted": body.get("pii_redacted"),
                        "grounded": body.get("grounded"),
                        "error": None,
                    })
                    print(f"{elapsed:6.1f}s  src={body.get('source_count')}")
                else:
                    record.update({"answer": "", "error": f"HTTP {r.status_code}: {r.text[:200]}"})
                    failures += 1
                    print(f"{elapsed:6.1f}s  HTTP {r.status_code}")
            except httpx.RequestError as e:
                elapsed = time.perf_counter() - t0
                record.update({
                    "http_status": None, "wall_sec": round(elapsed, 3),
                    "answer": "", "error": f"{type(e).__name__}: {e}",
                })
                failures += 1
                print(f"{elapsed:6.1f}s  FAILED ({type(e).__name__})")

            results.append(record)

        finished = datetime.now(timezone.utc)

    os.makedirs(RUNS_DIR, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in condition)
    path = os.path.join(RUNS_DIR, f"{safe}_{stamp}.json")

    payload = {
        "_meta": {
            "condition": condition,
            "api": args.api,
            "health": health,
            "started": started.isoformat(),
            "finished": finished.isoformat(),
            "duration_sec": round((finished - started).total_seconds(), 1),
            "case_count": len(results),
            "failures": failures,
            "warmup": args.warmup,
            "corpus_case_count": corpus["_meta"]["case_count"],
            "subset": bool(args.classes or args.ids),
        },
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"\nWrote {path}")
    print(f"  {len(results)} cases in {payload['_meta']['duration_sec']}s, {failures} failures")
    if failures:
        print("  NOTE: failed cases are recorded with an error and excluded from scoring.")
    return 1 if failures == len(results) else 0


if __name__ == "__main__":
    sys.exit(main())
