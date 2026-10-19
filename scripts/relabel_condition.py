"""
Renames an evaluation condition in both places it is recorded: the run files
(data/eval/runs/*.json, _meta.condition) and the audit log (audit_log.condition).

Exists for one correction. The first "baseline" arm was recorded with Layer 3's
output PII scan still on - there was no toggle for it yet - so it is not an
unprotected pipeline. Its data is still valid; it is the "everything except
Layer 3" ablation, and should carry the label that says so rather than be
thrown away and re-run.

Usage, from the repo root (inside the container):
    python scripts/relabel_condition.py --from baseline --to "rbac=0,floor=off,redact=0,ground=0,inject=off"
    python scripts/relabel_condition.py --from baseline --to ... --dry-run

Both stores are changed or neither is: run files are rewritten only after the
database update succeeds, and a mismatch between the two is reported.
"""
import argparse
import glob
import json
import sqlite3
import sys

RUNS_GLOB = "data/eval/runs/*.json"
AUDIT_DB = "data/guardrail.db"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", required=True)
    ap.add_argument("--to", dest="dst", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.src == args.dst:
        sys.exit("--from and --to are the same.")

    files = []
    for p in sorted(glob.glob(RUNS_GLOB)):
        with open(p, encoding="utf-8") as fh:
            d = json.load(fh)
        if d["_meta"].get("condition") == args.src:
            files.append((p, d))
        elif d["_meta"].get("condition") == args.dst:
            print(f"NOTE: {p} already uses {args.dst!r}; relabelled rows will merge with it.")

    con = sqlite3.connect(AUDIT_DB)
    try:
        n_rows = con.execute("SELECT COUNT(*) FROM audit_log WHERE condition = ?",
                             (args.src,)).fetchone()[0]
        print(f"run files : {len(files)} with condition {args.src!r}")
        print(f"audit rows: {n_rows} with condition {args.src!r}")
        if not files and not n_rows:
            sys.exit("Nothing to relabel.")
        if args.dry_run:
            print("dry run - nothing changed.")
            return 0

        con.execute("UPDATE audit_log SET condition = ? WHERE condition = ?",
                    (args.dst, args.src))
        con.commit()
    finally:
        con.close()

    for p, d in files:
        d["_meta"]["condition"] = args.dst
        d["_meta"]["relabelled_from"] = args.src
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"  relabelled {p}")

    print(f"Done: {args.src!r} -> {args.dst!r}")
    print("The run file names still contain the old label; the condition inside is what counts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
