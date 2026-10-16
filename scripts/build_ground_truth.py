"""
Builds the ground-truth PII answer key from labels produced by reading the
documents directly. No NER library is involved in deciding what counts as PII -
that circularity would make the evaluated tool score 100% by construction.

Positions are recorded as occurrence_index (the nth exact occurrence of the
string within the document), NOT character offsets. The repo stores LF but
Windows checkouts get CRLF, so byte offsets computed here would not match the
files the evaluation actually reads. Occurrence indices are line-ending
independent, and no labelled span crosses a newline.
"""
import json
import os
import sys

DOCS = "data/mock_docs"
OUT = "data/ground_truth/pii_labels.json"

P, E, T = "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"

# (text, type) per document. Every occurrence of each string is labelled.
LABELS = {
    "attendance_policy.txt": [("hr.ops@guardrailcorp.com", E)],
    "benefits_guide.txt": [
        ("Ritu Sharma", P), ("ritu.sharma@guardrailcorp.com", E),
    ],
    "code_of_conduct.txt": [("ethics@guardrailcorp.com", E)],
    "communication_guidelines.txt": [],
    "data_classification_policy.txt": [
        ("Sneha Nair", P), ("sneha.nair@guardrailcorp.com", E),
    ],
    "disciplinary_procedure.txt": [
        ("Rohan Mehta", P), ("Ananya Reddy", P),
        ("ananya.reddy@guardrailcorp.com", E), ("+91-99887-76655", T),
    ],
    "eng_onboarding.txt": [
        ("it.support@guardrailcorp.com", E), ("Vikram Joshi", P),
        ("vikram.joshi@guardrailcorp.com", E),
    ],
    "exit_policy.txt": [
        ("Karan Malhotra", P), ("karan.malhotra@guardrailcorp.com", E),
    ],
    "expense_reimbursement.txt": [
        ("Sneha Kulkarni", P), ("sneha.kulkarni@guardrailcorp.com", E),
    ],
    "hr_salary_bands.txt": [
        ("Arjun Mehta", P), ("arjun.mehta@guardrailcorp.com", E), ("912-345-6780", T),
        ("Sneha Iyer", P), ("sneha.iyer@guardrailcorp.com", E), ("987-654-3210", T),
        ("Rohan Desai", P), ("rohan.desai@guardrailcorp.com", E), ("911-222-3344", T),
        ("Priya Sharma", P), ("priya.sharma@guardrailcorp.com", E), ("800-123-4567", T),
    ],
    "incident_response.txt": [
        ("Rohan Verma", P), ("rohan.verma@guardrailcorp.com", E),
        ("+91-98765-43210", T), ("security-incident@guardrailcorp.com", E),
    ],
    "it_policy.txt": [
        ("it.support@guardrailcorp.com", E), ("Arjun Desai", P),
        ("arjun.desai@guardrailcorp.com", E),
    ],
    "leave_policy.txt": [
        ("Ananya Reddy", P), ("ananya.reddy@guardrailcorp.com", E),
    ],
    "meeting_norms.txt": [],
    "office_access_policy.txt": [],
    "performance_review.txt": [
        ("Neha Kapoor", P), ("neha.kapoor@guardrailcorp.com", E),
    ],
    "promotion_policy.txt": [
        ("Priya Sharma", P), ("priya.sharma@guardrailcorp.com", E),
    ],
    "recruitment_policy.txt": [
        ("Meera Iyer", P), ("meera.iyer@guardrailcorp.com", E),
        ("+91-98765-12345", T),
    ],
    "remote_work_policy.txt": [],
    "salary_bands.txt": [
        ("Priya Sharma", P), ("priya.sharma@guardrailcorp.com", E),
        ("+91-98765-47210", T),
    ],
}

# Present in the text but deliberately NOT labelled, with the reason. These are
# the evidence for the linkage finding: a stable identifier left intact next to
# a redacted name still identifies the person.
OUT_OF_SCOPE = {
    "benefits_guide.txt": [("₹5 lakhs", "monetary amount"), ("₹25,000", "monetary amount")],
    "data_classification_policy.txt": [("GC-SEC-1021", "employee ID")],
    "disciplinary_procedure.txt": [("GC-EMP-2187", "employee ID, directly linked to a named person and a disciplinary outcome")],
    "exit_policy.txt": [("GC-HR-1156", "employee ID")],
    "hr_salary_bands.txt": [
        ("EMP-1042", "employee ID"), ("EMP-1087", "employee ID"), ("EMP-1093", "employee ID"),
        ("Rs 8,00,000", "monetary amount"), ("Rs 12,00,000", "monetary amount"),
        ("Rs 18,50,000", "monetary amount"), ("Rs 24,00,000", "monetary amount"),
        ("Rs 32,00,000", "monetary amount"), ("Rs 40,00,000", "monetary amount"),
    ],
    "performance_review.txt": [("GC-HR-1098", "employee ID")],
    "salary_bands.txt": [
        ("GC-HR-1042", "employee ID"),
        ("₹6,50,000", "monetary amount"), ("₹9,50,000", "monetary amount"),
        ("₹10,00,000", "monetary amount"), ("₹16,00,000", "monetary amount"),
        ("₹18,50,000", "monetary amount"), ("₹24,00,000", "monetary amount"),
        ("₹28,00,000", "monetary amount"), ("₹36,00,000", "monetary amount"),
    ],
}

RULES = [
    "PERSON covers the name only, never the job title ('Onboarding Coordinator Vikram Joshi' -> 'Vikram Joshi').",
    "EMAIL_ADDRESS includes role mailboxes (ethics@, it.support@, hr.ops@, security-incident@), not only personal ones.",
    "Organisation names ('GuardRail Corp') are not a configured entity type and are not labelled.",
    "Employee IDs are not a configured entity type; recorded under out_of_scope.",
    "Monetary amounts and salary figures are not a configured entity type; recorded under out_of_scope.",
    "'IST' is a timezone abbreviation, not a LOCATION, and is not labelled.",
    "Every occurrence is labelled separately; recall is computed per occurrence.",
    "No LOCATION, CREDIT_CARD, US_SSN or IBAN_CODE instances exist in this corpus.",
]

NOTES = [
    "Corpus is 20 documents, not 21 - the 21st directory entry is classifications.json.",
    "Priya Sharma appears in 3 documents with two different phone numbers (800-123-4567 in hr_salary_bands.txt, +91-98765-47210 in salary_bands.txt) and two employee-ID schemes. This is an inconsistency in the synthetic data, not a labelling decision; it does not affect per-occurrence scoring.",
    "Ananya Reddy appears with different job titles in disciplinary_procedure.txt ('HR Lead') and leave_policy.txt ('HR Operations Executive'). Same note as above.",
    "hr_salary_bands.txt and salary_bands.txt overlap heavily in content but carry different classifications (Internal vs Confidential). Retrieval may return either; the classification label is what matters for access-control scoring.",
    "disciplinary_procedure.txt links employee ID GC-EMP-2187 to a named person and a disciplinary outcome. If the name is redacted but the ID is not, the record remains re-identifiable - see out_of_scope entries.",
]


def main():
    if not os.path.isdir(DOCS):
        sys.exit(f"Run from the repo root; {DOCS} not found.")

    on_disk = sorted(f for f in os.listdir(DOCS) if f.endswith(".txt"))
    if set(on_disk) != set(LABELS):
        sys.exit(f"Document set mismatch.\n  unlabelled: {sorted(set(on_disk) - set(LABELS))}"
                 f"\n  labelled but absent: {sorted(set(LABELS) - set(on_disk))}")

    documents, totals, problems = {}, {}, []

    for fname in on_disk:
        with open(os.path.join(DOCS, fname), encoding="utf-8", newline="") as fh:
            content = fh.read()

        labels = []
        for text, etype in LABELS[fname]:
            start, idx = 0, 0
            found = 0
            while (pos := content.find(text, start)) != -1:
                labels.append({"text": text, "type": etype, "occurrence_index": idx})
                start, idx, found = pos + len(text), idx + 1, found + 1
            if found == 0:
                problems.append(f"{fname}: labelled text not present: {text!r}")

        labels.sort(key=lambda d: content.find(d["text"]))

        oos = []
        for text, reason in OUT_OF_SCOPE.get(fname, []):
            if text not in content:
                problems.append(f"{fname}: out_of_scope text not present: {text!r}")
            else:
                oos.append({"text": text, "reason": reason})

        documents[fname] = {"labels": labels, "out_of_scope": oos}
        for d in labels:
            totals[d["type"]] = totals.get(d["type"], 0) + 1

    if problems:
        print("FAILED verification:")
        for p in problems:
            print("  -", p)
        sys.exit(1)

    payload = {
        "_meta": {
            "description": "Ground-truth PII labels for redaction evaluation (GuardRail RAG)",
            "corpus": DOCS,
            "document_count": len(documents),
            "entity_types": [P, E, T, "LOCATION", "CREDIT_CARD", "US_SSN", "IBAN_CODE"],
            "position_scheme": "occurrence_index: the nth exact occurrence of 'text' within the document. Character offsets are deliberately NOT used - the repo stores LF but Windows checkouts get CRLF, so offsets would not be portable.",
            "method": "Labelled by direct reading of the source documents. No NER library was used to decide what counts as PII, so the key is independent of the tool it evaluates. LLM-drafted; spot-checked by a team member against 6 of the 20 source documents on 2026-10-16, no discrepancies found. The remaining 14 documents are unverified.",
            "rules": RULES,
            "notes": NOTES,
            "totals": totals,
        },
        "documents": documents,
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"Wrote {OUT}")
    print(f"  documents: {len(documents)}  (empty: "
          f"{sum(1 for d in documents.values() if not d['labels'])})")
    print(f"  totals: {totals}  -> {sum(totals.values())} labels")
    print(f"  out_of_scope entries: {sum(len(d['out_of_scope']) for d in documents.values())}")
    print("\nPer document:")
    for f, d in documents.items():
        by = {}
        for l in d["labels"]:
            by[l["type"]] = by.get(l["type"], 0) + 1
        print(f"  {f:34s} {sum(by.values()):2d}  {by or '-'}")


if __name__ == "__main__":
    main()
