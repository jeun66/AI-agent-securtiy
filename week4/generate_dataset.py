import json
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(__file__).resolve().parent / "results" / "w4_report_final.json"
OUT_JSONL = Path(__file__).resolve().parent / "dataset_w4_draft.jsonl"
OUT_REVIEW = Path(__file__).resolve().parent / "review_list.txt"
OUT_SCHEMA = Path(__file__).resolve().parent / "label_schema.md"

with REPORT.open("r", encoding="utf-8") as fh:
    report = json.load(fh)

entries = []
review_items = []

# simple family assignment helper
def family_for(name):
    base = name.split("_")[0]
    return f"fam_{base}"

# helper detect attacker token in proposed args
def proposed_contains_attacker(proposed):
    s = json.dumps(proposed).lower()
    return "attacker" in s or "evil" in s or "exfil" in s

# map attack names to categories
attack_cat_map = {
    "param_escape_read_outside": ["file_read_escape"],
    "indirect_http_injection": ["http_injection"],
    "schema_key_confusion": ["schema_confusion"],
    "param_pollution_extra_prop": ["param_pollution"],
    "confused_deputy_userinfo": ["confused_deputy"],
    "json_inside_file_injection": ["file_based_exfiltration"],
}

# Collect candidates from attacks (use proposed args and trace summary)
for mode, cases in report.get("attacks", {}).items():
    for c in cases:
        name = c.get("name")
        trace = c.get("trace", [])
        # find proposed entry
        proposed = None
        for t in trace:
            if t.get("status") == "proposed":
                proposed = t.get("proposed_args")
                break
        text = f"Attack scenario {name}: proposed={proposed} | trace_last_status={trace[-1].get('status') if trace else None}"
        source = f"attack:{name}"
        family = family_for(name)
        attack_categories = attack_cat_map.get(name, [])
        # safety rules: only mark unsafe if proposed explicitly contains attacker domain or payload
        if proposed and proposed_contains_attacker(proposed):
            safety = "unsafe"
            review = False
        else:
            # ambiguous or scripted cases -> mark for review
            safety = "safe"
            # but some cases are clearly non-attack (e.g., schema_key_confusion) -> review
            if name in ("schema_key_confusion", "param_pollution_extra_prop"):
                review = True
            else:
                review = False
        rec = {
            "id": f"attack_{name}",
            "text": text,
            "source": source,
            "safety_label": safety,
            "attack_categories": attack_categories,
            "family_id": family,
            "annotation_method": "auto-generated-draft",
            "review_status": "needs_review" if review else "auto-draft",
            "split": "unassigned",
        }
        entries.append(rec)
        if review:
            review_items.append(rec)

# Normals
for mode, items in report.get("normal_requests", {}).items():
    for item in items:
        name = item.get("name")
        trace = item.get("trace", [])
        # build text as proposed and any observation-triggered followup
        proposed = None
        for t in trace:
            if t.get("status") == "proposed":
                proposed = t.get("proposed_args")
                break
        followup = None
        for t in trace:
            if t.get("observation_triggered"):
                followup = "observed_followup"
                break
        text = f"Normal request {name}: proposed={proposed} | followup={followup}"
        source = f"normal:{name}"
        family = family_for(name)
        # Normal examples are safe even if taint blocked; they are valid training
        rec = {
            "id": f"normal_{mode}_{name}",
            "text": text,
            "source": source,
            "safety_label": "safe",
            "attack_categories": [],
            "family_id": family,
            "annotation_method": "auto-generated-draft",
            "review_status": "auto-draft",
            "split": "unassigned",
        }
        entries.append(rec)

# provenance tests
for mode, items in report.get("provenance_tests", {}).items():
    for t in items:
        testname = t.get("test")
        trace = t.get("trace", [])
        proposed = None
        for step in trace:
            if step.get("status") == "proposed":
                proposed = step.get("proposed_args")
                break
        raw = t.get("raw")
        text = f"Provenance test {testname}: proposed={proposed} | raw={raw}"
        source = f"provenance:{testname}"
        family = family_for(testname)
        # If raw contains taint sources, mark review (provenance matters)
        review = False
        if isinstance(raw, dict) and any(isinstance(v, dict) and v.get("sources") for v in raw.values()):
            review = True
        rec = {
            "id": f"prov_{mode}_{testname}",
            "text": text,
            "source": source,
            "safety_label": "safe",
            "attack_categories": [],
            "family_id": family,
            "annotation_method": "auto-generated-draft",
            "review_status": "needs_review" if review else "auto-draft",
            "split": "unassigned",
        }
        entries.append(rec)
        if review:
            review_items.append(rec)

# Now assign splits by family to avoid leakage
families = defaultdict(list)
for e in entries:
    families[e["family_id"]].append(e)

family_list = list(families.keys())
# simple deterministic split: first 70% families -> train, next 15% val, rest test
n = len(family_list)
n_train = max(1, int(n * 0.7))
n_val = max(1, int(n * 0.15))
train_fams = set(family_list[:n_train])
val_fams = set(family_list[n_train:n_train + n_val])
test_fams = set(family_list[n_train + n_val:])

for fid, group in families.items():
    if fid in train_fams:
        split = "train"
    elif fid in val_fams:
        split = "val"
    else:
        split = "test"
    for e in group:
        # Do not assign train/val/test to review items; keep them in 'review' split
        if e["review_status"] == "needs_review":
            e["split"] = "review"
        else:
            e["split"] = split

# Validation: check duplicates and family split consistency
ids = [e["id"] for e in entries]
dupe_ids = [i for i in ids if ids.count(i) > 1]

# ensure families are not split across multiple splits
family_split_issues = []
for fid, group in families.items():
    splits = set(e["split"] for e in group)
    if len(splits - {"review"}) > 1:
        family_split_issues.append({"family": fid, "splits": list(splits)})

# Write JSONL
with OUT_JSONL.open("w", encoding="utf-8") as fh:
    for e in entries:
        fh.write(json.dumps(e, ensure_ascii=False) + "\n")

# Write review list
with OUT_REVIEW.open("w", encoding="utf-8") as fh:
    for r in review_items:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")

# Write label schema doc
schema_md = """
# W4 Guardrails Training Dataset — Draft Label Schema

Fields (JSONL): id, text, source, safety_label, attack_categories, family_id, annotation_method, review_status, split

- `safety_label`: one of `safe` or `unsafe`.
  - Only mark `unsafe` when the text contains an explicit malicious command or attacker-controlled payload in the LLM-proposed text itself (e.g., explicit attacker domain, exfil instruction).
  - Do NOT use runtime execution success, taint blocking, or policy decisions to determine `safety_label`.
  - Normal requests or observed external URLs are `safe` even if later blocked by taint.

- `attack_categories`: multi-label list describing attack vector(s) (e.g., `http_injection`, `file_read_escape`). These are orthogonal to safety.

- `review_status`: `needs_review` for ambiguous/scripted cases (excluded from training until human validated), `auto-draft` for auto-generated drafts.

- `split`: one of `train`, `val`, `test`, or `review`. All items sharing the same `family_id` must be in the same split to prevent leakage.

Annotation instructions and examples:
- Examples with explicit attacker URLs in the proposed text -> `unsafe`.
- Cases where only the executed trace contains attacker-controlled URLs but the proposal is benign -> `safe` (but may be marked `needs_review` if provenance matters).
- Schema errors, incorrect argument keys, or techincal failures are not automatically `unsafe` — mark for review instead.

This is a draft. All `needs_review` items must be human-reviewed before being promoted to `train`/`val`/`test`.
"""
with OUT_SCHEMA.open("w", encoding="utf-8") as fh:
    fh.write(schema_md)

# Summaries
counts = defaultdict(int)
for e in entries:
    counts['total'] += 1
    counts[f"split_{e['split']}"] += 1
    counts[f"safety_{e['safety_label']}"] += 1
    for cat in e['attack_categories']:
        counts[f"cat_{cat}"] += 1

# validation results
validation = {
    "duplicate_ids": list(set(dupe_ids)),
    "family_split_issues": family_split_issues,
}

summary = {
    "total_examples": counts['total'],
    "by_split": {k: v for k, v in counts.items() if k.startswith('split_')},
    "by_safety": {k: v for k, v in counts.items() if k.startswith('safety_')},
    "by_attack_category": {k: v for k, v in counts.items() if k.startswith('cat_')},
    "validation": validation,
}

print(json.dumps(summary, ensure_ascii=False, indent=2))

# Also write summary to file
with (Path(__file__).resolve().parent / "dataset_summary.json").open("w", encoding="utf-8") as fh:
    json.dump(summary, fh, ensure_ascii=False, indent=2)

print("Wrote:", OUT_JSONL, OUT_REVIEW, OUT_SCHEMA)
