
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


## Dataset status
- Total raw cases before dedupe: 39
- Total cases after dedupe: 20
- Unique original-texts: 8
- Training candidates: 7
- Review candidates (needs human review): 13

Note: This dataset is small and intended as a draft. Keep `needs_review` items separate until human validation.


## Dataset status
- Total raw cases before dedupe: 39
- Total cases after dedupe: 20
- Unique original-texts: 8
- Training candidates: 7
- Review candidates (needs human review): 13

Note: This dataset is small and intended as a draft. Keep `needs_review` items separate until human validation.
