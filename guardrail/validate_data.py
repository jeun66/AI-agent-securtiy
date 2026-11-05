"""Validate evaluation candidates without loading a model or approving labels."""
import argparse
from collections import Counter
from datetime import datetime
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import sys
import unicodedata

LABELS = {"benign", "prompt_injection", "jailbreak", "system_prompt_extraction"}
REQUIRED = ("id", "text", "label", "source_id", "family_id", "language", "split",
            "review_status", "annotation_method", "label_reason")
NEAR_THRESHOLD = 0.86
MIN_NEAR_LENGTH = 20


class DataError(ValueError):
    pass


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def review_sha256(row):
    # Approval covers the label and provenance as well as the text.
    fields = {key: row[key] for key in REQUIRED if key != "review_status"}
    encoded = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def canonical_text(text):
    # Match whitespace, casing, width and punctuation variants, including zero-width marks.
    return "".join(c for c in unicodedata.normalize("NFKC", text).casefold() if c.isalnum())


def load_jsonl(path):
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DataError("{}:{} invalid JSON: {}".format(path, number, exc.msg)) from exc
        if not isinstance(row, dict):
            raise DataError("{}:{} expected an object".format(path, number))
        rows.append(row)
    if not rows:
        raise DataError("empty JSONL: {}".format(path))
    return rows


def near_duplicate(left, right):
    if min(len(left), len(right)) < MIN_NEAR_LENGTH:
        return False
    # Also catch copied long payloads placed inside a new wrapper.
    if min(len(left), len(right)) >= 40 and (left in right or right in left):
        return True
    return SequenceMatcher(None, left, right, autojunk=False).ratio() >= NEAR_THRESHOLD


def audit(rows, exclusions, mode="candidate"):
    if mode not in ("candidate", "benchmark"):
        raise DataError("mode must be candidate or benchmark")
    if not rows:
        raise DataError("empty evaluation dataset")
    if not exclusions:
        raise DataError("empty exclusion corpus")
    reference = []
    for row in exclusions:
        if not isinstance(row.get("text"), str) or not canonical_text(row["text"]):
            raise DataError("exclusion corpus contains an empty/non-text row")
        for field in ("source_ids", "family_ids", "origins"):
            if not isinstance(row.get(field), list) or not all(
                    isinstance(v, str) and v.strip() for v in row[field]):
                raise DataError("malformed exclusion {}".format(field))
        if not row["origins"]:
            raise DataError("exclusion row requires an origin")
        reference.append((canonical_text(row["text"]), row))
    old_sources = {v for _, r in reference for v in r["source_ids"]}
    old_families = {v for _, r in reference for v in r["family_ids"]}
    ids, texts, approved = set(), [], 0
    source_families, family_sources = {}, {}
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise DataError("row {} is not an object".format(index))
        for field in REQUIRED:
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise DataError("row {} requires nonempty string {}".format(index, field))
        rid = row["id"]
        if rid in ids:
            raise DataError("duplicate id: " + rid)
        ids.add(rid)
        if row["label"] not in LABELS:
            raise DataError("unknown label: " + rid)
        if row["split"] != "eval" or row["language"] not in {"ko", "en"}:
            raise DataError("unknown split/language: " + rid)
        if row["review_status"] not in {"pending", "approved"}:
            raise DataError("unknown/rejected review status: " + rid)
        if row["annotation_method"] != "assistant_authored_synthetic":
            raise DataError("this candidate set must disclose synthetic authorship: " + rid)
        if row["review_status"] == "approved":
            for field in ("reviewer", "reviewed_at", "reviewed_record_sha256"):
                if not isinstance(row.get(field), str) or not row[field].strip():
                    raise DataError("approved row lacks {}: {}".format(field, rid))
            if row.get("reviewer_role") != "human":
                raise DataError("human review required: " + rid)
            try:
                timestamp = datetime.fromisoformat(row["reviewed_at"].replace("Z", "+00:00"))
            except ValueError as exc:
                raise DataError("invalid review timestamp: " + rid) from exc
            if timestamp.tzinfo is None:
                raise DataError("review timestamp requires timezone: " + rid)
            if row["reviewed_record_sha256"] != review_sha256(row):
                raise DataError("record changed after review: " + rid)
            approved += 1
        elif mode == "benchmark":
            raise DataError("human review pending: " + rid)
        if row["source_id"] in old_sources or row["family_id"] in old_families:
            raise DataError("source/family overlaps previous material: " + rid)
        # A translated pair belongs to one source and family. IDs are author assertions,
        # not an automated proof that independently named templates are unrelated.
        previous = source_families.setdefault(row["source_id"], row["family_id"])
        if previous != row["family_id"]:
            raise DataError("one source has inconsistent family metadata: " + rid)
        previous = family_sources.setdefault(row["family_id"], row["source_id"])
        if previous != row["source_id"]:
            raise DataError("one family has inconsistent source metadata: " + rid)
        normalized = canonical_text(row["text"])
        if not normalized:
            raise DataError("empty normalized text: " + rid)
        for other_id, other_text in texts:
            if normalized == other_text or near_duplicate(normalized, other_text):
                raise DataError("duplicate/near-duplicate eval texts: {} / {}".format(rid, other_id))
        for old_text, old_row in reference:
            if normalized == old_text or near_duplicate(normalized, old_text):
                raise DataError("text overlaps previous material: {} / {}".format(rid, old_row["origins"][0]))
        texts.append((rid, normalized))
    present = {r["label"] for r in rows}
    if present != LABELS:
        raise DataError("all four labels must be present")
    return {
        "schema_valid": True, "mode": mode, "rows": len(rows),
        "label_counts": dict(sorted(Counter(r["label"] for r in rows).items())),
        "binary_counts": {"benign": sum(r["label"] == "benign" for r in rows),
                          "attack": sum(r["label"] != "benign" for r in rows)},
        "language_counts": dict(sorted(Counter(r["language"] for r in rows).items())),
        "source_count": len(source_families), "family_count": len(family_sources),
        "approved_rows": approved, "pending_rows": len(rows) - approved,
        "reference_texts": len(reference), "exact_or_heuristic_overlap": False,
        "ready_for_benchmark": mode == "benchmark" and approved == len(rows),
        "scope": "small_assistant_authored_synthetic_set_not_external_benchmark",
        "overlap_limits": "known project material only; heuristic cannot prove semantic or pretraining independence",
        "model_inference_executed": False, "training_executed": False,
    }


def audit_files(data, manifest_path, mode):
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = manifest_path.parent
    exclusion_path = root / manifest["exclusion_file"]
    if sha256_file(exclusion_path) != manifest["exclusion_sha256"]:
        raise DataError("exclusion corpus checksum mismatch")
    expected = manifest["candidate_sha256"] if mode == "candidate" else manifest.get("evaluation_sha256")
    if not expected or (mode == "benchmark" and manifest.get("human_review_complete") is not True):
        raise DataError("evaluation is not reviewed and frozen")
    if sha256_file(data) != expected:
        raise DataError("dataset checksum mismatch; review changes and explicitly refreeze")
    result = audit(load_jsonl(data), load_jsonl(exclusion_path), mode)
    result.update({"data_sha256": sha256_file(data),
                   "exclusion_sha256": manifest["exclusion_sha256"],
                   "base_commit": manifest["base_commit"]})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument("--data", type=Path)
    parser.add_argument("--manifest", type=Path, default=root / "data_manifest.json")
    parser.add_argument("--mode", choices=("candidate", "benchmark"), default="candidate")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    data = args.data or root / ("eval.candidate.jsonl" if args.mode == "candidate" else "eval.jsonl")
    try:
        report = audit_files(data, args.manifest, args.mode)
    except (DataError, OSError, ValueError, KeyError) as exc:
        print("DATA_VALIDATION_FAILED: " + str(exc), file=sys.stderr)
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
