import json
from pathlib import Path
import tempfile
import unittest

from guardrail.validate_data import (
    DataError, audit, audit_files, canonical_text, load_jsonl,
    near_duplicate, review_sha256,
)

ROOT = Path(__file__).resolve().parent


class DataTests(unittest.TestCase):
    def setUp(self):
        self.rows = load_jsonl(ROOT / "eval.candidate.jsonl")
        self.exclusions = load_jsonl(ROOT / "provenance/exclusion_corpus.jsonl")

    def fails(self, rows=None, exclusions=None, message=None, mode="candidate"):
        with self.assertRaisesRegex(DataError, message or ".*"):
            audit(self.rows if rows is None else rows,
                  self.exclusions if exclusions is None else exclusions, mode)

    def approve_for_test(self):
        # Only in memory: these fabricated review stamps test validation, not data approval.
        for row in self.rows:
            row.update(review_status="approved", reviewer="unit-test-human-fixture",
                       reviewer_role="human", reviewed_at="2026-11-05T12:00:00+09:00")
            row["reviewed_record_sha256"] = review_sha256(row)

    def test_committed_candidate_checksums_and_counts(self):
        report = audit_files(ROOT / "eval.candidate.jsonl", ROOT / "data_manifest.json", "candidate")
        self.assertEqual(report["rows"], 24)
        self.assertEqual(report["binary_counts"], {"benign": 12, "attack": 12})
        self.assertEqual(report["language_counts"], {"ko": 12, "en": 12})
        self.assertEqual(report["pending_rows"], 24)
        self.assertEqual(report["source_count"], 12)
        self.assertFalse(report["ready_for_benchmark"])
        self.assertFalse(report["model_inference_executed"])

    def test_pending_rows_cannot_be_benchmarked(self):
        self.fails(mode="benchmark", message="human review pending")

    def test_unfrozen_manifest_cannot_be_benchmarked(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = json.loads((ROOT / "data_manifest.json").read_text(encoding="utf-8"))
            manifest.update(human_review_complete=False, evaluation_sha256=None,
                            exclusion_file=str(ROOT / "provenance/exclusion_corpus.jsonl"))
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(DataError, "not reviewed and frozen"):
                audit_files(ROOT / "eval.candidate.jsonl", path, "benchmark")

    def test_frozen_eval_preserves_the_approved_candidates(self):
        report = audit_files(ROOT / "eval.jsonl", ROOT / "data_manifest.json", "benchmark")
        self.assertEqual(report["approved_rows"], 24)
        self.assertEqual(report["pending_rows"], 0)
        self.assertTrue(report["ready_for_benchmark"])
        rows = load_jsonl(ROOT / "eval.jsonl")
        self.assertEqual([review_sha256(r) for r in rows], [review_sha256(r) for r in self.rows])

    def test_approved_metadata_is_required(self):
        self.rows[0]["review_status"] = "approved"
        self.fails(message="approved row lacks")

    def test_review_requires_human_role(self):
        self.approve_for_test()
        self.rows[0]["reviewer_role"] = "assistant"
        self.fails(mode="benchmark", message="human review required")

    def test_review_covers_label_and_provenance(self):
        self.approve_for_test()
        self.rows[0]["label"] = "jailbreak"
        self.fails(mode="benchmark", message="record changed after review")

    def test_review_timestamp_requires_timezone(self):
        self.approve_for_test()
        self.rows[0]["reviewed_at"] = "2026-11-05T12:00:00"
        self.fails(mode="benchmark", message="requires timezone")

    def test_reviewed_valid_data_can_pass_record_gate(self):
        self.approve_for_test()
        self.assertTrue(audit(self.rows, self.exclusions, "benchmark")["ready_for_benchmark"])

    def test_empty_eval_is_rejected(self):
        self.fails(rows=[], message="empty evaluation")

    def test_empty_exclusions_are_rejected(self):
        self.fails(exclusions=[], message="empty exclusion")

    def test_null_text_is_rejected(self):
        self.rows[0]["text"] = None
        self.fails(message="requires nonempty string text")

    def test_unknown_label_is_rejected(self):
        self.rows[0]["label"] = "safe"
        self.fails(message="unknown label")

    def test_non_eval_split_is_rejected(self):
        self.rows[0]["split"] = "train"
        self.fails(message="unknown split")

    def test_duplicate_id_is_rejected(self):
        self.rows[1]["id"] = self.rows[0]["id"]
        self.fails(message="duplicate id")

    def test_duplicate_text_with_different_label_is_rejected(self):
        self.rows[1]["text"] = self.rows[0]["text"]
        self.rows[1]["label"] = "jailbreak"
        self.fails(message="duplicate/near-duplicate")

    def test_punctuation_width_and_zero_width_do_not_hide_overlap(self):
        self.assertEqual(canonical_text("ＳＡＦＥ \u200b- data!"), canonical_text("safe data"))
        self.rows[0]["text"] = self.exclusions[0]["text"] + " \u200b!"
        self.fails(message="text overlaps previous")

    def test_template_variants_are_detected(self):
        self.assertTrue(near_duplicate("a" * 50 + "100", "a" * 50 + "200"))

    def test_copied_payload_inside_wrapper_is_detected(self):
        self.rows[0]["text"] = "prefix wrapped " + self.exclusions[0]["text"] + " wrapped suffix"
        self.fails(message="text overlaps previous")

    def test_source_overlap_is_rejected(self):
        origin = next(r for r in self.exclusions if r["source_ids"])
        self.rows[0]["source_id"] = origin["source_ids"][0]
        self.fails(message="source/family overlaps")

    def test_family_overlap_is_rejected(self):
        origin = next(r for r in self.exclusions if r["family_ids"])
        self.rows[0]["family_id"] = origin["family_ids"][0]
        self.fails(message="source/family overlaps")

    def test_source_pair_metadata_must_agree(self):
        self.rows[1]["family_id"] += ":different"
        self.fails(message="inconsistent family")

    def test_all_attack_types_and_benign_are_required(self):
        self.fails(rows=[r for r in self.rows if r["label"] != "jailbreak"], message="all four labels")

    def test_malformed_reference_cannot_silently_pass(self):
        self.exclusions[0]["origins"] = []
        self.fails(message="requires an origin")

    def test_jsonl_errors_are_reported_with_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            path.write_text('{}\nnot JSON\n', encoding="utf-8")
            with self.assertRaisesRegex(DataError, ":2 invalid JSON"):
                load_jsonl(path)
            path.write_text('[]\n', encoding="utf-8")
            with self.assertRaisesRegex(DataError, "expected an object"):
                load_jsonl(path)
            path.write_text('\n', encoding="utf-8")
            with self.assertRaisesRegex(DataError, "empty JSONL"):
                load_jsonl(path)

    def test_changed_dataset_fails_frozen_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed.jsonl"
            path.write_bytes((ROOT / "eval.candidate.jsonl").read_bytes() + b"\n")
            with self.assertRaisesRegex(DataError, "dataset checksum mismatch"):
                audit_files(path, ROOT / "data_manifest.json", "candidate")

    def test_changed_exclusion_fails_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            manifest = json.loads((ROOT / "data_manifest.json").read_text(encoding="utf-8"))
            manifest["exclusion_file"] = "changed.jsonl"
            (path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (path / "changed.jsonl").write_text('{}\n', encoding="utf-8")
            with self.assertRaisesRegex(DataError, "exclusion corpus checksum mismatch"):
                audit_files(ROOT / "eval.candidate.jsonl", path / "manifest.json", "candidate")


if __name__ == "__main__":
    unittest.main()
