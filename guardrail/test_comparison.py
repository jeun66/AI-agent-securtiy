import json
from pathlib import Path
import unittest

from guardrail.compare_reports import ROLES, compare
from guardrail.model_backends import read_protocol

ROOT = Path(__file__).resolve().parent / "reports/2026-11-05"


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.reports = {role: json.loads((ROOT / (role + ".json")).read_text(encoding="utf-8")) for role in ROLES}
        self.llama = json.loads((ROOT / "llama-preflight.json").read_text(encoding="utf-8"))
        _, self.protocol_sha = read_protocol()

    def test_preserved_actual_reports_compare_but_do_not_complete_three_models(self):
        result = compare(self.reports, self.llama, self.protocol_sha)
        self.assertFalse(result["three_model_comparison_complete"])
        self.assertEqual(result["rows"][0]["metrics"]["fp"], 12)
        self.assertEqual(result["rows"][1]["metrics"]["fn"], 5)
        self.assertEqual(result["rows"][2]["metrics"]["tp"], 11)
        self.assertIsNone(result["rows"][3]["metrics"])

    def test_different_threads_or_packages_cannot_share_comparison(self):
        self.reports["laya"]["backend"]["execution"]["threads"] = 4
        with self.assertRaisesRegex(ValueError, "runtime conditions"):
            compare(self.reports, self.llama, self.protocol_sha)

    def test_changed_eval_hash_is_rejected(self):
        self.reports["laya"]["data"]["data_sha256"] = "wrong"
        with self.assertRaisesRegex(ValueError, "mismatched data"):
            compare(self.reports, self.llama, self.protocol_sha)

    def test_mock_and_incomplete_results_are_rejected(self):
        self.reports["laya"]["backend"]["kind"] = "mock"
        with self.assertRaisesRegex(ValueError, "non-model"):
            compare(self.reports, self.llama, self.protocol_sha)

    def test_repeat_count_cannot_inflate_support(self):
        self.reports["laya"]["metrics"]["n"] = 72
        with self.assertRaisesRegex(ValueError, "support"):
            compare(self.reports, self.llama, self.protocol_sha)

    def test_unmeasured_llama_cannot_have_a_f1(self):
        self.llama["f1"] = 0.9
        with self.assertRaisesRegex(ValueError, "Llama preflight"):
            compare(self.reports, self.llama, self.protocol_sha)

    def test_required_primary_reports_cannot_be_omitted(self):
        del self.reports["laya"]
        with self.assertRaisesRegex(ValueError, "all required"):
            compare(self.reports, self.llama, self.protocol_sha)


if __name__ == "__main__":
    unittest.main()
