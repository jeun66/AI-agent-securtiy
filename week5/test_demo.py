import json
import unittest
from week5.run_demo import latency_stats, run_suite


class DemoTests(unittest.TestCase):
    def test_rules_suite_routes_and_exposes_scope(self):
        report = run_suite("rules", repeats=1, warmup=0)
        self.assertEqual(report["summary"]["scenarios"], 8)
        self.assertTrue(report["summary"]["all_matched"])
        self.assertFalse(report["evidence"]["model_inference_executed"])
        self.assertFalse(report["evidence"]["real_http_executed"])
        cases = {r["scenario"]: r for r in report["cases"]}
        self.assertFalse(cases["taint_denial"]["trace"]["tool_executed"])
        self.assertTrue(cases["output_pii"]["trace"]["tool_executed"])
        self.assertFalse(cases["output_pii"]["trace"]["output_released"])
        self.assertEqual(cases["local_file"]["tool_environment"], "local_filesystem_fixture")
        self.assertNotIn("test@example.invalid", json.dumps(report))
        self.assertEqual(report["latency"]["guard_input"]["count"], 6)
        self.assertEqual(report["latency"]["guard_output"]["count"], 3)
        self.assertTrue(all(row["f1"] is None for row in report["model_comparison"]))

    def test_mock_suite_is_not_detection_accuracy(self):
        report = run_suite("mock", repeats=1, warmup=0)
        self.assertTrue(report["summary"]["all_matched"])
        self.assertEqual(report["evidence"]["guard_kind"], "mock")
        cases = {r["scenario"]: r for r in report["cases"]}
        self.assertEqual(cases["injection"]["observed"], "ok")
        self.assertTrue(cases["output_pii"]["trace"]["output_released"])
        self.assertNotIn("accuracy", report["summary"])

    def test_empty_latency_is_unmeasured_and_p95_uses_nearest_rank(self):
        self.assertIsNone(latency_stats([])["mean_ms"])
        self.assertEqual(latency_stats(list(range(1, 101)))["p95_ms"], 95)
        with self.assertRaises(ValueError):
            run_suite(repeats=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
