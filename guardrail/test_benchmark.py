import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from guardrail.benchmark import binary_metrics, evaluate_file, latency_stats, main, run_guard, save_report
from guardrail.validate_data import DataError, load_jsonl
from week5.guards import GuardResult, MockGuard

ROOT = Path(__file__).resolve().parent


class CounterClock:
    def __init__(self):
        self.time = 0.0

    def __call__(self):
        self.time += 0.001
        return self.time


class ScriptedGuard:
    kind = "mock"
    name = "test-scripted"

    def __init__(self, fn):
        self.fn, self.calls = fn, 0

    def check(self, request):
        self.calls += 1
        value = self.fn(request.text, self.calls)
        if isinstance(value, Exception):
            raise value
        if value in ("allow", "block"):
            return GuardResult(value, self.name, self.kind)
        return value


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.rows = load_jsonl(ROOT / "eval.jsonl")

    def test_confusion_matrix_and_metrics(self):
        result = binary_metrics([(1, 1)] * 2 + [(0, 1)] + [(0, 0)] * 3 + [(1, 0)] * 2)
        self.assertEqual([result[k] for k in ("tp", "fp", "tn", "fn", "n")], [2, 1, 3, 2, 8])
        self.assertAlmostEqual(result["f1"], 4 / 7)
        self.assertEqual(result["accuracy"], 5 / 8)
        self.assertEqual(result["fpr"], 1 / 4)
        self.assertEqual(result["recall"], 1 / 2)

    def test_empty_metrics_and_zero_positive_predictions(self):
        self.assertIsNone(binary_metrics([])["f1"])
        self.assertEqual(binary_metrics([(1, 0), (0, 0)])["f1"], 0)
        self.assertIsNone(binary_metrics([(1, 0)])["precision"])

    def test_invalid_metric_values_are_not_coerced(self):
        for pair in ((1, None), (True, 1), (0, 2), ("0", 1)):
            with self.assertRaises(ValueError):
                binary_metrics([pair])

    def test_latency_nearest_rank_p95(self):
        self.assertEqual(latency_stats(list(range(1, 21)))["p95_ms"], 19)
        self.assertEqual(latency_stats([1, 2, 100])["p50_ms"], 2)
        self.assertIsNone(latency_stats([])["mean_ms"])
        for values in ([float("nan")], [-1], [True]):
            with self.assertRaises(ValueError):
                latency_stats(values)

    def test_repeats_do_not_multiply_metric_sample_count(self):
        report = run_guard(MockGuard(), self.rows, repeats=3, warmup=1, clock=CounterClock())
        self.assertEqual(report["latency"]["successful_attempts"]["count"], 72)
        self.assertEqual(report["diagnostics"]["completed_case_metrics"]["n"], 24)
        self.assertEqual(report["diagnostics"]["completed_case_metrics"]["fn"], 12)
        self.assertEqual(report["diagnostics"]["completed_case_metrics"]["tn"], 12)
        self.assertIsNone(report["metrics"])
        self.assertFalse(report["summary"]["eligible_for_model_comparison"])
        self.assertFalse(report["evidence"]["model_inference_executed"])

    def test_full_suites_keep_fixed_order(self):
        seen = []
        guard = ScriptedGuard(lambda text, n: seen.append(text) or "allow")
        run_guard(guard, self.rows, repeats=2, warmup=1, clock=CounterClock())
        self.assertEqual(seen, [r["text"] for r in self.rows] * 3)

    def test_warmup_error_invalidates_measurement_even_if_later_calls_succeed(self):
        guard = ScriptedGuard(lambda text, n: RuntimeError("private failure") if n == 1 else "allow")
        report = run_guard(guard, self.rows, repeats=1, warmup=1, clock=CounterClock())
        self.assertEqual(report["summary"]["completed_cases"], 24)
        self.assertEqual(report["summary"]["warmup_error_count"], 1)
        self.assertFalse(report["summary"]["measurement_valid"])

    def test_exception_never_becomes_a_block_and_is_redacted(self):
        target = self.rows[0]["text"]
        guard = ScriptedGuard(lambda text, n: TimeoutError("PRIVATE_EXCEPTION=" + text) if text == target else "allow")
        report = run_guard(guard, self.rows, repeats=2, warmup=0, clock=CounterClock())
        case = report["cases"][0]
        self.assertEqual(case["status"], "error")
        self.assertIsNone(case["prediction"])
        self.assertIsNone(case["decision"])
        self.assertEqual(report["summary"]["error_cases"], 1)
        self.assertAlmostEqual(report["summary"]["coverage"], 23 / 24)
        self.assertFalse(report["summary"]["measurement_valid"])
        self.assertIsNone(report["metrics"])
        self.assertNotIn("PRIVATE_EXCEPTION", json.dumps(report, ensure_ascii=False))
        self.assertNotIn(target, json.dumps(report, ensure_ascii=False))

    def test_malformed_response_is_an_error(self):
        report = run_guard(ScriptedGuard(lambda text, n: ("allow", [])), self.rows, repeats=1, warmup=0)
        self.assertEqual(report["summary"]["error_cases"], 24)
        self.assertEqual(report["diagnostics"]["completed_case_metrics"]["n"], 0)
        self.assertIsNone(report["latency"]["successful_attempts"]["mean_ms"])

    def test_wrong_backend_identity_is_an_error(self):
        report = run_guard(ScriptedGuard(lambda text, n: GuardResult("block", "wrong", "mock")),
                           self.rows, repeats=1, warmup=0)
        self.assertEqual(report["summary"]["error_cases"], 24)

    def test_unstable_predictions_are_not_counted_as_independent_samples(self):
        seen = {}
        def alternate(text, n):
            seen[text] = seen.get(text, 0) + 1
            return "allow" if seen[text] == 1 else "block"
        report = run_guard(ScriptedGuard(alternate), self.rows, repeats=2, warmup=0)
        self.assertEqual(report["summary"]["unstable_cases"], 24)
        self.assertEqual(report["summary"]["coverage"], 0)
        self.assertFalse(report["summary"]["measurement_valid"])

    def test_synchronization_callback_is_accepted_as_callable_object(self):
        class Sync:
            def __init__(self):
                self.count = 0
            def __call__(self):
                self.count += 1
        sync = Sync()
        report = run_guard(MockGuard(), self.rows, repeats=1, warmup=0, synchronize=sync, clock=CounterClock())
        self.assertEqual(sync.count, 48)
        self.assertEqual(report["config"]["synchronization"], "caller_callback")

    def test_bad_timer_is_not_a_valid_latency(self):
        report = run_guard(MockGuard(), self.rows, repeats=1, warmup=0, clock=lambda: float("nan"))
        self.assertEqual(report["summary"]["error_cases"], 24)

    def test_invalid_config_or_data_fail_before_any_calls(self):
        guard = ScriptedGuard(lambda text, n: "allow")
        for kwargs in ({"repeats": 0}, {"repeats": True}, {"warmup": -1}):
            with self.assertRaises(ValueError):
                run_guard(guard, self.rows, **kwargs)
        for rows in ([], [dict(self.rows[0], label="safe")], [self.rows[0], self.rows[0]]):
            with self.assertRaises(ValueError):
                run_guard(guard, rows)
        self.assertEqual(guard.calls, 0)

    def test_model_metadata_and_gpu_synchronization_are_required(self):
        guard = ScriptedGuard(lambda text, n: "allow")
        guard.kind = "model"
        with self.assertRaisesRegex(ValueError, "requires model_id"):
            run_guard(guard, self.rows)
        metadata = dict(model_id="unit-test-only", model_revision="unit-test-only",
                        variant="unit-test-only", device="cuda", dtype="float32",
                        decision_policy="fixed", threads=1)
        with self.assertRaisesRegex(ValueError, "synchronization callback"):
            run_guard(guard, self.rows, execution=metadata)
        self.assertEqual(guard.calls, 0)

    def test_unreviewed_file_cannot_trigger_backend_calls(self):
        guard = ScriptedGuard(lambda text, n: "allow")
        with self.assertRaises(DataError):
            evaluate_file(guard, ROOT / "eval.candidate.jsonl", ROOT / "data_manifest.json")
        self.assertEqual(guard.calls, 0)

    def test_file_entrypoint_records_frozen_hashes_without_raw_prompts(self):
        report = evaluate_file(MockGuard(), ROOT / "eval.jsonl", ROOT / "data_manifest.json", repeats=1, warmup=0)
        manifest = json.loads((ROOT / "data_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(report["data"]["data_sha256"], manifest["evaluation_sha256"])
        self.assertEqual(report["data"]["family_count"], 12)
        self.assertNotIn(self.rows[0]["text"], json.dumps(report, ensure_ascii=False))

    def test_json_and_csv_record_each_attempt(self):
        report = run_guard(MockGuard(), self.rows, repeats=2, warmup=0)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            csv_path = save_report(report, output)
            self.assertIsNone(json.loads(output.read_text())["metrics"])
            with csv_path.open(newline="", encoding="utf-8") as stream:
                records = list(csv.DictReader(stream))
            self.assertEqual(len(records), 48)
            self.assertNotIn("text", records[0])

    def test_cli_smoke_explicitly_reports_no_model_metrics(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as out:
            code = main(["--backend", "mock", "--repeats", "1", "--warmup", "0",
                         "--output", str(Path(tmp) / "report.json")])
        self.assertEqual(code, 0)
        self.assertIn("MODEL_METRICS=null", out.getvalue())
        self.assertIn("MODEL_INFERENCE=false", out.getvalue())

    def test_cli_cannot_overwrite_frozen_inputs(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["--backend", "mock", "--output", str(ROOT / "eval.jsonl")])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
