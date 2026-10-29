import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from week5.guards import GuardRequest
from week5.model_adapters import GLiClassGuard
from week5.run_zero_shot import AuditedPipeline, MODEL_ID, binary_metrics, load_samples, run_measurements, run_pipeline_probe, verify_manifest


class ZeroShotReportingTests(unittest.TestCase):
    def test_real_score_mapping_contract_with_fake_pipeline(self):
        labels = list(GLiClassGuard.labels)
        calls = []
        def fake(text, supplied_labels, threshold):
            calls.append(threshold)
            return [[{"label": label, "score": 0.8 if label == "jailbreak" else 0.1} for label in labels]]
        audited = AuditedPipeline(fake)
        result = GLiClassGuard(audited).check(GuardRequest("input", "fake test"))
        self.assertEqual(calls, [0.0])
        self.assertEqual(result.decision, "block")
        self.assertEqual([f.label for f in result.findings], ["jailbreak"])
        self.assertEqual(set(audited.last_scores), set(labels))

    def test_invalid_score_responses_raise_without_mock_fallback(self):
        labels = list(GLiClassGuard.labels)
        for rows in [[], [[]], [[{"label": label, "score": float("nan")} for label in labels]],
                     [[{"label": "benign", "score": 0.3} for _ in labels]]]:
            audited = AuditedPipeline(lambda *a, **kw: rows)
            with self.assertRaises(ValueError):
                audited("text", labels, threshold=0.5)
            self.assertIsNone(audited.last_scores)
            self.assertEqual(audited.calls, 0)

    def test_warmup_excluded_and_repeats_do_not_inflate_unique_support(self):
        samples = [{"id": "x", "language": "en", "text": "x", "expected_label": "jailbreak"}]
        audited = AuditedPipeline(lambda text, labels, **kw: [[
            {"label": label, "score": 0.8 if label == "jailbreak" else 0.1} for label in labels]])
        rows, times = run_measurements(GLiClassGuard(audited), audited, samples, repeats=3, warmup=2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(times), 3)
        self.assertEqual(audited.calls, 5)
        self.assertEqual(binary_metrics(rows)["tp"], 1)

    def test_metrics_preserve_missed_attacks_and_false_positives(self):
        rows = [{"expected_label": "prompt_injection", "decision": "allow"},
                {"expected_label": "benign", "decision": "block"}]
        metrics = binary_metrics(rows)
        self.assertEqual((metrics["fn"], metrics["fp"], metrics["tp"], metrics["tn"]), (1, 1, 0, 0))
        self.assertEqual(metrics["f1"], 0)
        self.assertEqual(binary_metrics([])["f1"], None)

    def test_pipeline_probe_skips_fake_model_for_policy_and_taint(self):
        audited = AuditedPipeline(lambda text, labels, **kw: [[
            {"label": label, "score": 0.9 if label == "benign" else 0.1} for label in labels]])
        rows = run_pipeline_probe(GLiClassGuard(audited), audited)
        self.assertEqual([r["model_forward_passes"] for r in rows], [0, 0, 1])
        self.assertEqual(rows[0]["trace"]["block_reason"], "policy")
        self.assertEqual(rows[1]["trace"]["block_reason"], "taint")
        self.assertEqual(rows[2]["trace"]["status"], "ok")

    def test_fixture_has_expected_eight_unique_cases(self):
        rows = load_samples(Path(__file__).with_name("fixtures") / "zero_shot_smoke.jsonl")
        self.assertEqual(len(rows), 8)
        self.assertEqual({r["language"] for r in rows}, {"ko", "en"})

    def test_manifest_detects_changed_weight_files(self):
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder)
            names = ["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json"]
            files = {}
            for name in names:
                (snapshot / name).write_bytes(b"fixture")
                files[name] = {"bytes": 7, "sha256": hashlib.sha256(b"fixture").hexdigest()}
            manifest = snapshot / "manifest.json"
            manifest.write_text(json.dumps({"model_id": MODEL_ID, "revision": "a" * 40,
                                            "snapshot_path": str(snapshot), "files": files}))
            self.assertEqual(verify_manifest(manifest)[0], snapshot.resolve())
            (snapshot / "model.safetensors").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                verify_manifest(manifest)

    def test_duplicate_fixtures_and_invalid_repetitions_rejected(self):
        row = {"id": "same", "language": "en", "text": "test", "expected_label": "benign"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "samples.jsonl"
            path.write_text(json.dumps(row) + '\n' + json.dumps(row) + '\n')
            with self.assertRaises(ValueError):
                load_samples(path)
        with self.assertRaises(ValueError):
            run_measurements(None, None, [], repeats=0, warmup=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
