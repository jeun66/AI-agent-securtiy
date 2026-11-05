import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from guardrail.model_backends import (LayaGuard, LlamaGuard4, llama_memory_preflight,
                                     parse_llama_verdict, read_protocol, verify_snapshot)
from week5.guards import GuardRequest


class FakeLaya:
    def __init__(self, scores, truncated=False):
        self.scores, self.truncated = scores, truncated
        self.state = None

    def predict(self, state, questions, **kwargs):
        self.state = state
        return {"usage": {"truncated": self.truncated},
                "answers": {k: {"type": "noul", "noul": v} for k, v in self.scores.items()}}


class ModelAdapterTests(unittest.TestCase):
    def setUp(self):
        self.protocol, self.sha = read_protocol()
        self.scores = {k: 0.1 for k in self.protocol["laya"]["questions"]}

    def test_laya_probability_threshold_and_prompt_field(self):
        agent = FakeLaya(dict(self.scores, jailbreak=0.5))
        result = LayaGuard(agent, "test-only", self.protocol).check(GuardRequest("input", "example"))
        self.assertEqual(result.decision, "block")
        self.assertEqual(result.findings[0].label, "jailbreak")
        self.assertEqual(agent.state, {"prompt": "example"})

    def test_laya_rejects_truncation_missing_labels_and_bad_probabilities(self):
        bad = [(self.scores, True), ({"jailbreak": 0.1}, False),
               (dict(self.scores, jailbreak=float("nan")), False),
               (dict(self.scores, jailbreak=True), False), (dict(self.scores, jailbreak=1.1), False)]
        for scores, truncated in bad:
            with self.assertRaises(ValueError):
                LayaGuard(FakeLaya(scores, truncated), "test-only", self.protocol).check(GuardRequest("input", "x"))

    def test_laya_allow_is_not_a_fixed_mock(self):
        self.assertEqual(LayaGuard(FakeLaya(self.scores), "test-only", self.protocol)
                         .check(GuardRequest("input", "x")).decision, "allow")

    def test_llama_parser_does_not_find_safe_inside_unsafe(self):
        self.assertEqual(parse_llama_verdict("safe")[0], "allow")
        verdict, findings = parse_llama_verdict("unsafe\nS7, S14")
        self.assertEqual(verdict, "block")
        self.assertEqual([r.label for r in findings], ["S7", "S14"])

    def test_llama_parser_rejects_unrecognized_or_truncated_outputs(self):
        for value in (None, "", "unsafe", "not safe", "safe\nS7", "unsafe\nS15", "unsafe\nS1,S1", "safe please"):
            with self.assertRaises(ValueError):
                parse_llama_verdict(value)

    def test_llama_adapter_uses_generated_verdict(self):
        guard = LlamaGuard4(lambda text: "unsafe\nS7", "test-only")
        self.assertEqual(guard.check(GuardRequest("input", "x")).decision, "block")
        with self.assertRaises(ValueError):
            guard.check(GuardRequest("output", "x"))

    def test_memory_preflight_never_invents_metrics(self):
        result = llama_memory_preflight(16 * 1024 ** 3, self.protocol)
        self.assertEqual(result["status"], "not_run_memory_limit")
        self.assertEqual(result["estimated_weight_bytes_float32"], 48_000_000_000)
        self.assertIsNone(result["f1"])
        self.assertFalse(result["model_inference_executed"])
        self.assertNotEqual(llama_memory_preflight(64 * 1024 ** 3, self.protocol)["status"], "not_run_memory_limit")

    def test_snapshot_identity_hash_and_traversal_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snap = root / "snapshot"
            snap.mkdir()
            (snap / "model.safetensors").write_bytes(b"test-only-not-real-weights")
            data = {"model_id": "test/model", "revision": "a" * 40, "snapshot_path": str(snap),
                    "files": {"model.safetensors": {"bytes": 26, "sha256": hashlib.sha256(b"test-only-not-real-weights").hexdigest()}}}
            data["files"]["model.safetensors"]["bytes"] = (snap / "model.safetensors").stat().st_size
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(data))
            self.assertEqual(verify_snapshot(manifest, "test/model", ["model.safetensors"])[0], snap.resolve())
            with self.assertRaises(ValueError):
                verify_snapshot(manifest, "wrong/model", ["model.safetensors"])
            (snap / "model.safetensors").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_snapshot(manifest, "test/model", ["model.safetensors"])
            data["files"] = {"../outside.json": {"bytes": 0, "sha256": ""}}
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "escapes"):
                verify_snapshot(manifest, "test/model", [])

    def test_protocol_retains_primary_variant_and_fixed_cpu_conditions(self):
        self.assertEqual(self.protocol["primary_gliclass_variant"], "study_head_finetuned")
        self.assertEqual(self.protocol["device"], "cpu")
        self.assertEqual(self.protocol["threads"], 2)
        self.assertEqual(self.protocol["threshold"], 0.5)


if __name__ == "__main__":
    unittest.main()
