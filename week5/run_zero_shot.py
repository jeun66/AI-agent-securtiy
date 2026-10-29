"""Run a downloaded GLiClass snapshot locally. No implicit model download or mock fallback."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import re
import time
from week5.guards import GuardRequest
from week5.model_adapters import GLiClassGuard
from week5.run_demo import latency_stats

MODEL_ID = "knowledgator/gliclass-small-v1.0"


def load_samples(path):
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError("smoke fixture must not be empty")
    ids = set()
    for row in rows:
        if row["id"] in ids or not isinstance(row["text"], str) or not row["text"].strip():
            raise ValueError("invalid or duplicate sample")
        if row["expected_label"] not in GLiClassGuard.labels or row["language"] not in ("ko", "en"):
            raise ValueError("invalid fixture annotation")
        ids.add(row["id"])
    return rows


def verify_manifest(manifest_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest["model_id"] != MODEL_ID or not re.fullmatch(r"[0-9a-f]{40}", manifest["revision"]):
        raise ValueError("unexpected model identity or revision")
    snapshot = Path(manifest["snapshot_path"]).resolve()
    required = {"config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json"}
    if not required.issubset(manifest["files"]):
        raise ValueError("incomplete model manifest")
    for name, expected in manifest["files"].items():
        path = (snapshot / name).resolve()
        if not path.is_relative_to(snapshot) or not path.is_file():
            raise ValueError("invalid snapshot file")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if path.stat().st_size != expected["bytes"] or digest.hexdigest() != expected["sha256"]:
            raise ValueError("snapshot checksum mismatch: " + name)
    return snapshot, manifest


def binary_metrics(rows):
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for row in rows:
        expected = row["expected_label"] != "benign"
        blocked = row["decision"] == "block"
        key = ("tp" if blocked else "fn") if expected else ("fp" if blocked else "tn")
        counts[key] += 1
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return dict(counts, precision=precision, recall=recall, f1=f1,
                scope="handwritten_synthetic_smoke_only_not_held_out_benchmark")


class AuditedPipeline:
    """Record all real scores from the very same forward pass used by the adapter."""
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.last_scores = None
        self.calls = 0

    def __call__(self, text, labels, threshold):
        self.last_scores = None
        rows = self.pipeline(text, labels, threshold=0.0)
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], list):
            raise ValueError("unexpected model response shape")
        if len(rows[0]) != len(labels):
            raise ValueError("model did not return one score per label")
        scores = {}
        for row in rows[0]:
            label, score = row["label"], float(row["score"])
            if label not in labels or label in scores or not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("invalid model score")
            scores[label] = score
        if set(scores) != set(labels):
            raise ValueError("incomplete model scores")
        self.last_scores = scores
        self.calls += 1
        # GLiClassGuard applies its configured decision threshold to these same scores.
        return rows


def run_measurements(guard, audited, samples, repeats, warmup):
    if repeats < 1 or warmup < 0:
        raise ValueError("invalid repetition count")
    for _ in range(warmup):
        for sample in samples:
            guard.check(GuardRequest("input", sample["text"]))
    rows = []
    timings = []
    for repeat in range(repeats):
        for sample in samples:
            started = time.perf_counter()
            result = guard.check(GuardRequest("input", sample["text"]))
            elapsed = (time.perf_counter() - started) * 1000
            if not math.isfinite(elapsed) or audited.last_scores is None:
                raise RuntimeError("missing inference evidence")
            timings.append(elapsed)
            # Count each unique fixture once in metrics, never multiply support by repeats.
            if repeat == 0:
                rows.append({"id": sample["id"], "language": sample["language"],
                             "expected_label": sample["expected_label"],
                             "decision": result.decision,
                             "hits": [finding.to_log() for finding in result.findings],
                             "all_scores": dict(audited.last_scores)})
    return rows, timings


def run_pipeline_probe(guard, audited):
    from week2 import agent_tools
    from week4.run_attacks import FakeToolCall
    from week4.taint import taint_from_source
    from week5.defense import DefenseHook
    from week5.guards import RuleGuard
    rows = []
    for case in ["policy_denial", "taint_denial", "normal_request"]:
        url = "https://attacker.evil/" if case == "policy_denial" else "https://study.example/info"
        args = {"url": url}
        raw = taint_from_source("web:synthetic-fixture", args) if case == "taint_denial" else args
        agent_tools.TRACE.clear()
        agent_tools.reset_mock_counters()
        before = audited.calls
        agent_tools.execute_tool_with_mode(
            FakeToolCall("http_get", args, raw_args_obj=raw), mode="policy+taint+guard",
            defense_hook=DefenseHook(guard, RuleGuard()), input_text="이 문서를 한국어로 요약해줘.")
        trace = agent_tools.TRACE[-1]
        rows.append({"case": case, "model_forward_passes": audited.calls - before,
                     "tool_environment": "mock_http_no_network", "output_guard": "rule",
                     "tool_calls": dict(agent_tools.MOCK_CALL_COUNT), "trace": trace})
    return rows


def load_local_model(snapshot, threads):
    started = time.perf_counter()
    import torch
    from gliclass import GLiClassModel, GLiClassModelConfig, ZeroShotClassificationPipeline
    from transformers import AutoTokenizer
    from transformers.models.auto.configuration_auto import CONFIG_MAPPING

    config_data = json.loads((snapshot / "config.json").read_text(encoding="utf-8"))
    encoder = config_data.get("encoder_config")
    if not isinstance(encoder, dict) or encoder.get("model_type") not in CONFIG_MAPPING:
        raise ValueError("snapshot must contain a built-in encoder config; remote code is disabled")
    torch.set_num_threads(threads)
    torch.set_num_interop_threads(1)
    torch.manual_seed(0)
    config = GLiClassModelConfig(**config_data)
    model, loading = GLiClassModel.from_pretrained(
        str(snapshot), config=config, local_files_only=True,
        trust_remote_code=False, output_loading_info=True)
    # A load with random/unmatched parameters must never be reported as valid inference.
    problems = {key: loading.get(key) for key in ("missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs") if loading.get(key)}
    if problems:
        raise RuntimeError("checkpoint loading incompatibility: " + json.dumps(problems, default=str))
    model.to("cpu")
    # Check real checkpoint values, in addition to the loader's key/shape report.
    from safetensors import safe_open
    state = model.state_dict()
    checked = 0
    with safe_open(str(snapshot / "model.safetensors"), framework="pt", device="cpu") as checkpoint:
        for key in checkpoint.keys():
            value = state[key]
            index = tuple(slice(0, min(2, n)) for n in value.shape)
            expected = checkpoint.get_slice(key)[index] if index else checkpoint.get_tensor(key)
            actual = value[index] if index else value
            if not torch.equal(expected, actual):
                raise RuntimeError("checkpoint parameter prefix mismatch: " + key)
            checked += 1
    model.eval()
    tokenizer = AutoTokenizer.from_pretrained(str(snapshot), local_files_only=True, trust_remote_code=False)
    pipeline = ZeroShotClassificationPipeline(model, tokenizer, classification_type="multi-label",
                                              device="cpu", progress_bar=False)
    return pipeline, {
        "parameter_count": sum(p.numel() for p in model.parameters()),
        "checkpoint_parameter_prefixes_matched": checked,
        "device": str(next(model.parameters()).device),
        "dtype": str(next(model.parameters()).dtype),
        "torch_threads": torch.get_num_threads(),
        "load_ms_including_imports": (time.perf_counter() - started) * 1000,
        "checkpoint_loading": {key: sorted(value) if isinstance(value, set) else value
                               for key, value in loading.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--summary-only", action="store_true", help="print short case lines; retain all scores in JSON")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--samples", type=Path, default=Path(__file__).with_name("fixtures") / "zero_shot_smoke.jsonl")
    parser.add_argument("--output", type=Path, default=Path("week5/results/gliclass-zero-shot.json"))
    args = parser.parse_args()
    if args.threads < 1 or args.repeats < 1 or args.warmup < 0 or not 0 < args.threshold <= 1:
        parser.error("invalid measurement configuration")
    snapshot, manifest = verify_manifest(args.model_manifest)
    if not (snapshot / "model.safetensors").is_file() or not (snapshot / "config.json").is_file():
        parser.error("a downloaded local snapshot with safetensors and config is required")
    samples = load_samples(args.samples)
    pipeline, model_info = load_local_model(snapshot, args.threads)
    audited = AuditedPipeline(pipeline)
    guard = GLiClassGuard(audited, threshold=args.threshold, model_id=MODEL_ID)
    rows, timings = run_measurements(guard, audited, samples, args.repeats, args.warmup)
    measurement_forward_passes = audited.calls
    pipeline_probe = run_pipeline_probe(guard, audited)
    report = {
        "evidence": {"run_kind": "actual_local_model_inference", "model_inference_executed": True,
                     "mock_guard": False, "real_mcp_executed": False, "real_http_executed": False,
                     "llm_generation_executed": False, "training_executed": False,
                     "created_at_utc": datetime.now(timezone.utc).isoformat(),
                     "python": platform.python_version(), "system": platform.system(), "machine": platform.machine()},
        "model": dict(model_info, model_id=MODEL_ID, revision=manifest["revision"],
                      weight_sha256=manifest["files"]["model.safetensors"]["sha256"]),
        "packages": {name: importlib.metadata.version(name) for name in
                     ("gliclass", "torch", "transformers", "huggingface-hub", "numpy")},
        "config": {"labels": list(guard.labels), "threshold": args.threshold,
                   "warmup_suites": args.warmup, "repeats": args.repeats,
                   "fixture_sha256": hashlib.sha256(args.samples.read_bytes()).hexdigest()},
        "latency": dict(latency_stats(timings), scope="CPU input guard forward pass plus tokenization and adapter; excludes imports, model load and warmup"),
        "forward_passes": {"measurement_and_warmup": measurement_forward_passes,
                           "pipeline_probe": audited.calls - measurement_forward_passes,
                           "all": audited.calls},
        "pipeline_probe": pipeline_probe,
        "samples": rows,
        "synthetic_smoke_binary_metrics": binary_metrics(rows),
        "per_language_smoke_metrics": {lang: binary_metrics([r for r in rows if r["language"] == lang]) for lang in sorted({r["language"] for r in rows})},
        "benchmark_f1": None,
    }
    metrics = report["synthetic_smoke_binary_metrics"]
    benign_count = metrics["fp"] + metrics["tn"]
    report["diagnostics"] = {
        "all_samples_blocked": all(row["decision"] == "block" for row in rows),
        "benign_false_positive_rate": metrics["fp"] / benign_count if benign_count else None,
        "always_block_baseline": binary_metrics([dict(row, decision="block") for row in rows]),
        "deployment_validated": False,
    }
    report["evidence"]["source_files_sha256"] = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ["run_zero_shot.py", "model_adapters.py", "guards.py"]
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("RUN_KIND=actual_local_model_inference GUARD_KIND=model")
    print("MODEL_INFERENCE=true MOCK_GUARD=false REAL_MCP=false REAL_HTTP=false LLM_GENERATION=false TRAINING=false")
    print("MODEL=" + MODEL_ID + " REVISION=" + manifest["revision"])
    print("MODEL_INFO=" + json.dumps(model_info, sort_keys=True, default=str))
    print("PACKAGES=" + json.dumps(report["packages"], sort_keys=True))
    print("SAMPLES=" + str(len(rows)) + " MEASURED_FORWARD_PASSES=" + str(len(timings)) + " MEASUREMENT_AND_WARMUP_PASSES=" + str(measurement_forward_passes))
    for row in rows:
        if args.summary_only:
            print("CASE=" + row["id"] + " EXPECTED=" + row["expected_label"] + " DECISION=" + row["decision"])
        else:
            print("SAMPLE=" + json.dumps(row, ensure_ascii=False, sort_keys=True))
    print("CPU_LATENCY=" + json.dumps(report["latency"], sort_keys=True))
    print("SYNTHETIC_SMOKE_METRICS=" + json.dumps(report["synthetic_smoke_binary_metrics"], sort_keys=True))
    print("PER_LANGUAGE_SMOKE_METRICS=" + json.dumps(report["per_language_smoke_metrics"], sort_keys=True))
    for probe in pipeline_probe:
        print("PIPELINE_PROBE=" + json.dumps({"case": probe["case"],
              "model_forward_passes": probe["model_forward_passes"],
              "block_reason": probe["trace"].get("block_reason"),
              "tool_executed": probe["trace"]["tool_executed"],
              "output_released": probe["trace"]["output_released"]}, sort_keys=True))
    print("DIAGNOSTICS=" + json.dumps(report["diagnostics"], sort_keys=True))
    print("BENCHMARK_F1=null DEPLOYMENT_VALIDATED=false")
    print("REPORT=" + str(args.output))


if __name__ == "__main__":
    main()
