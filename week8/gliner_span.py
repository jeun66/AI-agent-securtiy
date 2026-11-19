"""Optional real GLiNER PII span benchmark; separate from classifier F1.

Requires a locally pinned GLiNER snapshot manifest. No download, remote
inference, mock score or prompt-injection accuracy substitution is permitted.
"""
import argparse
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
from time import perf_counter

from guardrail.benchmark import latency_stats
from guardrail.model_backends import verify_snapshot
from week5.guards import GuardRequest
from week5.model_adapters import GLiNERGuard
from week5.span_study import build_span_rows, validate_span_rows, exact_span_metrics


def _hash(data):
    return sha256(data).hexdigest()


def measure(guard, rows, *, repeats=3, warmup=1):
    if getattr(guard, "kind", None) != "model":
        raise ValueError("real_model_span_guard_required")
    if type(repeats) is not int or repeats < 1 or type(warmup) is not int or warmup < 0:
        raise ValueError("invalid_repeat_or_warmup")
    validate_span_rows(rows)
    tests = [r for r in rows if r["split"] == "test"]
    if not tests:
        raise ValueError("no_test_span_examples")
    timings, observed = [], []
    for _ in range(warmup):
        for row in tests:
            guard.check(GuardRequest("output", row["text"]))
    for iteration in range(repeats):
        for row in tests:
            start = perf_counter()
            prediction = guard.check(GuardRequest("output", row["text"]))
            elapsed = (perf_counter() - start) * 1000
            if prediction.backend != guard.name or prediction.kind != "model":
                raise ValueError("invalid_model_span_response")
            timings.append(elapsed)
            spans = [{"start": f.start, "end": f.end, "label": f.label,
                      "score": f.score} for f in prediction.findings]
            if any(s["start"] is None or s["end"] is None for s in spans):
                raise ValueError("missing_predicted_offsets")
            if iteration == 0:
                observed.append({"id": row["id"], "spans": spans})
            elif spans != next(x["spans"] for x in observed if x["id"] == row["id"]):
                raise ValueError("unstable_span_prediction")
    # Explicitly refuse case/order mismatch, even though rows originate in a
    # fixed frozen synthetic generator.
    if [r["id"] for r in tests] != [r["id"] for r in observed]:
        raise ValueError("span_test_order_changed")
    metrics = exact_span_metrics(tests, [r["spans"] for r in observed])
    return {"span_metrics": metrics, "latency": latency_stats(timings),
            "test_rows": len(tests), "warmup_suites": warmup, "repeats": repeats,
            "predictions": observed}


def run(output_dir, *, model_manifest, threshold=0.5, repeats=3):
    if type(threshold) is not float and type(threshold) is not int:
        raise ValueError("invalid_threshold")
    if not 0 < threshold <= 1:
        raise ValueError("invalid_threshold")
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    manifest = json.loads(Path(model_manifest).read_text(encoding="utf-8"))
    files = manifest.get("files", {})
    if not any(k in files for k in ("model.safetensors", "pytorch_model.bin")):
        raise ValueError("pinned_gliner_weights_required")
    snapshot, pinned = verify_snapshot(model_manifest, manifest["model_id"],
                                       ("config.json",), manifest["revision"])
    try:
        from gliner import GLiNER
        import torch
    except ImportError as exc:
        raise RuntimeError("gliner_and_torch_packages_required") from exc
    torch.set_num_threads(2)
    model = GLiNER.from_pretrained(str(snapshot))
    model.to("cpu")
    model.eval()
    guard = GLiNERGuard(model, threshold=threshold,
                        model_id=pinned["model_id"] + "@" + pinned["revision"])
    rows = build_span_rows()
    stats = measure(guard, rows, repeats=repeats)
    dataset_id = json.dumps(rows, sort_keys=True, ensure_ascii=False).encode("utf-8")
    report = {"schema": "w8-gliner-pii-span-v1", "backend": guard.name,
              "model_inference_executed": True,
              "model_id": pinned["model_id"], "model_revision": pinned["revision"],
              "manifest_sha256": _hash(Path(model_manifest).read_bytes()),
              "data_sha256": _hash(dataset_id), "device": "cpu",
              "package_version": importlib.metadata.version("gliner"),
              "threshold": threshold, **stats,
              "comparability": "synthetic PII exact-character-span F1; NOT comparable to GLiClass/Laya/Llama Guard input classification F1"}
    directory = Path(output_dir)
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("output directory must be empty")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "span-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.output_dir, model_manifest=args.model_manifest,
                 threshold=args.threshold, repeats=args.repeats)
    print(json.dumps({"model_inference_executed": True, "span_f1": report["span_metrics"]["f1"],
                      "p50_ms": report["latency"]["p50_ms"],
                      "p95_ms": report["latency"]["p95_ms"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()