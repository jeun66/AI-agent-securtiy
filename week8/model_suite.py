"""W8 step 7: compare verified *actual* classifier inference reports.

The existing guardrail.run_models CLI performs the forward passes. This
module reads its files only; it never substitutes old numbers or mock guards.
GLiNER PII spans have their own, incomparable evaluation (gliner_span.py).
"""
import argparse
from hashlib import sha256
import math
import json
from pathlib import Path

from guardrail.model_backends import read_protocol
from guardrail.validate_data import audit_files

ROLES = {
    "gliclass-base": "zero_shot",
    "gliclass-trained": "study_head_finetuned",
    "laya": "multilingual_322m_typed_questions",
    "llama-guard4": "vanilla_content_safety",
}
PRIMARY = ("gliclass-trained", "laya", "llama-guard4")
MATCH_RUNTIME = ("device", "dtype", "threads", "interop_threads", "quantization")
MATCH_CONFIG = ("repeats", "warmup_suites", "batch_size", "order", "metric_unit")


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _file_hash(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _validate_actual(role, report, *, protocol_sha, data_sha, expected_n):
    backend = report.get("backend", {})
    summary = report.get("summary", {})
    execution = backend.get("execution", {})
    metrics = report.get("metrics")
    if (backend.get("kind") != "model" or
            report.get("evidence", {}).get("model_inference_executed") is not True or
            summary.get("measurement_valid") is not True or
            summary.get("eligible_for_model_comparison") is not True or
            summary.get("coverage") != 1 or summary.get("error_cases") != 0 or
            summary.get("unstable_cases") != 0 or summary.get("warmup_error_count") != 0 or
            not isinstance(metrics, dict)):
        raise ValueError("model_report_invalid_or_incomplete:" + role)
    if (report.get("protocol_sha256") != protocol_sha or
            report.get("data", {}).get("data_sha256") != data_sha or
            report["data"].get("rows") != expected_n or
            execution.get("variant") != ROLES[role]):
        raise ValueError("model_report_protocol_or_data_mismatch:" + role)
    count = expected_n * report["config"]["repeats"]
    latency = report.get("latency", {}).get("successful_attempts", {})
    if (metrics.get("n") != expected_n or latency.get("count") != count or
            not all(isinstance(metrics.get(k), (int, float)) and
                    not isinstance(metrics.get(k), bool) and
                    math.isfinite(metrics[k]) and 0 <= metrics[k] <= 1
                    for k in ("accuracy", "f1", "fpr")) or
            not all(isinstance(latency.get(k), (int, float)) and
                    math.isfinite(latency[k]) and latency[k] >= 0
                    for k in ("p50_ms", "p95_ms")) or
            latency["p95_ms"] < latency["p50_ms"] or
            type(report.get("forward_passes")) is not int or report["forward_passes"] < count):
        raise ValueError("model_report_missing_observed_measurements:" + role)
    if (role != "llama-guard4" and
            report["forward_passes"] != expected_n * (
                report["config"]["repeats"] + report["config"]["warmup_suites"])):
        raise ValueError("invalid_forward_pass_count:" + role)
    return execution


def comparison(reports, *, protocol_sha, data_sha, expected_n, preflight=None):
    """reports maps role to actual JSON; omitted roles are explicitly not run."""
    if not set(reports) <= ROLES.keys():
        raise ValueError("unknown_model_role")
    reference = None
    rows = []
    for role in ROLES:
        report = reports.get(role)
        if report is None:
            status = "not_run"
            if role == "llama-guard4" and preflight is not None:
                if (preflight.get("status") != "not_run_memory_limit" or
                        preflight.get("model_inference_executed") is not False or
                        preflight.get("f1") is not None or
                        preflight.get("latency_ms") is not None or
                        preflight.get("protocol_sha256") != protocol_sha or
                        preflight.get("data_sha256") != data_sha):
                    raise ValueError("invalid_llama_preflight")
                status = "not_run_memory_limit"
            rows.append({"role": role, "status": status, "accuracy": None, "f1": None,
                         "fpr": None, "p50_ms": None, "p95_ms": None,
                         "model_revision": None, "forward_passes": 0})
            continue
        execution = _validate_actual(role, report, protocol_sha=protocol_sha,
                                     data_sha=data_sha, expected_n=expected_n)
        if reference is None:
            reference = report
        else:
            for key in MATCH_RUNTIME:
                if execution.get(key) != reference["backend"]["execution"].get(key):
                    raise ValueError("mismatched_model_runtime:" + role + ":" + key)
            for key in MATCH_CONFIG:
                if report["config"].get(key) != reference["config"].get(key):
                    raise ValueError("mismatched_model_config:" + role + ":" + key)
            for key in ("python", "system", "machine"):
                if report["runtime"].get(key) != reference["runtime"].get(key):
                    raise ValueError("mismatched_host:" + role + ":" + key)
            if report.get("packages") != reference.get("packages"):
                raise ValueError("mismatched_packages:" + role)
        metrics, latency = report["metrics"], report["latency"]["successful_attempts"]
        rows.append({"role": role, "status": "executed", "accuracy": metrics["accuracy"],
                     "f1": metrics["f1"], "fpr": metrics["fpr"],
                     "p50_ms": latency["p50_ms"], "p95_ms": latency["p95_ms"],
                     "model_revision": execution["model_revision"],
                     "forward_passes": report["forward_passes"]})
    return {"schema": "w8-model-comparison-v1", "protocol_sha256": protocol_sha,
            "data_sha256": data_sha, "n_texts": expected_n,
            "three_model_comparison_complete": all(
                next(row for row in rows if row["role"] == role)["status"] == "executed"
                for role in PRIMARY),
            "rows": rows,
            "warnings": ["Synthetic fixed inputs, not production effectiveness",
                         "GLiNER PII span F1 is not comparable to text classification F1",
                         "Llama Guard 4 uses vanilla content-safety policy rather than an injection-specific taxonomy",
                         "Missing and preflight-only models have null metrics, not zeros"]}


def markdown(report):
    lines = ["# W8 actual-model comparison (stage 7)", "",
             "| Guard | Status | Accuracy | F1 | FPR | p50 ms | p95 ms |",
             "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    def fmt(x, percent=False):
        return "—" if x is None else (f"{x:.1%}" if percent else f"{x:.3f}")
    for row in report["rows"]:
        lines.append("| " + " | ".join([
            row["role"], row["status"], fmt(row["accuracy"], True), fmt(row["f1"]),
            fmt(row["fpr"], True), fmt(row["p50_ms"]), fmt(row["p95_ms"])]) + " |")
    lines += ["", "Three primary classifiers completed: " + str(report["three_model_comparison_complete"]),
              "Input classification only. PII span evaluation is a separate report."]
    return "\n".join(lines) + "\n"


def run(report_paths, *, output_dir, preflight_path=None):
    root = Path(__file__).resolve().parents[1]
    protocol, protocol_sha = read_protocol()
    data = audit_files(root / "guardrail/eval.jsonl", root / "guardrail/data_manifest.json", "benchmark")
    data_sha, n = data["data_sha256"], data["rows"]
    paths = {role: Path(p) for role, p in report_paths.items() if p is not None}
    models = {role: _read(p) for role, p in paths.items()}
    preflight = _read(preflight_path) if preflight_path else None
    result = comparison(models, protocol_sha=protocol_sha, data_sha=data_sha,
                        expected_n=n, preflight=preflight)
    for role, report in models.items():
        sources = report.get("runtime", {}).get("source_files_sha256")
        if not isinstance(sources, dict) or not sources:
            raise ValueError("missing_inference_source_hashes:" + role)
        for name, digest in sources.items():
            source = (root / name).resolve()
            if not source.is_relative_to(root) or not source.is_file() or _file_hash(source) != digest:
                raise ValueError("inference_source_changed:" + role + ":" + name)
    result["source_reports"] = {role: {"path": str(p.resolve()), "sha256": _file_hash(p)}
                                for role, p in paths.items()}
    result["source_reports_sha256"] = {role: row["sha256"] for role, row in result["source_reports"].items()}
    result["preflight"] = ({"path": str(Path(preflight_path).resolve()),
                             "sha256": _file_hash(preflight_path)} if preflight_path else None)
    result["preflight_sha256"] = _file_hash(preflight_path) if preflight_path else None
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "comparison.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "comparison.md").write_text(markdown(result), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gliclass-base", type=Path)
    parser.add_argument("--gliclass-trained", type=Path)
    parser.add_argument("--laya", type=Path)
    parser.add_argument("--llama-guard4", type=Path)
    parser.add_argument("--llama-preflight", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    paths = {key.replace("_", "-"): getattr(args, key) for key in
             ("gliclass_base", "gliclass_trained", "laya", "llama_guard4")}
    report = run(paths, output_dir=args.output_dir, preflight_path=args.llama_preflight)
    print(markdown(report), end="")


if __name__ == "__main__":
    main()