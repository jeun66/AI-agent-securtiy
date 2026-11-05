"""Build a comparison only from complete actual runs with matching conditions."""
import argparse
import hashlib
import json
from pathlib import Path

from guardrail.model_backends import read_protocol
from guardrail.validate_data import audit_files

ROLES = {"gliclass-base": "zero_shot", "gliclass-trained": "study_head_finetuned",
         "laya": "multilingual_322m_typed_questions"}


def compare(reports, llama_preflight, protocol_sha):
    if set(reports) != set(ROLES):
        raise ValueError("base, trained, and Laya actual reports are all required")
    reference = reports["gliclass-trained"]
    matching = ("device", "dtype", "threads", "interop_threads", "quantization")
    rows = []
    for role, variant in ROLES.items():
        report = reports[role]
        execution = report["backend"]["execution"]
        if (report["backend"]["kind"] != "model" or not report["evidence"]["model_inference_executed"] or
                not report["summary"]["eligible_for_model_comparison"] or report["metrics"] is None or
                report["summary"]["coverage"] != 1 or report["summary"]["error_cases"] or
                report["summary"]["unstable_cases"] or report["summary"]["warmup_error_count"]):
            raise ValueError("incomplete/non-model report: " + role)
        if execution["variant"] != variant or report["protocol_sha256"] != protocol_sha:
            raise ValueError("wrong variant or protocol: " + role)
        for section, fields in (("data", ("data_sha256", "exclusion_sha256", "rows", "family_count")),
                                ("runtime", ("machine", "system", "python")),
                                ("config", ("repeats", "warmup_suites", "batch_size", "order", "metric_unit"))):
            if any(report[section][key] != reference[section][key] for key in fields):
                raise ValueError("mismatched " + section + ": " + role)
        if report["packages"] != reference["packages"] or any(execution[k] != reference["backend"]["execution"][k] for k in matching):
            raise ValueError("mismatched runtime conditions: " + role)
        measured = report["data"]["rows"] * report["config"]["repeats"]
        expected_forwards = report["data"]["rows"] * (report["config"]["repeats"] + report["config"]["warmup_suites"])
        if (report["forward_passes"] != expected_forwards or report["metrics"]["n"] != report["data"]["rows"] or
                report["latency"]["successful_attempts"]["count"] != measured):
            raise ValueError("invalid forward/metric/latency support: " + role)
        rows.append({"role": role, "variant": variant,
                     "comparison_role": "additional_baseline" if role == "gliclass-base" else "primary",
                     "status": "executed", "metrics": report["metrics"],
                     "latency": report["latency"]["successful_attempts"],
                     "model_revision": execution["model_revision"], "packages": report["packages"],
                     "parameter_count": execution["parameter_count"], "forward_passes": report["forward_passes"]})
    if (llama_preflight.get("status") != "not_run_memory_limit" or
            llama_preflight.get("model_inference_executed") is not False or
            llama_preflight.get("f1") is not None or llama_preflight.get("latency_ms") is not None or
            llama_preflight["data_sha256"] != reference["data"]["data_sha256"] or
            llama_preflight["protocol_sha256"] != protocol_sha):
        raise ValueError("invalid or mismatched Llama preflight")
    return {"data": reference["data"], "protocol_sha256": protocol_sha,
            "conditions": {k: reference["backend"]["execution"][k] for k in matching},
            "rows": rows + [{"role": "llama-guard4", "comparison_role": "primary", "status": "not_run_memory_limit",
                             "metrics": None, "latency": None, "preflight": llama_preflight}],
            "three_model_comparison_complete": False,
            "scope": "24 human-reviewed synthetic texts; 12 source groups; not deployment validation",
            "caveats": ["GLiClass baseline blocked every benign input; F1 alone is misleading.",
                        "Prior head tuning used only excluded study material; not trained on eval.jsonl.",
                        "Laya uses typed questions; Llama Guard uses a different vanilla content-safety taxonomy.",
                        "Runs were sequential in separate processes, interrupted in wall-clock time; thermal/load conditions not controlled.",
                        "Llama Guard was not downloaded, executed, or replaced with a quantized model."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    protocol, sha = read_protocol()
    reports = {role: json.loads((args.reports_dir / (role + ".json")).read_text(encoding="utf-8")) for role in ROLES}
    llama = json.loads((args.reports_dir / "llama-preflight.json").read_text(encoding="utf-8"))
    frozen = audit_files(root / "eval.jsonl", root / "data_manifest.json", "benchmark")
    for report in reports.values():
        if report["data"]["data_sha256"] != frozen["data_sha256"]:
            raise ValueError("report uses a different frozen dataset")
        for relative, expected in report["runtime"]["source_files_sha256"].items():
            path = root.parent / relative
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("executed source differs from current files: " + relative)
    result = compare(reports, llama, sha)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("THREE_MODEL_COMPARISON_COMPLETE=false")
    for row in result["rows"]:
        if row["metrics"] is None:
            print(row["role"] + ": status=" + row["status"] + " F1=null LATENCY_MS=null")
        else:
            print("{}: F1={:.3f} FPR={:.3f} mean_ms={:.3f} p95_ms={:.3f}".format(
                row["role"], row["metrics"]["f1"], row["metrics"]["fpr"], row["latency"]["mean_ms"], row["latency"]["p95_ms"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
