"""W8 step 8: evidence-backed cross-layer scoreboard; no fabricated measurements.

Scores with different attack denominators or semantic definitions are NEVER
combined into one misleading ranking. Absent measurements remain null.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from week7.audit import verify_audit
from week8.ablation import conditions
from week8.patch_compare import compare as compare_patches
from week8.model_suite import ROLES

ROOT = Path(__file__).resolve().parents[1]


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _hash(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _verify_audit_bundle(report_path):
    folder = Path(report_path).parent
    required = (folder / "audit.jsonl", folder / "audit-signer.did", folder / "checkpoint.json")
    if not all(p.is_file() for p in required):
        raise ValueError("missing_signed_evidence:" + str(folder))
    signer = required[1].read_text(encoding="ascii").strip()
    result = verify_audit(required[0], signer=signer, checkpoint=required[2])
    if result.missing_executions:
        raise ValueError("incomplete_audit_executions:" + str(folder))
    return {"signer": signer, "merkle_root": result.merkle_root,
            "signed_events": len(result.events),
            "audit_sha256": _hash(required[0]), "checkpoint_sha256": _hash(required[2])}


def _ratio(success, total, observed):
    if type(success) is not int or type(total) is not int or total <= 0 or not 0 <= success <= total:
        raise ValueError("invalid_numerator_denominator")
    actual = success / total
    if not isinstance(observed, (float, int)) or abs(actual - observed) > 1e-10:
        raise ValueError("inconsistent_reported_ratio")
    return actual


def _row(scope, name, *, denominator=None, asr=None, adaptive_asr=None,
         utility=None, fpr=None, p50=None, p95=None, source=None):
    return {"scope": scope, "config": name, "attack_tasks": denominator, "ASR": asr,
            "adaptive_ASR": adaptive_asr, "Utility": utility, "FPR": fpr,
            "p50_ms": p50, "p95_ms": p95, "source_key": source}


def _baseline_rows(report):
    if not isinstance(report.get("modes"), dict):
        raise ValueError("invalid_W7_baseline")
    rows = []
    for name in ("baseline", "policy_only", "full"):
        item = report["modes"][name]
        attack = _ratio(item["attack_successes"], item["attack_cases"], item["asr"])
        normal = _ratio(item["normal_successes"], item["normal_cases"], item["utility"])
        if item["attack_cases"] != 11 or item["normal_cases"] != 2:
            raise ValueError("unexpected_W7_original_task_count")
        if abs(1 - normal - item["fpr"]) > 1e-10:
            raise ValueError("inconsistent_false_positive_rate")
        lat = item["latency"]
        rows.append(_row("W7_original_11_tasks", name, denominator=11, asr=attack,
                         utility=normal, fpr=item["fpr"],
                         p50=lat["p50_ms"], p95=lat["p95_ms"], source="w7_baseline"))
    return rows


def _adaptive_row(report, phase):
    if report.get("schema") != f"w8-adaptive-{phase}-v1":
        raise ValueError("incorrect_adaptive_phase:" + phase)
    group = report["w7"]
    tasks = [x for x in report["tasks"] if x["task_id"] != "taint_split"]
    if len(tasks) != 8 or group["original_tasks"] != 8:
        raise ValueError("wrong_adaptive_task_denominator")
    count = sum(bool(t["success"]) for t in tasks)
    _ratio(count, 8, group["asr"])
    if report["mode"] != "w7_plus_taint_guard":
        raise ValueError("unexpected_adaptive_defense_mode")
    lat = report["latency"]
    return _row("W8_adaptive_8_tasks", f"full_{phase}_patch",
                denominator=8, adaptive_asr=group["asr"], utility=report["utility"],
                fpr=report["fpr"], p50=lat["p50_ms"], p95=lat["p95_ms"],
                source="adaptive_" + phase)


def _ablation_rows(report):
    if report.get("schema") != "w8-real-layer-ablation-v1":
        raise ValueError("unexpected_ablation_schema")
    expected = {name: (enabled, kind) for name, enabled, kind in conditions()}
    actual = {r["config"]: r for r in report["configs"]}
    if set(expected) != set(actual) or len(actual) != len(report["configs"]):
        raise ValueError("incomplete_ablation_matrix")
    rows = []
    for name, (enabled, kind) in expected.items():
        item = actual[name]
        if set(item["enabled_layers"]) != set(enabled) or item["condition_kind"] != kind:
            raise ValueError("mismatched_ablation_switches:" + name)
        if item["w7_attack_cases"] != 12 or item["normal_cases"] != 2:
            raise ValueError("ablation_denominator_not_12")
        attack = _ratio(item["w7_attack_successes"], 12, item["asr"])
        utility = _ratio(item["normal_successes"], 2, item["utility"])
        if abs(1 - utility - item["fpr"]) > 1e-10:
            raise ValueError("ablation_fpr_mismatch")
        rows.append(_row("W8_ablation_12_tasks", name, denominator=12, asr=attack,
                         utility=utility, fpr=item["fpr"],
                         p50=item["latency"]["p50_ms"], p95=item["latency"]["p95_ms"],
                         source="ablation"))
    return rows


def _pending(scope, names, count=None):
    return [_row(scope, x, denominator=count) for x in names]


def _code_head():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                       text=True, stderr=subprocess.DEVNULL, timeout=3).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def aggregate(paths, *, model_paths=None, gliner_path=None, anchor_dir=None,
              model_pipeline_paths=None, verify_anchor=False, ots="ots"):
    """Paths are explicit evidence inputs. Missing inputs produce null rows."""
    files, audits, data = {}, {}, {}
    for name in ("w7_baseline", "adaptive_before", "adaptive_after", "ablation", "model_comparison"):
        path = (model_paths or {}).get(name) if name == "model_comparison" else paths.get(name)
        if path is not None:
            path = Path(path)
            files[name] = {"path": str(path.resolve()), "sha256": _hash(path)}
            data[name] = _load(path)
            if name in ("w7_baseline", "adaptive_before", "adaptive_after", "ablation"):
                audits[name] = _verify_audit_bundle(path)
    if "model_comparison" in data and data["model_comparison"].get("schema") != "w8-model-comparison-v1":
        raise ValueError("unverified_model_comparison_schema")
    if "model_comparison" in data:
        from week8.model_suite import comparison as verify_model_comparison
        from guardrail.model_backends import read_protocol
        from guardrail.validate_data import audit_files
        protocol, sha = read_protocol()
        snapshot = audit_files(ROOT / "guardrail/eval.jsonl", ROOT / "guardrail/data_manifest.json", "benchmark")
        if (data["model_comparison"].get("protocol_sha256") != sha or
                data["model_comparison"].get("data_sha256") != snapshot["data_sha256"]):
            raise ValueError("model_comparison_protocol_mismatch")
        declared = data["model_comparison"].get("source_reports")
        if not isinstance(declared, dict):
            raise ValueError("missing_model_source_reports")
        raw_reports = {}
        for role, info in declared.items():
            if role not in ROLES or _hash(info["path"]) != info["sha256"]:
                raise ValueError("model_source_report_hash_mismatch")
            raw_reports[role] = _load(info["path"])
        original_preflight = data["model_comparison"].get("preflight")
        preflight = None
        if original_preflight is not None:
            if _hash(original_preflight["path"]) != original_preflight["sha256"]:
                raise ValueError("model_preflight_hash_mismatch")
            preflight = _load(original_preflight["path"])
        checked = verify_model_comparison(raw_reports, protocol_sha=sha,
                 data_sha=snapshot["data_sha256"], expected_n=snapshot["rows"],
                 preflight=preflight)
        for name in ("rows", "three_model_comparison_complete"):
            if checked[name] != data["model_comparison"].get(name):
                raise ValueError("model_comparison_not_reproducible")
    if gliner_path:
        span = _load(gliner_path)
        if span.get("schema") != "w8-gliner-pii-span-v1" or span.get("model_inference_executed") is not True:
            raise ValueError("invalid_gliner_actual_measurement")
        data["gliner_span"] = span
        files["gliner_span"] = {"path": str(Path(gliner_path).resolve()), "sha256": _hash(gliner_path)}
    pipelines = {}
    for role, path in (model_pipeline_paths or {}).items():
        if role not in ROLES or role in pipelines:
            raise ValueError("invalid_model_pipeline_role")
        sample = _load(path)
        if (sample.get("schema") != "w8-model-pipeline-probe-v1" or
                sample.get("model_backend") != role or
                sample.get("guard", {}).get("kind") != "model" or
                type(sample.get("model_forward_passes")) is not int or
                sample["model_forward_passes"] < 4 or
                len(sample.get("probes", [])) != 4):
            raise ValueError("invalid_actual_model_pipeline_probe:" + role)
        file_key = "pipeline_" + role
        files[file_key] = {"path": str(Path(path).resolve()), "sha256": _hash(path)}
        audits[file_key] = _verify_audit_bundle(path)
        pipelines[role] = {"status": "executed", "forward_passes": sample["model_forward_passes"],
                           "probe_results": [{"case": row["case"],
                                              "tool_invoked": row["outcome"]["tool_invoked"],
                                              "decision": row["outcome"]["decision"]}
                                             for row in sample["probes"]]}
    rows = _baseline_rows(data["w7_baseline"]) if "w7_baseline" in data else _pending(
        "W7_original_11_tasks", ("baseline", "policy_only", "full"), 11)
    for phase in ("before", "after"):
        key = "adaptive_" + phase
        rows += [_adaptive_row(data[key], phase)] if key in data else _pending(
            "W8_adaptive_8_tasks", ("full_" + phase + "_patch",), 8)
    if "adaptive_before" in data and "adaptive_after" in data:
        patch = compare_patches(data["adaptive_before"], data["adaptive_after"])
    else:
        patch = None
    rows += (_ablation_rows(data["ablation"]) if "ablation" in data else
             _pending("W8_ablation_12_tasks", [name for name, _, _ in conditions()], 12))
    model = data.get("model_comparison")
    if model is None:
        model = {"three_model_comparison_complete": False,
                 "rows": [{"role": role, "status": "not_run", "accuracy": None, "f1": None,
                           "fpr": None, "p50_ms": None, "p95_ms": None} for role in ROLES]}
    anchor = {"state": "not_submitted", "bitcoin_verified_in_this_run": False}
    if anchor_dir is not None:
        from week8.ots_anchor import inspect_evidence, anchor as ots_anchor
        directory = Path(anchor_dir)
        checked = inspect_evidence(directory)
        anchor = {"state": "checkpoint_verified_ots_unverified", "bitcoin_verified_in_this_run": False,
                  "merkle_root": checked["merkle_root"]}
        manifest = directory / "anchor-status.json"
        if manifest.is_file():
            stamp = _load(manifest)
            if stamp.get("checkpoint_sha256") != checked["checkpoint_sha256"]:
                raise ValueError("anchored_checkpoint_hash_mismatch")
            proof = directory / "checkpoint.json.ots"
            if not proof.is_file() or stamp.get("proof_sha256") != _hash(proof):
                raise ValueError("missing_or_mismatched_ots_proof")
            anchor.update(ots_recorded_state=stamp.get("state"),
                          note="OTS evidence present; re-run week8.ots_anchor verify for independent Bitcoin confirmation")
            if verify_anchor:
                checked_ots = ots_anchor(directory, action="verify", ots=ots)
                anchor.update(state=checked_ots["state"],
                              bitcoin_verified_in_this_run=checked_ots["state"] == "verified")
    elif verify_anchor:
        raise ValueError("anchor_directory_required_for_verification")
    complete = set(("w7_baseline", "adaptive_before", "adaptive_after", "ablation", "model_comparison")) <= set(data)
    all_gates = (complete and patch is not None and
                 model.get("three_model_comparison_complete") is True and
                 anchor["bitcoin_verified_in_this_run"] and
                 all(role in pipelines for role in ("gliclass-trained", "laya", "llama-guard4")))
    return {"schema": "w8-evidence-leaderboard-v1", "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_head": _code_head(), "source_reports": files, "verified_audit_bundles": audits,
            "report_inputs_present": complete, "all_gates_complete": all_gates,
            "scores": rows, "patch_comparison": patch, "model_comparison": model,
            "model_pipeline_probes": pipelines,
            "gliner_pii_spans": data.get("gliner_span"), "external_anchor": anchor,
            "scope_rules": ["W7 11 tasks, W8 adaptive 8 tasks, ablation 12 tasks use DIFFERENT denominators",
                            "Text-model binary F1/FPR is from 24 fixed inputs, not an observed unauthorized tool-action ASR",
                            "Model pipeline probes are separate from adaptive ASR",
                            "Missing measurements remain null; benchmark results are never back-filled",
                            "Bitcoin anchor status is not independently verified in this aggregation command"]}


def markdown(report):
    def fmt(value, percent=False):
        return "—" if value is None else (f"{value:.1%}" if percent else f"{value:.3f}")
    lines = ["# W8 integrated evidence leaderboard", "",
             "Different denominators have separate sections. Empty cells mean **not measured**.", ""]
    for scope in ("W7_original_11_tasks", "W8_adaptive_8_tasks", "W8_ablation_12_tasks"):
        lines.extend(["## " + scope, "", "| Configuration | ASR | Adaptive ASR | Utility | FPR | p50 ms | p95 ms |",
                      "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
        for item in report["scores"]:
            if item["scope"] != scope:
                continue
            lines.append("| " + " | ".join((item["config"], fmt(item["ASR"], True),
                fmt(item["adaptive_ASR"], True), fmt(item["Utility"], True),
                fmt(item["FPR"], True), fmt(item["p50_ms"]), fmt(item["p95_ms"]))) + " |")
        lines.append("")
    lines.extend(["## Actual model inference (text classification, n=24)", "",
                  "| Model | Status | Accuracy | F1 | FPR | p50 ms | p95 ms |",
                  "| --- | --- | ---: | ---: | ---: | ---: | ---: |"])
    for row in report["model_comparison"]["rows"]:
        lines.append("| " + " | ".join([row["role"], row["status"],
             fmt(row.get("accuracy"), True), fmt(row.get("f1")),
             fmt(row.get("fpr"), True), fmt(row.get("p50_ms")),
             fmt(row.get("p95_ms"))]) + " |")
    lines.extend(["", "GLiNER output PII exact-span F1 (separate): " +
                  (fmt(report["gliner_pii_spans"]["span_metrics"]["f1"]) if report["gliner_pii_spans"] else "—"),
                  "External anchor (reverification needed): " + report["external_anchor"]["state"],
                  "Report inputs present: " + str(report["report_inputs_present"]),
                  "All gates complete (incl. real models + external Bitcoin reverify): " + str(report["all_gates_complete"]), "",
                  "## Evidence", "", "Files, SHA-256, signer DID and verified Merkle roots are indexed in evidence-index.json.",
                  "Do not treat the historical model study or a pending OTS proof as a new complete W8 run."])
    return "\n".join(lines) + "\n"


def save(report, directory):
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("output directory must be empty")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "leaderboard.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "leaderboard.md").write_text(markdown(report), encoding="utf-8")
    evidence = {k: report[k] for k in ("source_head", "source_reports", "verified_audit_bundles", "external_anchor")}
    (directory / "evidence-index.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "CAPTURE_CHECKLIST.md").write_text(
        "# Screenshot / proof checklist\n\n"
        "- W7 baseline pytest result, code/data/OPA version manifest and 11-case table\n"
        "- Signed request approval preview: operation, target, risk, and command hash\n"
        "- Stage-3 prepatch 8-task adaptive trace and mock taint test\n"
        "- Stage-4 afterpatch trace, paired ASR comparison, fixed normal requests\n"
        "- Stage-5 original/tampered/truncated audit checks, OTS stamp, upgrade and confirmed Bitcoin verification if available\n"
        "- Stage-6 cumulative and leave-one-out table with signed logs\n"
        "- Stage-7 actual model forward-pass, accuracy/F1/FPR/p50/p95; missing 12B stays blank\n"
        "- Stage-8 leaderboard, git commit and source-report SHA-256 evidence index\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("w7-baseline", "adaptive-before", "adaptive-after", "ablation", "model-comparison"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--gliner-span", type=Path)
    parser.add_argument("--model-pipeline", action="append", default=[], metavar="ROLE=REPORT_PATH")
    parser.add_argument("--anchor-evidence-dir", type=Path)
    parser.add_argument("--verify-anchor", action="store_true",
                        help="Re-check external OTS Bitcoin confirmation during aggregation")
    parser.add_argument("--ots", default="ots")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    paths = {key: getattr(args, key) for key in ("w7_baseline", "adaptive_before", "adaptive_after", "ablation")}
    pipeline_paths = {}
    for entry in args.model_pipeline:
        role, sep, path = entry.partition("=")
        if not sep or not path or role in pipeline_paths:
            parser.error("--model-pipeline requires unique ROLE=REPORT_PATH")
        pipeline_paths[role] = Path(path)
    result = aggregate(paths, model_paths={"model_comparison": args.model_comparison},
                       gliner_path=args.gliner_span, anchor_dir=args.anchor_evidence_dir,
                       model_pipeline_paths=pipeline_paths,
                       verify_anchor=args.verify_anchor, ots=args.ots)
    save(result, args.output_dir)
    print(markdown(result), end="")


if __name__ == "__main__":
    main()