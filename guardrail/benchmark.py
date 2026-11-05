"""Measure Guard.check on frozen eval data. CLI backends here are smoke tests only."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

from guardrail.validate_data import LABELS, DataError, audit_files
from week5.guards import GuardRequest, GuardResult, MockGuard, RuleGuard


def binary_metrics(pairs):
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for expected, predicted in pairs:
        if type(expected) is not int or type(predicted) is not int or expected not in (0, 1) or predicted not in (0, 1):
            raise ValueError("binary metrics require integer 0/1 pairs")
        key = ("tn", "fp", "fn", "tp")[expected * 2 + predicted]
        counts[key] += 1
    tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))
    ratio = lambda a, b: a / b if b else None
    return dict(counts, n=tp + fp + tn + fn,
                accuracy=ratio(tp + tn, tp + fp + tn + fn),
                precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                f1=ratio(2 * tp, 2 * tp + fp + fn),
                fpr=ratio(fp, fp + tn), fnr=ratio(fn, fn + tp))


def latency_stats(values):
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool)
               and math.isfinite(v) and v >= 0 for v in values):
        raise ValueError("latency must be finite and nonnegative")
    ordered = sorted(values)
    return {"count": len(values), "mean_ms": statistics.mean(values) if values else None,
            "p50_ms": statistics.median(values) if values else None,
            "p95_ms": ordered[math.ceil(0.95 * len(ordered)) - 1] if values else None}


def timed_check(guard, text, synchronize, clock):
    request = GuardRequest(direction="input", text=text)
    started, elapsed, stage = None, None, "synchronize_before"
    try:
        # GPU backends must supply a real synchronization callback; CPU uses a no-op.
        synchronize()
        stage = "clock_start"
        started = clock()
        stage = "guard_check"
        result = guard.check(request)
        stage = "synchronize_after"
        synchronize()
        stage = "clock_end"
        elapsed = (clock() - started) * 1000
        if not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError("invalid elapsed time")
        stage = "result_validation"
        if not isinstance(result, GuardResult):
            raise TypeError("expected GuardResult")
        if result.decision not in ("allow", "block"):
            raise ValueError("unknown decision")
        if result.kind != guard.kind or result.backend != guard.name:
            raise ValueError("backend identity mismatch")
        return {"status": "ok", "decision": result.decision, "elapsed_ms": elapsed,
                "findings": [f.to_log() for f in result.findings],
                "error_type": None, "error_stage": None}
    except Exception as exc:
        # Exceptions are errors, never attack detections. Messages may contain raw input.
        # Do not log them or mix error timing with successful inference latency.
        return {"status": "error", "decision": None, "elapsed_ms": None, "findings": [],
                "error_type": type(exc).__name__, "error_stage": stage}


def run_guard(guard, rows, repeats=3, warmup=1, synchronize=None, clock=time.perf_counter, execution=None):
    """Core runner. evaluate_file is the public frozen-data entry point.

    Warmup counts full suites. Metrics use one vote per unique row, not repeats.
    Any warmup error, failed repeat, or unstable decision invalidates headline metrics.
    """
    if type(repeats) is not int or repeats < 1 or type(warmup) is not int or warmup < 0:
        raise ValueError("repeats >= 1 and warmup >= 0 must be integers")
    if guard.kind not in ("rule", "mock", "model") or not isinstance(guard.name, str) or not guard.name:
        raise ValueError("guard must declare valid kind and name")
    execution = dict(execution or {})
    if guard.kind == "model":
        for field in ("model_id", "model_revision", "variant", "device", "dtype", "decision_policy"):
            if not isinstance(execution.get(field), str) or not execution[field].strip():
                raise ValueError("model execution metadata requires " + field)
        if type(execution.get("threads")) is not int or execution["threads"] < 1:
            raise ValueError("model execution metadata requires positive threads")
        if execution["device"] != "cpu" and synchronize is None:
            raise ValueError("non-CPU models require an explicit synchronization callback")
    if not rows:
        raise ValueError("empty evaluation data")
    ids = set()
    for row in rows:
        if not isinstance(row.get("id"), str) or not row["id"] or row["id"] in ids:
            raise ValueError("empty/duplicate evaluation id")
        if row.get("label") not in LABELS or not isinstance(row.get("text"), str) or not row["text"].strip():
            raise ValueError("unknown label or empty text")
        ids.add(row["id"])
    explicit_sync = synchronize is not None
    synchronize = synchronize or (lambda: None)
    warmup_errors = []
    for suite in range(warmup):
        for row in rows:
            event = timed_check(guard, row["text"], synchronize, clock)
            if event["status"] != "ok":
                warmup_errors.append(dict(id=row["id"], suite=suite, error_type=event["error_type"],
                                          error_stage=event["error_stage"]))
    cases = {row["id"]: {"id": row["id"], "label": row["label"],
                          "language": row.get("language"), "attempts": []} for row in rows}
    # Repeat the full fixed order rather than timing one example many times in a row.
    for repeat in range(repeats):
        for row in rows:
            event = timed_check(guard, row["text"], synchronize, clock)
            cases[row["id"]]["attempts"].append(dict(event, repeat=repeat))
    for case in cases.values():
        decisions = {e["decision"] for e in case["attempts"] if e["status"] == "ok"}
        if any(e["status"] != "ok" for e in case["attempts"]):
            case.update(status="error", decision=None, prediction=None)
        elif len(decisions) != 1:
            case.update(status="unstable", decision=None, prediction=None)
        else:
            decision = decisions.pop()
            case.update(status="ok", decision=decision, prediction=int(decision == "block"))
    completed = [c for c in cases.values() if c["status"] == "ok"]
    diagnostics = binary_metrics([(int(c["label"] != "benign"), c["prediction"]) for c in completed])
    successful_ms = [e["elapsed_ms"] for c in cases.values() for e in c["attempts"] if e["status"] == "ok"]
    run_valid = len(completed) == len(rows) and not warmup_errors
    eligible = guard.kind == "model" and run_valid
    return {
        "backend": {"name": guard.name, "kind": guard.kind, "execution": execution},
        "evidence": {"model_inference_executed": guard.kind == "model",
                     "backend_kind_source": "caller_supplied_guard_declaration",
                     "scope": "model_benchmark" if guard.kind == "model" else "smoke_only_not_model_performance",
                     "training_executed": False, "runner_network_requests_executed": False,
                     "real_mcp_executed": False, "agent_asr_measured": False},
        "config": {"repeats": repeats, "warmup_suites": warmup, "batch_size": 1,
                   "order": "fixed_file_order_each_repeat", "metric_unit": "one_unique_row",
                   "synchronization": "caller_callback" if explicit_sync else "unspecified_or_cpu_noop"},
        "summary": {"total_cases": len(rows), "completed_cases": len(completed),
                    "error_cases": sum(c["status"] == "error" for c in cases.values()),
                    "unstable_cases": sum(c["status"] == "unstable" for c in cases.values()),
                    "coverage": len(completed) / len(rows), "warmup_error_count": len(warmup_errors),
                    "measurement_valid": run_valid, "eligible_for_model_comparison": eligible},
        "metrics": diagnostics if eligible else None,
        "diagnostics": {"completed_case_metrics": diagnostics,
                        "warning": "Uses only cases with every repeat valid and consistent; never substitutes for incomplete/model headline metrics."},
        "latency": {"scope": "successful guard.check plus device synchronization; excludes warmup/loading/file I/O/metric calculation",
                    "successful_attempts": latency_stats(successful_ms),
                    "model_loading_ms": None,
                    "errors_excluded_from_latency": len(rows) * repeats - len(successful_ms)},
        "warmup_errors": warmup_errors, "cases": list(cases.values()),
    }


def evaluate_file(guard, data, manifest, **kwargs):
    snapshot = Path(data).read_bytes()
    data_report = audit_files(data, manifest, "benchmark")
    if hashlib.sha256(snapshot).hexdigest() != data_report["data_sha256"]:
        raise DataError("evaluation data changed while loading")
    rows = [json.loads(line) for line in snapshot.decode("utf-8").splitlines() if line.strip()]
    report = run_guard(guard, rows, **kwargs)
    report["data"] = {k: data_report[k] for k in ("data_sha256", "exclusion_sha256", "base_commit",
                                                     "rows", "source_count", "family_count")}
    report["runtime"] = {"created_at_utc": datetime.now(timezone.utc).isoformat(),
                         "python": platform.python_version(), "system": platform.system(),
                         "machine": platform.machine()}
    source_root = Path(__file__).resolve().parents[1]
    try:
        report["runtime"]["source_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source_root, stderr=subprocess.DEVNULL, text=True).strip()
        report["runtime"]["working_tree_dirty"] = bool(subprocess.check_output(
            ["git", "--no-optional-locks", "status", "--porcelain"], cwd=source_root,
            stderr=subprocess.DEVNULL, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        report["runtime"].update(source_commit=None, working_tree_dirty=None)
    files = [Path(__file__), source_root / "guardrail/validate_data.py", source_root / "week5/guards.py"]
    report["runtime"]["source_files_sha256"] = {
        str(p.relative_to(source_root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    return report


def save_report(report, output):
    output = Path(output)
    csv_path = output.with_suffix(".csv")
    if output.suffix != ".json" or output.resolve() == csv_path.resolve():
        raise ValueError("report output must end with .json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    fields = ["id", "label", "language", "case_status", "repeat", "status", "decision", "elapsed_ms", "error_type", "error_stage"]
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for case in report["cases"]:
            for attempt in case["attempts"]:
                row = {k: attempt.get(k) for k in fields}
                row.update(id=case["id"], label=case["label"], language=case["language"], case_status=case["status"])
                writer.writerow(row)
    return csv_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument("--backend", choices=("rules", "mock"), required=True)
    parser.add_argument("--mock-decision", choices=("allow", "block"), default="allow")
    parser.add_argument("--data", type=Path, default=root / "eval.jsonl")
    parser.add_argument("--manifest", type=Path, default=root / "data_manifest.json")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.suffix != ".json":
        parser.error("report output must end with .json")
    # Prevent accidental replacement of frozen inputs or implementation sources.
    package = root.resolve()
    outputs = [args.output.resolve(), args.output.with_suffix(".csv").resolve()]
    protected = {args.data.resolve(), args.manifest.resolve()}
    if any(p in protected or package == p or package in p.parents for p in outputs):
        parser.error("write reports outside guardrail/ and do not overwrite input files")
    guard = RuleGuard() if args.backend == "rules" else MockGuard(args.mock_decision)
    try:
        report = evaluate_file(guard, args.data, args.manifest, repeats=args.repeats, warmup=args.warmup)
        csv_path = save_report(report, args.output)
    except (ValueError, OSError, KeyError) as exc:
        print("BENCHMARK_FAILED: " + str(exc), file=sys.stderr)
        return 2
    print("RUN_KIND=smoke_only MODEL_INFERENCE=false")
    print("SUMMARY=" + json.dumps(report["summary"], sort_keys=True))
    print("MODEL_METRICS=null")
    print("DIAGNOSTIC_METRICS=" + json.dumps(report["diagnostics"]["completed_case_metrics"], sort_keys=True))
    print("LATENCY=" + json.dumps(report["latency"]["successful_attempts"], sort_keys=True))
    print("REPORT=" + str(args.output))
    print("ATTEMPTS_CSV=" + str(csv_path))
    return 0 if report["summary"]["measurement_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
