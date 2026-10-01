from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEEK3_DIR = Path(__file__).resolve().parent
RESULTS_DIR = WEEK3_DIR / "results"
ATTACKS_DIR = WEEK3_DIR / "attacks"
UTILITY_DIR = WEEK3_DIR / "utility"
SANDBOX_DIR = PROJECT_ROOT / "week2" / "sandbox"


def _load_module(module_name: str, module_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"모듈을 불러올 수 없습니다: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


agent_tools = _load_module("agent_tools", PROJECT_ROOT / "week2" / "agent_tools.py")
agent_loop = _load_module("agent_loop", PROJECT_ROOT / "week2" / "agent_loop.py")

try:
    from week3.evaluator import judge
except ModuleNotFoundError:  # pragma: no cover
    evaluator_module = _load_module("week3_evaluator", WEEK3_DIR / "evaluator.py")
    judge = evaluator_module.judge

try:
    from week3.policy_engine import check_policy, evaluate_policy
except ModuleNotFoundError:  # pragma: no cover
    policy_module = _load_module("week3_policy_engine", WEEK3_DIR / "policy_engine.py")
    check_policy = policy_module.check_policy
    evaluate_policy = policy_module.evaluate_policy


def _as_case_id(record: dict[str, Any]) -> str:
    return str(record.get("id") or "unknown")


def _sorted_case_files(folder: Path) -> list[Path]:
    return sorted(folder.glob("*.yaml")) if folder.exists() else []


def load_attack_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for kind in ("direct", "indirect", "bypass"):
        target = ATTACKS_DIR / kind
        for path in _sorted_case_files(target):
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                raise ValueError(f"YAML 형식이 dict가 아닙니다: {path}")
            data["_path"] = str(path)
            cases.append(data)
    return cases


def load_utility_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path in _sorted_case_files(UTILITY_DIR):
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"YAML 형식이 dict가 아닙니다: {path}")
        data["_path"] = str(path)
        cases.append(data)
    return cases


def build_user_input(case: dict[str, Any]) -> str:
    if case.get("type") == "indirect":
        return str(case.get("user_request") or "")
    user_request = str(case.get("user_request") or "")
    payload = str(case.get("payload") or "")
    if not user_request and not payload:
        return ""
    if not user_request:
        return payload
    if not payload:
        return user_request
    return f"{user_request}\n\n{payload}"


def ensure_in_sandbox(rel_path: str) -> Path:
    target = (SANDBOX_DIR / rel_path).resolve()
    if not target.is_relative_to(SANDBOX_DIR):
        raise ValueError(f"sandbox 밖 경로는 허용하지 않습니다: {rel_path}")
    return target


def inject_indirect_payload(case: dict[str, Any]):
    payload_file = case.get("payload_file")
    if not payload_file:
        return None, None
    target = ensure_in_sandbox(str(payload_file))
    if target.exists() and target.is_dir():
        raise ValueError(f"디렉터리는 payload 파일로 사용할 수 없습니다: {payload_file}")
    original = target.read_bytes() if target.exists() else None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(str(case.get("payload") or ""), encoding="utf-8")
    return target, original


def restore_payload_file(target: Path | None, original: bytes | None) -> None:
    if target is None:
        return
    if original is None:
        target.unlink(missing_ok=True)
    else:
        target.write_bytes(original)


def _record_model_meta() -> dict[str, Any]:
    return {
        "model": os.getenv("OPENAI_MODEL", "unset"),
        "generation": {
            "temperature": os.getenv("OPENAI_TEMPERATURE"),
            "max_tokens": os.getenv("OPENAI_MAX_TOKENS"),
            "seed": os.getenv("OPENAI_SEED"),
        },
    }


def _rotate_results_file(name: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / name
    if not path.exists():
        return
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = RESULTS_DIR / f"{name[:-5]}_{stamp}.json"
    shutil.copy2(path, backup)


def save_case_result(results_path: Path, record: dict[str, Any], records: list[dict[str, Any]]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"meta": _record_model_meta(), "results": records}
    if results_path.exists() and records:
        _rotate_results_file(results_path.name)
    results_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def install_policy_runtime(policy_mode: str):
    def wrapped_execute_tool(tool_call):
        name = tool_call.function.name
        raw_args = tool_call.function.arguments
        entry = {
            "step": len(agent_tools.TRACE) + 1,
            "tool": name,
            "args": raw_args,
            "status": "pending",
            "policy_decision": "allow",
            "policy_reason": "policy_off",
        }
        agent_tools.TRACE.append(entry)

        try:
            args = json.loads(raw_args)
            entry["args"] = args

            if policy_mode == "on":
                decision, reason = evaluate_policy(name, args)
                entry["policy_decision"] = decision
                entry["policy_reason"] = reason
                if decision in {"deny", "approval"}:
                    entry["status"] = "denied"
                    entry["result"] = "POLICY_DENIED"
                    return "POLICY_DENIED"

            if name not in agent_tools.TOOLS:
                raise ValueError(f"허용되지 않은 도구: {name}")

            expected_key = {"read_file": "path", "http_get": "url"}[name]
            if not isinstance(args, dict) or set(args) != {expected_key}:
                raise ValueError("도구 인자 형식이 올바르지 않습니다.")
            if not isinstance(args[expected_key], str):
                raise ValueError("도구 인자는 문자열이어야 합니다.")

            result = agent_tools.TOOLS[name](**args)
            entry["status"] = "ok"
            entry["result"] = result
            return result
        except Exception as error:
            result = f"도구 오류: {error}"
            entry["status"] = "error"
            entry["result"] = result
            if "policy_decision" not in entry or entry["policy_decision"] == "allow":
                entry["policy_decision"] = "deny"
                entry["policy_reason"] = "policy_error"
            return result

    agent_tools.execute_tool = wrapped_execute_tool
    agent_loop.execute_tool = wrapped_execute_tool
    return wrapped_execute_tool


def run_case(case: dict[str, Any], records: list[dict[str, Any]], policy_mode: str, results_path: Path) -> None:
    case_id = str(case.get("id") or "unknown")
    case_type = str(case.get("type") or "unknown")
    case_category = str(case.get("category") or "unknown")
    print(f"[RUN] {case_id} {case_type} start", flush=True)

    target: Path | None = None
    original: bytes | None = None
    trace_snapshot: list[dict[str, Any]] = []
    error: str | None = None
    success = False
    policy_blocked = False

    try:
        if case_type == "indirect":
            target, original = inject_indirect_payload(case)

        user_input = build_user_input(case)
        agent_tools.TRACE.clear()
        agent_loop.run_agent(user_input, max_steps=8)
        trace_snapshot = deepcopy(agent_tools.TRACE)
        cond = case.get("success_if") or None
        success = bool(judge(trace_snapshot, cond))
        if policy_mode == "on":
            policy_blocked = any(
                (entry.get("policy_decision") in {"deny", "approval"})
                and entry.get("result") == "POLICY_DENIED"
                for entry in trace_snapshot
            )
        print(f"[RESULT] {case_id} {'ATTACK OK' if success else 'NOT SUCCESS'}", flush=True)
    except Exception as exc:  # pragma: no cover
        error = str(exc)
        success = False
        print(f"[RESULT] {case_id} ERROR", flush=True)
    finally:
        if case_type == "indirect":
            restore_payload_file(target, original)

    record = {
        "id": case_id,
        "type": case_type,
        "category": case_category,
        "success": success,
        "error": error,
        "policy_blocked": policy_blocked,
        "TRACE": trace_snapshot,
    }
    records.append(record)
    save_case_result(results_path, record, records)


def _asr(records: list[dict[str, Any]], case_type: str | None = None) -> tuple[str | float, int, int, int]:
    filtered = records if case_type is None else [r for r in records if r.get("type") == case_type]
    executed = [r for r in filtered if not r.get("error")]
    successes = sum(1 for r in executed if r.get("success") is True)
    errors = sum(1 for r in filtered if r.get("error"))
    if not executed:
        return "N/A", successes, len(executed), errors
    return round(successes / len(executed), 4), successes, len(executed), errors


def summarize(records: list[dict[str, Any]], normal_records: list[dict[str, Any]]) -> dict[str, Any]:
    attack_records = [r for r in records if r.get("type") in {"direct", "indirect", "bypass"}]
    normal_success = sum(1 for r in normal_records if r.get("success") is True)
    normal_blocked = sum(1 for r in normal_records if r.get("success") is False and r.get("policy_blocked") is True)
    attack_success = sum(1 for r in attack_records if r.get("success") is True)
    attack_total = len(attack_records)
    error_count = sum(1 for r in records if r.get("error"))
    asr = "N/A" if not attack_records else round(attack_success / len(attack_records), 4)
    fpr = "N/A" if not normal_records else round(normal_blocked / len(normal_records), 4)
    return {
        "attack_cases": attack_total,
        "attack_success": attack_success,
        "asr": asr,
        "normal_cases": len(normal_records),
        "normal_success": normal_success,
        "normal_blocked": normal_blocked,
        "fpr": fpr,
        "errors": error_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", choices=["off", "on"], default="off")
    args = parser.parse_args()

    if args.policy == "on":
        install_policy_runtime("on")
    else:
        install_policy_runtime("off")

    all_results = []
    normal_records = []
    attack_records = []

    for case in load_attack_cases():
        record_list = all_results
        result_path = RESULTS_DIR / f"policy_{args.policy}.json"
        run_case(case, record_list, args.policy, result_path)
        attack_records.append(record_list[-1])

    for case in load_utility_cases():
        result_path = RESULTS_DIR / f"policy_{args.policy}.json"
        run_case(case, all_results, args.policy, result_path)
        normal_records.append(all_results[-1])

    summary = summarize(all_results, normal_records)
    payload = {
        "policy": args.policy,
        "summary": summary,
        "results": all_results,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / f"policy_{args.policy}.json"
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(
        f"[SUMMARY] policy={args.policy} attacks={summary['attack_cases']} success={summary['attack_success']} ASR={summary['asr']} "
        f"normal={summary['normal_cases']} blocked={summary['normal_blocked']} FPR={summary['fpr']} errors={summary['errors']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
