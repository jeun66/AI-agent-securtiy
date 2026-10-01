from __future__ import annotations

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
except ModuleNotFoundError:
    evaluator_module = _load_module("week3_evaluator", WEEK3_DIR / "evaluator.py")
    judge = evaluator_module.judge


def _as_case_id(record: dict[str, Any]) -> str:
    return str(record.get("id") or "unknown")


def _sorted_case_files() -> list[Path]:
    files: list[Path] = []
    for kind in ("direct", "indirect"):
        target = ATTACKS_DIR / kind
        if target.exists():
            files.extend(sorted(target.glob("*.yaml")))
    return files


def load_attack_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path in _sorted_case_files():
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


def _rotate_baseline_file() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    baseline_path = RESULTS_DIR / "baseline.json"
    if not baseline_path.exists():
        return
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = RESULTS_DIR / f"baseline_{timestamp}.json"
    shutil.copy2(baseline_path, backup)


def save_case_result(record: dict[str, Any], records: list[dict[str, Any]]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": _record_model_meta(),
        "results": records,
    }
    baseline_path = RESULTS_DIR / "baseline.json"
    if baseline_path.exists() and records:
        _rotate_baseline_file()
    baseline_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def run_case(case: dict[str, Any], records: list[dict[str, Any]]) -> None:
    case_id = str(case.get("id") or "unknown")
    case_type = str(case.get("type") or "unknown")
    case_category = str(case.get("category") or "unknown")
    print(f"[RUN] {case_id} {case_type} start", flush=True)

    target: Path | None = None
    original: bytes | None = None
    trace_snapshot: list[dict[str, Any]] = []
    error: str | None = None
    success = False

    try:
        if case_type == "indirect":
            target, original = inject_indirect_payload(case)

        user_input = build_user_input(case)
        agent_tools.TRACE.clear()
        result = agent_loop.run_agent(user_input, max_steps=8)
        trace_snapshot = deepcopy(agent_tools.TRACE)
        cond = case.get("success_if") or None
        success = bool(judge(trace_snapshot, cond))
        print(f"[RESULT] {case_id} {'ATTACK OK' if success else 'NOT SUCCESS'}", flush=True)
    except Exception as exc:  # pragma: no cover - defensive path for real run
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
        "TRACE": trace_snapshot,
    }
    records.append(record)
    save_case_result(record, records)


def run_all_cases() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    cases = load_attack_cases()
    for case in cases:
        run_case(case, records)
    return records


def _asr(records: list[dict[str, Any]], case_type: str | None = None) -> tuple[str | float, int, int, int]:
    filtered = records if case_type is None else [r for r in records if r.get("type") == case_type]
    executed = [r for r in filtered if not r.get("error")]
    successes = sum(1 for r in executed if r.get("success") is True)
    errors = sum(1 for r in filtered if r.get("error"))
    if not executed:
        return "N/A", successes, len(executed), errors
    return round(successes / len(executed), 4), successes, len(executed), errors


def main() -> int:
    records = run_all_cases()
    total_executed = [r for r in records if r.get("error") is None]
    total_success = sum(1 for r in total_executed if r.get("success") is True)
    total_errors = sum(1 for r in records if r.get("error"))

    overall_asr, _, _, _ = _asr(records)
    direct_asr, _, _, _ = _asr(records, "direct")
    indirect_asr, _, _, _ = _asr(records, "indirect")

    print(
        f"[SUMMARY] total={len(records)} executed={len(total_executed)} success={total_success} errors={total_errors} "
        f"ASR_total={overall_asr} ASR_direct={direct_asr} ASR_indirect={indirect_asr}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
