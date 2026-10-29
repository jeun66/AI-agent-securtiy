"""MCP-Guard-style local hooks: policy -> taint -> guardrail.

This is an in-process enforcement interface, not an MCP JSON-RPC transport.
"""
import json
import time
from week4.taint import Tainted, check_http_get, collect_sources, is_tainted
from week5.guards import GuardRequest, GuardResult

BLOCKED_OUTPUT = "[출력 가드에 의해 응답이 보류되었습니다.]"
from week5.prompts import HARDENED_SYSTEM_PROMPT


def _plain(value):
    if isinstance(value, Tainted):
        return _plain(value.value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


class DefenseHook:
    def __init__(self, input_guard, output_guard):
        self.input_guard = input_guard
        self.output_guard = output_guard

    def check(self, direction, text, *, context="", tool_name="", sources=()):
        guard = self.input_guard if direction == "input" else self.output_guard
        started = time.perf_counter()
        try:
            result = guard.check(GuardRequest(direction, text, context, tool_name, tuple(sources)))
            if not isinstance(result, GuardResult):
                raise TypeError("invalid guard result")
            if result.backend != guard.name or result.kind != guard.kind:
                raise ValueError("guard identity mismatch")
            log = result.to_log()
        except Exception:
            # Backend failures and malformed replies never permit execution/release.
            log = {"decision": "block", "backend": getattr(guard, "name", "missing"),
                   "kind": getattr(guard, "kind", "unavailable"),
                   "reason": "guard_error", "findings": []}
        log.update(direction=direction, elapsed_ms=(time.perf_counter() - started) * 1000)
        return log

    def filter_output(self, text, *, tool_name="", sources=()):
        check = self.check("output", text, tool_name=tool_name, sources=sources)
        return (text if check["decision"] == "allow" else BLOCKED_OUTPUT), check


def execute_guarded(tool_call, hook, *, trace, tools, input_text="", context_text=""):
    entry = {"step": len(trace) + 1, "tool": tool_call.function.name,
             "args": None, "executed_args": None, "status": "pending",
             "sources": [], "layers": [], "guard_checks": [],
             "tool_executed": False, "output_released": False}
    trace.append(entry)
    name = entry["tool"]
    try:
        args = json.loads(tool_call.function.arguments)
        key = {"http_get": "url", "read_file": "path"}.get(name)
        if name not in tools or key is None or not isinstance(args, dict) or set(args) != {key}:
            raise ValueError("schema")
        if not isinstance(args[key], str):
            raise ValueError("schema")
        raw = getattr(tool_call, "raw_args_obj", None)
        if raw is None:
            raw = args
        if _plain(raw) != args:
            raise ValueError("raw_args_mismatch")
        entry["sources"] = sorted(collect_sources(raw))
    except Exception:
        entry.update(status="error", block_reason="schema", result="denied: invalid_tool_arguments")
        return entry["result"]

    def layer(label, check):
        started = time.perf_counter()
        try:
            allowed, reason = check()
        except Exception:
            allowed, reason = False, "layer_error"
        entry["layers"].append({"layer": label, "decision": "allow" if allowed else "block",
                                "reason": reason, "elapsed_ms": (time.perf_counter() - started) * 1000})
        if not allowed:
            entry.update(status="denied", block_reason=label, result="denied_by_" + label + ": " + reason)
        return allowed

    def policy():
        from week3.policy_engine import evaluate_policy
        decision, reason = evaluate_policy(name, args)
        entry.update(policy_decision=decision, policy_reason=reason)
        return decision == "allow", reason

    def taint():
        if name == "http_get":
            return check_http_get(raw["url"])
        return not is_tainted(raw), "tainted_arg" if is_tainted(raw) else "allow"

    def input_guard():
        if not isinstance(hook, DefenseHook):
            return False, "guard_not_configured"
        check = hook.check("input", input_text,
                           context=context_text + "\n" + json.dumps(args, ensure_ascii=False),
                           tool_name=name, sources=entry["sources"])
        entry["guard_checks"].append(check)
        return check["decision"] == "allow", check["reason"]

    for label, check in (("policy", policy), ("taint", taint), ("guardrail", input_guard)):
        if not layer(label, check):
            entry["skipped_layers"] = [x for x in ("policy", "taint", "guardrail")
                                       if x not in [v["layer"] for v in entry["layers"]]]
            return entry["result"]

    # Do not retain plaintext arguments or raw tool output in the public audit log.
    # tool_executed distinguishes a post-execution output block from a pre-call denial.
    entry["tool_executed"] = True
    entry["args"] = {key: "[REDACTED]"}
    entry["executed_args"] = {key: "[REDACTED]"}
    try:
        result = tools[name](**args)
        if not isinstance(result, str):
            raise TypeError("expected a text tool result")
    except Exception:
        entry.update(status="error", block_reason="tool", result="tool_execution_error")
        return entry["result"]
    released, check = hook.filter_output(result, tool_name=name, sources=entry["sources"])
    entry["guard_checks"].append(check)
    entry["output_released"] = check["decision"] == "allow"
    if not entry["output_released"]:
        entry.update(status="output_blocked", block_reason="guardrail_output", result=BLOCKED_OUTPUT)
    else:
        entry.update(status="ok", result="[output checked; plaintext omitted from audit]")
    return released
