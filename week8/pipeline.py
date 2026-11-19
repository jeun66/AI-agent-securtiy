"""One instrumented call path: W7 trust -> OPA -> provenance -> guards -> local tool.

Stage 2 attaches W4 provenance and W5 input/output hooks to the real W7
Gateway rather than bypassing its identity, delegation or approval checks.
All state is invocation-local (ContextVar), including concurrent calls.
"""
from contextvars import ContextVar
from dataclasses import dataclass, field
from hashlib import sha256
from time import perf_counter_ns

from week4.taint import Tainted, collect_sources, is_tainted
from week5.defense import DefenseHook
from week7.gateway import Gateway, GatewayResult, Invocation

STAGES = ("identity", "delegation", "command", "policy", "approval", "taint",
          "input_guard", "tool", "output_guard")
W7_MODES = {"w7_full", "w7_plus_taint", "w7_plus_taint_guard"}
MODES = {"none", "policy_only", *W7_MODES}


@dataclass
class _RequestState:
    raw: object | None = None
    hook: DefenseHook | None = None
    events: list[dict] = field(default_factory=list)


_ACTIVE = ContextVar("week8_gateway_invocation", default=None)


def _plain(value):
    if isinstance(value, Tainted):
        return _plain(value.value)
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _guard_check(hook, direction, text, *, sources=()):
    if not isinstance(hook, DefenseHook):
        return {"decision": "block", "reason": "guard_not_configured"}
    return hook.check(direction, text, tool_name="local_file", sources=sources)


class IntegratedGateway(Gateway):
    """Adds only pre-execution hooks; W7 cryptographic validation is unchanged."""

    def _dispatch(self, command, context, verified, approval_expires_at):
        state = _ACTIVE.get()
        if state is None:
            return GatewayResult("DENY", "missing_integration_context")
        expected = command.write_content if command.write_content is not None else command.instruction
        raw = state.raw
        if raw is not None and _plain(raw) != expected:
            state.events.append({"layer": "taint", "decision": "block", "reason": "provenance_mismatch"})
            return GatewayResult("DENY", "provenance_mismatch")
        if is_tainted(raw):
            state.events.append({"layer": "taint", "decision": "block", "reason": "tainted_arg",
                                 "sources": sorted(collect_sources(raw))})
            return GatewayResult("DENY", "tainted_arg")
        state.events.append({"layer": "taint", "decision": "allow", "reason": "untainted"})
        if state.hook is not None:
            checked = _guard_check(state.hook, "input", command.instruction,
                                   sources=tuple(sorted(collect_sources(raw))))
            decision = checked["decision"]
            state.events.append({"layer": "input_guard", "decision": decision,
                                 "reason": checked["reason"], "kind": checked.get("kind")})
            if decision != "allow":
                return GatewayResult("DENY", "input_guard_blocked")
        return super()._dispatch(command, context, verified, approval_expires_at)


def approval_preview(request, *, reveal_content=False):
    """Human-facing approval notice; never call issue_approval automatically here.

    The default preview is safe to log; the explicit content view is only for a
    trusted approval screen and must not be placed in audit telemetry.
    """
    from week7.approval import ApprovalRequest
    if not isinstance(request, ApprovalRequest):
        raise ValueError("approval_request_required")
    command = request.command
    is_write = command.write_content is not None
    notice = {
        "operation": command.grant.action,
        "target": command.grant.resource,
        "gateway_audience": command.audience,
        "executing_agent": request.actor,
        "approver": request.approver,
        "risk": ("Existing file will be replaced; review the exact bytes before approval"
                 if is_write else "Local resource content may be disclosed"),
        "request_hash": request.request_hash,
        "command_hash": command.digest(),
    }
    if is_write:
        encoded = command.write_content.encode("utf-8")
        notice["new_content_sha256"] = sha256(encoded).hexdigest()
        notice["new_content_bytes"] = len(encoded)
        if reveal_content:
            notice["content_for_human_review_only"] = command.write_content
    return notice


@dataclass(frozen=True)
class PipelineOutcome:
    decision: str
    reason: str
    tool_invoked: bool
    output: str | None
    output_released: bool
    audit_call_id: str | None
    layers: tuple[dict, ...]
    elapsed_ms: float
    approval_request: object | None = field(default=None, repr=False)

    def to_log(self):
        # Never serialize the raw command, credentials, signed approval or output.
        return {"decision": self.decision, "reason": self.reason,
                "tool_invoked": self.tool_invoked, "output_released": self.output_released,
                "audit_call_id": self.audit_call_id, "layers": list(self.layers),
                "elapsed_ms": self.elapsed_ms}


_FAIL_LAYER = {
    "invalid_invocation": "identity", "invalid_signature": "identity",
    "challenge_unknown_or_used": "identity", "challenge_binding_mismatch": "identity",
    "challenge_expired": "identity", "invalid_did": "identity",
    "command_changed": "command", "command_path_mismatch": "command",
    "command_signature_invalid": "command",
    "policy_denied": "policy", "policy_unavailable": "policy",
    "invalid_policy_decision": "policy", "approval_required": "approval",
    "approval_already_used": "approval", "approval_request_mismatch": "approval",
    "approval_inactive": "approval", "invalid_approval_token": "approval",
    "approval_signer_mismatch": "approval", "approval_policy_required": "approval",
    "approval_not_applicable": "approval", "tainted_arg": "taint",
    "provenance_mismatch": "taint", "input_guard_blocked": "input_guard",
    "missing_integration_context": "taint", "runtime_error": "tool",
    "audit_unavailable": "tool", "audit_result_unavailable": "tool",
}


def _layer_of(reason):
    if reason in _FAIL_LAYER:
        return _FAIL_LAYER[reason]
    if reason.startswith(("invalid_token", "capability_", "credential_", "scope_", "delegation_", "invalid_parent", "invalid_root", "system_ceiling", "validity_")):
        return "delegation"
    return "delegation"  # unknown cryptographic error: do not claim full success


def _timeline(mode, result, events, post_output=None):
    fail = None if result.decision == "ALLOW" else _layer_of(result.reason)
    if mode == "policy_only":
        fail = "policy" if result.reason == "policy_denied" else ("approval" if result.reason == "approval_required" else fail)
    rows = []
    for label in STAGES:
        enabled = (label == "tool" or
                   (label == "policy" and mode != "none") or
                   (label in ("identity", "delegation", "command", "approval") and mode in W7_MODES) or
                   (label == "taint" and mode in ("w7_plus_taint", "w7_plus_taint_guard")) or
                   (label in ("input_guard", "output_guard") and mode == "w7_plus_taint_guard"))
        if not enabled:
            rows.append({"layer": label, "decision": "disabled"})
            continue
        explicit = next((event for event in events if event["layer"] == label), None)
        if label == "output_guard" and post_output is not None:
            explicit = post_output
        if explicit is not None:
            rows.append(explicit)
        elif fail == label:
            rows.append({"layer": label, "decision": "pending" if result.decision == "REQUIRE_APPROVAL" else "block",
                         "reason": result.reason})
        elif fail is not None and STAGES.index(label) > STAGES.index(fail):
            rows.append({"layer": label, "decision": "not_reached"})
        elif label == "tool":
            rows.append({"layer": label, "decision": "executed" if result.tool_invoked else "not_reached"})
        elif label == "output_guard":
            rows.append({"layer": label, "decision": "not_reached"})
        else:
            rows.append({"layer": label, "decision": "allow",
                         "basis": "gateway_control_flow" if label in ("identity", "delegation", "command", "policy", "approval") else "hook"})
    return tuple(rows)


class Pipeline:
    def __init__(self, mode, verifier, policy, runtime, *, hook=None, audit=None):
        if mode not in MODES:
            raise ValueError("unsupported_layer_mode")
        if mode == "w7_plus_taint_guard" and not isinstance(hook, DefenseHook):
            raise ValueError("guard_required")
        self.mode = mode
        self.policy, self.runtime = policy, runtime
        self.hook = hook if mode == "w7_plus_taint_guard" else None
        cls = IntegratedGateway if mode in ("w7_plus_taint", "w7_plus_taint_guard") else Gateway
        self.gateway = cls(verifier, policy, runtime, audit=audit) if mode in W7_MODES else None

    def call(self, invocation: Invocation, actor: str, actor_key, *, approval=None, raw=None):
        state = _RequestState(raw=raw, hook=self.hook)
        started = perf_counter_ns()
        if self.gateway is None:
            from week7.run_eval import _unverified_call
            result = _unverified_call("policy_only" if self.mode == "policy_only" else "baseline",
                                      invocation.received, self.policy, self.runtime)
        else:
            token = _ACTIVE.set(state)
            try:
                challenge = self.gateway.issue_challenge(actor, invocation)
                signature = actor_key.sign(challenge.signing_bytes()).signature
                result = self.gateway.invoke(invocation, challenge.nonce, signature, approval=approval)
            finally:
                _ACTIVE.reset(token)
        released = result.output is not None
        post = None
        final = result
        if self.hook is not None and result.output is not None:
            checked = _guard_check(self.hook, "output", result.output,
                                   sources=tuple(sorted(collect_sources(raw))))
            released = checked["decision"] == "allow"
            post = {"layer": "output_guard", "decision": checked["decision"],
                    "reason": checked["reason"], "kind": checked.get("kind")}
            if not released:
                # The W7 audit still correctly says the tool was invoked. The
                # outward result explicitly records that output was withheld.
                final = GatewayResult("DENY", "output_guard_blocked", True,
                                      audit_call_id=result.audit_call_id)
        elapsed_ms = (perf_counter_ns() - started) / 1_000_000
        return PipelineOutcome(final.decision, final.reason, final.tool_invoked,
                               final.output, released, final.audit_call_id,
                               _timeline(self.mode, result, state.events, post),
                               elapsed_ms, result.approval_request)
