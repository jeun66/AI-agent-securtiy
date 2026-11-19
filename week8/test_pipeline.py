"""Offline W8 unit tests. Real OPA baseline is a separate integration run."""
from dataclasses import replace
import json

import pytest

from week4.taint import taint_from_source
from week5.defense import DefenseHook
from week5.guards import RuleGuard
from week7.approval import issue_approval
from week7.commands import Command
from week7.opa import PolicyDecision
from week7.runtime import LocalFileRuntime
from week8.adaptive import AUDIENCE, READ, WRITE, NOTE, _taint_attempt, _w7_attempt, make_lab
from week8.pipeline import Pipeline, approval_preview


class FixedPolicy:
    """Testing double only; not used for recorded OPA performance results."""
    def __init__(self, *args):
        pass

    def evaluate(self, actor, grant):
        allowed = grant.resource == "note.txt" and grant.action in ("read_file", "write_file")
        return PolicyDecision(allowed, allowed and grant.action == "write_file", "unit-test-policy")

    def evaluate_tool(self, grant):
        return self.evaluate("simulated", grant)


def build(tmp_path, mode="w7_plus_taint_guard", output=NOTE):
    (tmp_path / "note.txt").write_text(output, encoding="utf-8")
    (tmp_path / "blocked.txt").write_text("blocked", encoding="utf-8")
    lab = make_lab(tmp_path)
    hook = DefenseHook(RuleGuard(), RuleGuard()) if mode == "w7_plus_taint_guard" else None
    pipeline = Pipeline(mode, lab.verifier, FixedPolicy(), LocalFileRuntime(tmp_path), hook=hook)
    return lab, pipeline


def test_all_w7_layers_and_mock_guards_share_one_call(tmp_path):
    lab, pipe = build(tmp_path)
    command = Command(AUDIENCE, "Read the named local sandbox file.", READ)
    result = pipe.call(lab.invocation(command), lab.actor, lab.actor_key)
    assert result.decision == "ALLOW" and result.output == NOTE
    assert result.output_released and result.tool_invoked
    assert [row["layer"] for row in result.layers] == [
        "identity", "delegation", "command", "policy", "approval", "taint",
        "input_guard", "tool", "output_guard"]
    assert [row["decision"] for row in result.layers] == [
        "allow", "allow", "allow", "allow", "allow", "allow", "allow", "executed", "allow"]
    assert NOTE not in json.dumps(result.to_log())


def test_tainted_input_denies_before_tool_and_never_logs_payload(tmp_path):
    lab, pipe = build(tmp_path)
    command = Command(AUDIENCE, "Read the named local sandbox file.", READ)
    denied = pipe.call(lab.invocation(command), lab.actor, lab.actor_key,
                       raw=taint_from_source("external:unit", command.instruction))
    assert denied.decision == "DENY" and denied.reason == "tainted_arg"
    assert not denied.tool_invoked
    assert next(x for x in denied.layers if x["layer"] == "taint")["decision"] == "block"
    assert command.instruction not in json.dumps(denied.to_log())
    mismatched = pipe.call(lab.invocation(command), lab.actor, lab.actor_key,
                           raw=taint_from_source("external", "DIFFERENT"))
    assert mismatched.reason == "provenance_mismatch" and not mismatched.tool_invoked


def test_output_guard_withholds_actual_read_without_claiming_no_execution(tmp_path):
    lab, pipe = build(tmp_path, output="test@example.invalid")
    command = Command(AUDIENCE, "Read the named local sandbox file.", READ)
    result = pipe.call(lab.invocation(command), lab.actor, lab.actor_key)
    assert result.decision == "DENY" and result.reason == "output_guard_blocked"
    assert result.tool_invoked and not result.output_released and result.output is None
    assert next(x for x in result.layers if x["layer"] == "output_guard")["decision"] == "block"
    assert "test@example.invalid" not in json.dumps(result.to_log())


def test_approval_binds_write_and_is_one_use(tmp_path):
    lab, pipe = build(tmp_path)
    command = Command(AUDIENCE, "Replace local file.", WRITE, write_content="approved\n")
    request = lab.invocation(command)
    pending = pipe.call(request, lab.actor, lab.actor_key)
    assert pending.decision == "REQUIRE_APPROVAL" and not pending.tool_invoked
    preview = approval_preview(pending.approval_request)
    assert preview["operation"] == "write_file" and preview["target"] == "note.txt"
    assert "risk" in preview and "new_content_sha256" in preview
    assert "approved" not in json.dumps(preview)
    assert approval_preview(pending.approval_request, reveal_content=True)["content_for_human_review_only"] == "approved\n"
    approval = issue_approval(lab.user_key, pending.approval_request)
    changed = lab.invocation(replace(command, write_content="tampered\n"))
    denied = pipe.call(changed, lab.actor, lab.actor_key, approval=approval)
    assert denied.reason == "approval_request_mismatch" and not denied.tool_invoked
    accepted = pipe.call(request, lab.actor, lab.actor_key, approval=approval)
    assert accepted.decision == "ALLOW" and accepted.tool_invoked
    assert (tmp_path / "note.txt").read_text() == "approved\n"
    replay = pipe.call(request, lab.actor, lab.actor_key, approval=approval)
    assert replay.reason == "approval_already_used" and not replay.tool_invoked


def test_unpatched_w4_split_is_observed_not_silently_patched():
    vulnerable, log = _taint_attempt("original")
    assert vulnerable and log["tool_invoked"]
    assert log["kind"] == "mock_http; no external network"
    preserved, log = _taint_attempt("spacing")
    assert not preserved and not log["tool_invoked"]


@pytest.mark.parametrize("task", [
    "capability_forgery", "parent_link", "depth_expansion", "scope_expansion",
    "command_rewrite", "signature_substitution", "approval_swap", "approval_replay",
])
def test_w7_adaptive_attack_rejected_before_unauthorized_effect(task, monkeypatch):
    import week8.adaptive as adaptive
    monkeypatch.setattr(adaptive, "OpaPolicy", FixedPolicy)
    success, evidence = _w7_attempt(task, "w7_plus_taint_guard", "original", "unused", None)
    assert not success, (task, evidence)


def test_no_defense_reference_does_execute_invalid_token(monkeypatch):
    import week8.adaptive as adaptive
    monkeypatch.setattr(adaptive, "OpaPolicy", FixedPolicy)
    success, log = _w7_attempt("capability_forgery", "none", "original", "unused", None)
    assert success and log["tool_invoked"]
