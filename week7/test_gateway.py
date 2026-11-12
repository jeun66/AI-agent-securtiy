from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from week7.approval import APPROVAL_TYPE, ApprovalVerifier, issue_approval
from week7.commands import Command, forward_command, sign_command
from week7.credentials import issue_credential
from week7.delegation import DelegationVerifier, issue_capability
from week7.gateway import Gateway, GatewayResult, Invocation
from week7.identity import generate_identity
from week7.opa import OpaPolicy, PolicyDecision
from week7.runtime import LocalFileRuntime
from week7.scope import Grant
from week7.signed_tokens import sign_token, verify_token


NOW = 1_794_442_000
AUDIENCE = "urn:agent-trust:gateway:w7"
READ = Grant("read_file", "note.txt")
WRITE = Grant("write_file", "note.txt")
POLICY_BLOCKED = Grant("read_file", "blocked.txt")
GRANTS = {READ, WRITE, POLICY_BLOCKED}


@pytest.fixture
def opa_executable():
    executable = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not executable:
        pytest.skip("install OPA or set OPA_BIN for CLI integration tests")
    return executable


@pytest.fixture
def lab(tmp_path):
    issuer, issuer_key = generate_identity()
    user, user_key = generate_identity()
    middle, middle_key = generate_identity()
    actor, actor_key = generate_identity()
    now = [NOW]
    credential = issue_credential(issuer_key, user, AUDIENCE, GRANTS, valid_from=NOW - 10, valid_until=NOW + 40)
    root = issue_capability(user_key, middle, AUDIENCE, GRANTS, credential=credential,
                            issued_at=NOW - 5, expires_at=NOW + 30, remaining_depth=1)
    child = issue_capability(middle_key, actor, AUDIENCE, GRANTS, credential=credential,
                             issued_at=NOW - 3, expires_at=NOW + 15, parent=root)
    verifier = DelegationVerifier(AUDIENCE, trusted_issuers={issuer}, ceiling=GRANTS,
                                  user_policies={user: GRANTS}, clock=lambda: now[0])
    (tmp_path / "note.txt").write_text("실제 실습 파일\n", encoding="utf-8")

    def sign_request(command):
        anchor = sign_command(user_key, command)
        first = forward_command(user_key, middle, command, anchor)
        second = forward_command(middle_key, actor, command, first)
        return Invocation(credential, (root, child), anchor, (first, second), command)

    def request(grant=READ, *, content="승인된 변경\n"):
        write_content = content if grant.action == "write_file" else None
        return sign_request(Command(AUDIENCE, "사용자 최초 명령", grant, write_content=write_content))

    def invoke(gateway, invocation, *, approval=None):
        challenge = gateway.issue_challenge(actor, invocation)
        signature = actor_key.sign(challenge.signing_bytes()).signature
        return gateway.invoke(invocation, challenge.nonce, signature, approval=approval)

    return SimpleNamespace(actor=actor, actor_key=actor_key, user_key=user_key, middle_key=middle_key, verifier=verifier,
                           request=request, sign_request=sign_request, invoke=invoke, root=root, now=now)


def test_real_opa_and_runtime_read_the_verified_local_file(lab, tmp_path, opa_executable):
    gateway = Gateway(lab.verifier, OpaPolicy(opa_executable), LocalFileRuntime(tmp_path))
    result = lab.invoke(gateway, lab.request())
    assert result == GatewayResult("ALLOW", "allowed", True, "실제 실습 파일\n")


def test_challenge_cannot_be_replayed_or_transplanted_to_another_valid_command(lab):
    policy = Mock(spec=OpaPolicy)
    policy.evaluate.return_value = PolicyDecision(True, False)
    runtime = Mock(spec=LocalFileRuntime)
    runtime.run.return_value = "checked"
    gateway = Gateway(lab.verifier, policy, runtime)
    request = lab.request()
    challenge = gateway.issue_challenge(lab.actor, request)
    signature = lab.actor_key.sign(challenge.signing_bytes()).signature
    assert gateway.invoke(lab.request(), challenge.nonce, signature) == GatewayResult("DENY", "challenge_binding_mismatch")
    assert gateway.invoke(request, challenge.nonce, signature) == GatewayResult("ALLOW", "allowed", True, "checked")
    assert gateway.invoke(request, challenge.nonce, signature) == GatewayResult("DENY", "challenge_unknown_or_used")
    runtime.run.assert_called_once_with(READ)


def test_a_different_authenticated_actor_cannot_use_the_leafs_capability(lab):
    other, other_key = generate_identity()
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, policy, runtime)
    request = lab.request()
    challenge = gateway.issue_challenge(other, request)
    signature = other_key.sign(challenge.signing_bytes()).signature
    assert gateway.invoke(request, challenge.nonce, signature) == GatewayResult("DENY", "capability_subject_mismatch")
    policy.evaluate.assert_not_called()
    runtime.run.assert_not_called()


@pytest.mark.parametrize("changed_field", ["instruction", "grant", "hop_only"])
def test_middle_agent_cannot_change_user_command_even_with_valid_signatures(lab, changed_field):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, policy, runtime)
    original = lab.request()
    changes = {"grant": WRITE, "write_content": "변경"} if changed_field == "grant" else {"instruction": "변조된 명령"}
    modified = replace(original.received, **changes)
    hop = forward_command(lab.middle_key, lab.actor, modified, original.hops[0])
    received = original.received if changed_field == "hop_only" else modified
    request = replace(original, received=received, hops=(original.hops[0], hop))
    assert lab.invoke(gateway, request) == GatewayResult("DENY", "command_changed")
    policy.evaluate.assert_not_called()
    runtime.run.assert_not_called()


def test_gateway_rejects_forged_anchor_missing_hop_and_incorrect_link(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, policy, runtime)
    request = lab.request()
    forged = replace(request, anchor=replace(request.anchor, signature=bytes(64)))
    missing = replace(request, hops=request.hops[1:])
    wrong_hop = forward_command(lab.middle_key, lab.actor, request.received, request.anchor)
    wrong_link = replace(request, hops=(request.hops[0], wrong_hop))
    assert lab.invoke(gateway, forged) == GatewayResult("DENY", "command_signature_invalid")
    assert lab.invoke(gateway, missing) == GatewayResult("DENY", "command_path_mismatch")
    assert lab.invoke(gateway, wrong_link) == GatewayResult("DENY", "command_path_mismatch")
    policy.evaluate.assert_not_called()
    runtime.run.assert_not_called()


def test_scope_and_revocation_stop_runtime_before_opa(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, policy, runtime)
    assert lab.invoke(gateway, lab.request(Grant("read_file", "outside.txt"))) == GatewayResult("DENY", "scope_denied")
    lab.verifier.revoke(lab.root)
    assert lab.invoke(gateway, lab.request()) == GatewayResult("DENY", "capability_revoked")
    policy.evaluate.assert_not_called()
    runtime.run.assert_not_called()


def test_real_opa_deny_and_approval_decisions_stop_runtime(lab, opa_executable):
    runtime = Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, OpaPolicy(opa_executable), runtime)
    assert lab.invoke(gateway, lab.request(POLICY_BLOCKED)) == GatewayResult("DENY", "policy_denied")
    result = lab.invoke(gateway, lab.request(WRITE))
    assert (result.decision, result.reason, result.tool_invoked) == ("REQUIRE_APPROVAL", "approval_required", False)
    assert result.approval_request.command.grant == WRITE
    runtime.run.assert_not_called()


def test_missing_opa_stops_runtime(lab, tmp_path):
    runtime = Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, OpaPolicy(tmp_path / "missing-opa"), runtime)
    assert lab.invoke(gateway, lab.request()) == GatewayResult("DENY", "policy_unavailable")
    runtime.run.assert_not_called()


def test_real_opa_policy_error_stops_runtime(lab, tmp_path, opa_executable):
    broken = tmp_path / "broken.rego"
    broken.write_text("package agent.authz\nallow if {\n", encoding="utf-8")
    runtime = Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, OpaPolicy(opa_executable, policy_path=broken), runtime)
    assert lab.invoke(gateway, lab.request()) == GatewayResult("DENY", "policy_unavailable")
    runtime.run.assert_not_called()


@pytest.mark.parametrize("response", [b"undefined", b'{"allow":true}', b'{"allow":1,"requires_approval":false}'])
def test_malformed_opa_result_stops_runtime(lab, monkeypatch, response):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=response))
    runtime = Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, OpaPolicy(), runtime)
    assert lab.invoke(gateway, lab.request()) == GatewayResult("DENY", "invalid_policy_decision")
    runtime.run.assert_not_called()


def test_opa_timeout_stops_runtime(lab, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("opa", 3)

    monkeypatch.setattr(subprocess, "run", timeout)
    runtime = Mock(spec=LocalFileRuntime)
    gateway = Gateway(lab.verifier, OpaPolicy(), runtime)
    assert lab.invoke(gateway, lab.request()) == GatewayResult("DENY", "policy_unavailable")
    runtime.run.assert_not_called()


def test_expiry_during_policy_evaluation_stops_runtime(lab):
    def evaluate(actor, grant):
        lab.now[0] = NOW + 15
        return PolicyDecision(True, False)

    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    policy.evaluate.side_effect = evaluate
    gateway = Gateway(lab.verifier, policy, runtime)
    assert lab.invoke(gateway, lab.request()) == GatewayResult("DENY", "capability_inactive")
    runtime.run.assert_not_called()


@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_authorized_filename_cannot_read_linked_file(lab, tmp_path, opa_executable, link):
    hidden = tmp_path / "hidden.txt"
    hidden.write_text("protected", encoding="utf-8")
    note = tmp_path / "note.txt"
    note.unlink()
    if link == "symlink":
        note.symlink_to(hidden)
    else:
        os.link(hidden, note)
    gateway = Gateway(lab.verifier, OpaPolicy(opa_executable), LocalFileRuntime(tmp_path))
    assert lab.invoke(gateway, lab.request()) == GatewayResult("ERROR", "runtime_error", True)


def test_runtime_does_not_traverse_a_symlink_directory(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (tmp_path / "private.txt").write_text("outside sandbox", encoding="utf-8")
    (sandbox / "alias").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        LocalFileRuntime(sandbox).run(Grant("read_file", "alias/private.txt"))


def test_real_approved_write_rejects_changed_content_and_reuse(lab, tmp_path, opa_executable):
    note = tmp_path / "note.txt"
    original = note.read_bytes()
    gateway = Gateway(lab.verifier, OpaPolicy(opa_executable), LocalFileRuntime(tmp_path),
                      approvals=ApprovalVerifier(clock=lambda: NOW))
    invocation = lab.request(WRITE, content="승인한 내용\r\n둘째 줄\n")
    pending = lab.invoke(gateway, invocation)
    assert pending.decision == "REQUIRE_APPROVAL" and not pending.tool_invoked
    assert note.read_bytes() == original
    review = pending.approval_request
    assert review.request_hash == invocation.binding()
    assert review.actor == lab.actor and review.command == invocation.received
    token = issue_approval(lab.user_key, review, issued_at=NOW)

    modified = lab.sign_request(replace(invocation.received, write_content="승인 후 바뀐 내용\n"))
    assert lab.invoke(gateway, modified, approval=token) == GatewayResult("DENY", "approval_request_mismatch")
    assert note.read_bytes() == original
    assert lab.invoke(gateway, invocation, approval=token) == GatewayResult("ALLOW", "allowed", True, "written")
    assert note.read_bytes() == invocation.received.write_content.encode("utf-8")
    assert lab.invoke(gateway, invocation, approval=token) == GatewayResult("DENY", "approval_already_used")


def test_approval_rejects_misleading_review_signer_and_other_gateway(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    policy.evaluate.return_value = PolicyDecision(True, True)
    gateway = Gateway(lab.verifier, policy, runtime, approvals=ApprovalVerifier(clock=lambda: NOW))
    another = Gateway(lab.verifier, policy, runtime, approvals=ApprovalVerifier(clock=lambda: NOW))
    invocation = lab.request(WRITE)
    review = lab.invoke(gateway, invocation).approval_request
    token = issue_approval(lab.user_key, review, issued_at=NOW)
    _, claims = verify_token(token, APPROVAL_TYPE)
    wrong_signer = sign_token(lab.actor_key, APPROVAL_TYPE, claims)

    wrong_content = replace(review, command=replace(review.command, write_content="다른 미리보기"))
    wrong_target = replace(review, command=replace(review.command, grant=Grant("write_file", "other.txt")))
    wrong_actor = replace(review, actor=review.approver)
    for misleading in (wrong_content, wrong_target, wrong_actor):
        misleading_token = issue_approval(lab.user_key, misleading, issued_at=NOW)
        assert lab.invoke(gateway, invocation, approval=misleading_token) == GatewayResult("DENY", "approval_request_mismatch")
    assert lab.invoke(gateway, invocation, approval=wrong_signer) == GatewayResult("DENY", "approval_signer_mismatch")
    assert lab.invoke(another, invocation, approval=token) == GatewayResult("DENY", "approval_request_mismatch")
    runtime.run.assert_not_called()


def test_expired_and_malformed_approvals_stop_runtime(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    policy.evaluate.return_value = PolicyDecision(True, True)
    gateway = Gateway(lab.verifier, policy, runtime, approvals=ApprovalVerifier(clock=lambda: lab.now[0]))
    invocation = lab.request(WRITE)
    review = lab.invoke(gateway, invocation).approval_request
    token = issue_approval(lab.user_key, review, issued_at=NOW, ttl_seconds=5)
    lab.now[0] += 5
    assert lab.invoke(gateway, invocation, approval=token) == GatewayResult("DENY", "approval_inactive")
    assert lab.invoke(gateway, invocation, approval="invalid") == GatewayResult("DENY", "invalid_approval_token")
    runtime.run.assert_not_called()


def test_write_fails_closed_if_policy_omits_approval(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    policy.evaluate.return_value = PolicyDecision(True, False)
    gateway = Gateway(lab.verifier, policy, runtime)
    assert lab.invoke(gateway, lab.request(WRITE)) == GatewayResult("DENY", "approval_policy_required")
    runtime.run.assert_not_called()


def test_approval_does_not_restore_a_revoked_delegation(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    policy.evaluate.return_value = PolicyDecision(True, True)
    gateway = Gateway(lab.verifier, policy, runtime, approvals=ApprovalVerifier(clock=lambda: NOW))
    invocation = lab.request(WRITE)
    review = lab.invoke(gateway, invocation).approval_request
    token = issue_approval(lab.user_key, review, issued_at=NOW)
    lab.verifier.revoke(lab.root)
    assert lab.invoke(gateway, invocation, approval=token) == GatewayResult("DENY", "capability_revoked")
    runtime.run.assert_not_called()


def test_same_approval_dispatched_only_once_for_concurrent_invocations(lab):
    policy, runtime = Mock(spec=OpaPolicy), Mock(spec=LocalFileRuntime)
    policy.evaluate.return_value = PolicyDecision(True, True)
    runtime.run.return_value = "written"
    gateway = Gateway(lab.verifier, policy, runtime, approvals=ApprovalVerifier(clock=lambda: NOW))
    invocation = lab.request(WRITE)
    review = lab.invoke(gateway, invocation).approval_request
    token = issue_approval(lab.user_key, review, issued_at=NOW)
    with ThreadPoolExecutor(max_workers=2) as workers:
        decisions = list(workers.map(lambda _: lab.invoke(gateway, invocation, approval=token), range(2)))
    assert {result.reason for result in decisions} == {"allowed", "approval_already_used"}
    runtime.run.assert_called_once_with(WRITE, write_content=invocation.received.write_content)


def test_write_failure_preserves_old_content_and_consumes_token(lab, tmp_path, monkeypatch):
    note = tmp_path / "note.txt"
    original = note.read_bytes()
    policy = Mock(spec=OpaPolicy)
    policy.evaluate.return_value = PolicyDecision(True, True)
    gateway = Gateway(lab.verifier, policy, LocalFileRuntime(tmp_path), approvals=ApprovalVerifier(clock=lambda: NOW))
    invocation = lab.request(WRITE)
    review = lab.invoke(gateway, invocation).approval_request
    token = issue_approval(lab.user_key, review, issued_at=NOW)

    def failed_replace(*args, **kwargs):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(os, "replace", failed_replace)
    assert lab.invoke(gateway, invocation, approval=token) == GatewayResult("ERROR", "runtime_error", True)
    assert note.read_bytes() == original
    assert set(tmp_path.iterdir()) == {note}
    assert lab.invoke(gateway, invocation, approval=token) == GatewayResult("DENY", "approval_already_used")
