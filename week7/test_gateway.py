from dataclasses import replace
import os
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from week7.commands import Command, forward_command, sign_command
from week7.credentials import issue_credential
from week7.delegation import DelegationVerifier, issue_capability
from week7.gateway import Gateway, GatewayResult, Invocation
from week7.identity import generate_identity
from week7.opa import OpaPolicy, PolicyDecision
from week7.runtime import LocalFileRuntime
from week7.scope import Grant


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

    def request(grant=READ):
        command = Command(AUDIENCE, "사용자 최초 명령", grant)
        anchor = sign_command(user_key, command)
        first = forward_command(user_key, middle, command, anchor)
        second = forward_command(middle_key, actor, command, first)
        return Invocation(credential, (root, child), anchor, (first, second), command)

    def invoke(gateway, invocation):
        challenge = gateway.issue_challenge(actor, invocation)
        signature = actor_key.sign(challenge.signing_bytes()).signature
        return gateway.invoke(invocation, challenge.nonce, signature)

    return SimpleNamespace(actor=actor, actor_key=actor_key, middle_key=middle_key, verifier=verifier,
                           request=request, invoke=invoke, root=root, now=now)


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
    changes = {"grant": WRITE} if changed_field == "grant" else {"instruction": "변조된 명령"}
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
    assert lab.invoke(gateway, lab.request(WRITE)) == GatewayResult("REQUIRE_APPROVAL", "approval_required")
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
