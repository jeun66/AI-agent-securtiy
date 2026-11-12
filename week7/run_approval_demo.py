"""Review and approve one real write in an isolated temporary sandbox."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time

from week7.approval import issue_approval
from week7.commands import Command, forward_command, sign_command
from week7.credentials import issue_credential
from week7.delegation import DelegationVerifier, issue_capability
from week7.gateway import Gateway, Invocation
from week7.identity import generate_identity
from week7.opa import OpaPolicy
from week7.runtime import LocalFileRuntime
from week7.scope import Grant


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opa", default=os.environ.get("OPA_BIN", "opa"))
    args = parser.parse_args()

    audience = "urn:agent-trust:gateway:w7"
    grant = Grant("write_file", "note.txt")
    now = int(time())
    issuer, issuer_key = generate_identity()
    user, user_key = generate_identity()
    actor, actor_key = generate_identity()
    vc = issue_credential(issuer_key, user, audience, {grant}, valid_from=now, valid_until=now + 900)
    capability = issue_capability(user_key, actor, audience, {grant}, credential=vc,
                                  issued_at=now, expires_at=now + 840)
    verifier = DelegationVerifier(audience, trusted_issuers={issuer}, ceiling={grant}, user_policies={user: {grant}})

    def request(command):
        anchor = sign_command(user_key, command)
        hop = forward_command(user_key, actor, command, anchor)
        return Invocation(vc, (capability,), anchor, (hop,), command)

    with TemporaryDirectory(prefix="w7-approval-") as directory:
        sandbox = Path(directory).resolve()
        note = sandbox / "note.txt"
        original = b"Original sandbox content\n"
        note.write_bytes(original)
        gateway = Gateway(verifier, OpaPolicy(args.opa), LocalFileRuntime(sandbox))

        def check(invocation, label, expected, reason, token=None):
            challenge = gateway.issue_challenge(actor, invocation)
            signature = actor_key.sign(challenge.signing_bytes()).signature
            result = gateway.invoke(invocation, challenge.nonce, signature, approval=token)
            invoked = str(result.tool_invoked).lower()
            print(f"{label}: {result.decision}, tool_invoked={invoked} ({result.reason})")
            if (result.decision, result.reason, result.tool_invoked) != (expected, reason, expected == "ALLOW"):
                raise RuntimeError(f"unexpected result for {label}")
            return result

        command = Command(audience, "Replace the sandbox file once.", grant, write_content="Approved replacement\n")
        invocation = request(command)
        pending = check(invocation, "before approval", "REQUIRE_APPROVAL", "approval_required")
        review = pending.approval_request
        if review is None or note.read_bytes() != original:
            raise RuntimeError("approval review missing or file changed before approval")
        print(f"작업 {review.command.grant.action} · 대상 임시 샌드박스의 {review.command.grant.resource}")
        print(f"실행자 {review.actor}")
        print("위험 기존 파일 내용을 덮어씁니다.")
        print(f"변경 내용 {json.dumps(review.command.write_content, ensure_ascii=True)}")
        try:
            choice = input("이 변경을 승인하려면 APPROVE를 입력하세요. ")
        except EOFError:
            choice = ""
        if choice != "APPROVE":
            print("승인 취소 · 파일 변경 없음")
            return

        token = issue_approval(user_key, review)
        changed = request(replace(command, write_content="Modified after approval\n"))
        check(changed, "changed content with original approval", "DENY", "approval_request_mismatch", token)
        if note.read_bytes() != original:
            raise RuntimeError("modified request changed the file")

        check(invocation, "approved write", "ALLOW", "allowed", token)
        expected = command.write_content.encode("utf-8")
        if note.read_bytes() != expected:
            raise RuntimeError("file content differs from the approved bytes")
        inode = note.stat().st_ino
        print("file content matches approved bytes: true")
        check(invocation, "reused approval", "DENY", "approval_already_used", token)
        if note.read_bytes() != expected or note.stat().st_ino != inode:
            raise RuntimeError("reused token changed the file")


if __name__ == "__main__":
    main()
