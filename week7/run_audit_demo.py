"""Record real local Gateway decisions and verify audit tamper detection."""

import argparse
from dataclasses import replace
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time

from week7.approval import issue_approval
from week7.audit import SignedAuditLog, verify_audit
from week7.commands import Command, forward_command, sign_command
from week7.credentials import issue_credential
from week7.delegation import DelegationVerifier, issue_capability
from week7.delegation_graph import delegation_markdown
from week7.gateway import Gateway, Invocation
from week7.identity import generate_identity
from week7.opa import OpaPolicy
from week7.runtime import LocalFileRuntime
from week7.scope import Grant


def run_calls(sandbox: Path, opa: str, audit: SignedAuditLog) -> None:
    audience = "urn:agent-trust:gateway:w7"
    read = Grant("read_file", "note.txt")
    write = Grant("write_file", "note.txt")
    child_grants = {read, write}
    root_grants = child_grants | {Grant("read_file", "archive.txt")}
    now = int(time())
    issuer, issuer_key = generate_identity()
    user, user_key = generate_identity()
    parent, parent_key = generate_identity()
    actor, actor_key = generate_identity()
    vc = issue_credential(issuer_key, user, audience, root_grants, valid_from=now, valid_until=now + 300)
    root = issue_capability(user_key, parent, audience, root_grants, credential=vc,
                            issued_at=now, expires_at=now + 240, remaining_depth=1)
    leaf = issue_capability(parent_key, actor, audience, child_grants, credential=vc,
                            issued_at=now, expires_at=now + 180, parent=root)
    delegation = DelegationVerifier(audience, trusted_issuers={issuer}, ceiling=root_grants,
                                    user_policies={user: root_grants})
    note = sandbox / "note.txt"
    note.write_text("W7 initial content\n", encoding="utf-8")
    gateway = Gateway(delegation, OpaPolicy(opa), LocalFileRuntime(sandbox), audit=audit)

    def request(command):
        anchor = sign_command(user_key, command)
        first = forward_command(user_key, parent, command, anchor)
        second = forward_command(parent_key, actor, command, first)
        return Invocation(vc, (root, leaf), anchor, (first, second), command)

    def invoke(invocation, label, expected, *, approval=None, forged=False):
        challenge = gateway.issue_challenge(actor, invocation)
        signature = bytes(64) if forged else actor_key.sign(challenge.signing_bytes()).signature
        result = gateway.invoke(invocation, challenge.nonce, signature, approval=approval)
        print(f"{label}: {result.decision} ({result.reason})")
        if result.decision != expected:
            raise RuntimeError(f"unexpected result for {label}")
        return result

    read_request = request(Command(audience, "Read the sandbox file.", read))
    invoke(read_request, "verified read", "ALLOW")
    changed = replace(read_request.received, instruction="Middle agent changed the instruction.")
    invoke(replace(read_request, received=changed), "changed command", "DENY")
    invoke(read_request, "invalid actor proof", "DENY", forged=True)

    command = Command(audience, "Replace the sandbox file.", write, write_content="W7 approved content\n")
    write_request = request(command)
    pending = invoke(write_request, "without approval", "REQUIRE_APPROVAL")
    token = issue_approval(user_key, pending.approval_request)
    invoke(write_request, "approved write (scripted approval)", "ALLOW", approval=token)
    if note.read_bytes() != command.write_content.encode("utf-8"):
        raise RuntimeError("sandbox content did not match approved bytes")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--opa", default=os.environ.get("OPA_BIN", "opa"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    log = args.output_dir / "audit.jsonl"
    checkpoint = args.output_dir / "checkpoint.json"

    _, key = generate_identity()
    with SignedAuditLog(log, key) as audit, TemporaryDirectory(prefix="w7-audit-") as directory:
        run_calls(Path(directory).resolve(), args.opa, audit)
        audit.write_checkpoint(checkpoint)
        signer = audit.signer
    result = verify_audit(log, signer=signer, checkpoint=checkpoint)
    if len(result.events) != 7 or result.missing_executions:
        raise RuntimeError("unexpected audit coverage")
    print(f"original audit: VERIFIED ({len(result.events)} records, missing_executions=0)")
    print(f"merkle_root={result.merkle_root}")

    with (args.output_dir / "audit-signer.did").open("x", encoding="ascii") as stream:
        stream.write(signer + "\n")
    with (args.output_dir / "delegation.md").open("x", encoding="utf-8") as stream:
        stream.write(delegation_markdown(result.events[0]))

    raw = log.read_bytes()
    cases = (
        ("tampered", raw.replace(b'"reason":"allowed"', b'"reason":"forged"', 1), "audit_hash_mismatch"),
        ("truncated", b"".join(raw.splitlines(keepends=True)[:-1]), "audit_checkpoint_mismatch"),
    )
    for label, changed, reason in cases:
        path = args.output_dir / f"{label}.jsonl"
        with path.open("xb") as stream:
            stream.write(changed)
        try:
            verify_audit(path, signer=signer, checkpoint=checkpoint)
        except ValueError as exc:
            if str(exc) != reason:
                raise
            print(f"{label} audit: REJECTED ({reason})")
        else:
            raise RuntimeError(f"{label} audit unexpectedly passed verification")
    print(f"evidence_dir={args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
