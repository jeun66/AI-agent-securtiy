"""Stage-5 OTS tests use an explicit fake CLI; never claim real confirmation."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from week7.audit import SignedAuditLog
from week7.identity import generate_identity
from week8 import ots_anchor


def evidence(tmp_path):
    signer, key = generate_identity()
    with SignedAuditLog(tmp_path / "audit.jsonl", key) as audit:
        audit.append({"call_id": "1" * 32, "phase": "decision", "actor_id": "fixture",
                      "decision": "DENY", "reason": "fixture",
                      "tool_invoked": False})
        audit.write_checkpoint(tmp_path / "checkpoint.json")
    (tmp_path / "audit-signer.did").write_text(signer + "\n", encoding="ascii")
    return tmp_path


def test_signed_merkle_integrity_and_mutation_detection(tmp_path):
    base = evidence(tmp_path)
    row = ots_anchor.inspect_evidence(base)
    assert row["records"] == 1
    assert len(row["merkle_root"]) == 64
    assert ots_anchor.check_mutations(base) == {
        "tampered": "audit_hash_mismatch", "truncated": "audit_checkpoint_mismatch"}


def test_pending_is_not_misreported_as_bitcoin_verified(tmp_path, monkeypatch):
    base = evidence(tmp_path)
    def mock_command(_ots, action, filename):
        if action == "stamp":
            Path(str(filename) + ".ots").write_bytes(b"fixture-only")
        return 0, ("Success! Bitcoin block 123 attests existence" if action == "verify"
                   else "calendar accepted; pending")
    monkeypatch.setattr(ots_anchor, "_command", mock_command)
    status = ots_anchor.anchor(base, action="stamp")
    assert status["state"] == "pending"
    assert ots_anchor.anchor(base, action="upgrade")["state"] == "pending"
    assert ots_anchor.anchor(base, action="verify")["state"] == "verified"


def test_client_pending_or_nonzero_never_claims_verified(tmp_path, monkeypatch):
    base = evidence(tmp_path)
    def fake(_ots, action, filename):
        if action == "stamp":
            Path(str(filename) + ".ots").write_bytes(b"fixture")
        return (1, "Pending confirmation") if action == "verify" else (0, "")
    monkeypatch.setattr(ots_anchor, "_command", fake)
    ots_anchor.anchor(base, action="stamp")
    assert ots_anchor.anchor(base, action="verify")["state"] == "pending"


def test_changed_checkpoint_fails_closed(tmp_path, monkeypatch):
    base = evidence(tmp_path)
    def mock(_ots, action, filename):
        if action == "stamp":
            Path(str(filename) + ".ots").write_bytes(b"fixture")
        return 0, ""
    monkeypatch.setattr(ots_anchor, "_command", mock)
    ots_anchor.anchor(base, action="stamp")
    (base / "checkpoint.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="audit_checkpoint"):
        ots_anchor.anchor(base, action="verify")


def test_untracked_proof_replacement_rejected(tmp_path, monkeypatch):
    base = evidence(tmp_path)
    def mock(_ots, action, filename):
        if action == "stamp":
            Path(str(filename) + ".ots").write_bytes(b"fixture")
        return 0, ""
    monkeypatch.setattr(ots_anchor, "_command", mock)
    ots_anchor.anchor(base, action="stamp")
    (base / "checkpoint.json.ots").write_bytes(b"modified")
    with pytest.raises(ValueError, match="untracked_ots"):
        ots_anchor.anchor(base, action="verify")
