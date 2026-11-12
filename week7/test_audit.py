from hashlib import sha256
import json

import pytest

from week7.audit import AuditWriteError, SignedAuditLog, merkle_root, verify_audit
from week7.identity import generate_identity


def _json_line(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def test_checkpoint_detects_valid_prefix_and_signer_is_pinned(tmp_path):
    signer, key = generate_identity()
    other_signer, _ = generate_identity()
    audit_file = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"
    with SignedAuditLog(audit_file, key) as audit:
        for call_id in ("1" * 32, "2" * 32):
            audit.append({"call_id": call_id, "phase": "decision", "decision": "DENY", "tool_invoked": False})
        audit.write_checkpoint(checkpoint)

    with pytest.raises(ValueError, match="^invalid_audit_signature$"):
        verify_audit(audit_file, signer=other_signer, checkpoint=checkpoint)
    records = audit_file.read_bytes().splitlines(keepends=True)
    audit_file.write_bytes(records[0])
    assert len(verify_audit(audit_file, signer=signer).events) == 1
    with pytest.raises(ValueError, match="^audit_checkpoint_mismatch$"):
        verify_audit(audit_file, signer=signer, checkpoint=checkpoint)


def test_recalculating_record_hash_does_not_forge_signature(tmp_path):
    signer, key = generate_identity()
    path = tmp_path / "audit.jsonl"
    with SignedAuditLog(path, key) as audit:
        audit.append({"call_id": "1" * 32, "phase": "decision", "decision": "DENY", "tool_invoked": False})
    record = json.loads(path.read_bytes())
    signature = record.pop("signature")
    record.pop("hash")
    record["event"]["decision"] = "REQUIRE_APPROVAL"
    forged_hash = sha256(_json_line(record)[:-1]).hexdigest()
    path.write_bytes(_json_line({**record, "hash": forged_hash, "signature": signature}))
    with pytest.raises(ValueError, match="^invalid_audit_signature$"):
        verify_audit(path, signer=signer)


def test_merkle_root_of_three_leaves_uses_ordered_tree_split():
    leaves = [sha256(text).hexdigest() for text in (b"first", b"second", b"third")]
    first, second, third = [sha256(b"\x00" + bytes.fromhex(leaf)).digest() for leaf in leaves]
    left = sha256(b"\x01" + first + second).digest()
    assert merkle_root(leaves) == sha256(b"\x01" + left + third).hexdigest()


def test_failed_append_preserves_prior_record_and_stops_writer(tmp_path, monkeypatch):
    signer, key = generate_identity()
    path = tmp_path / "audit.jsonl"
    event = {"call_id": "1" * 32, "phase": "decision", "decision": "DENY", "tool_invoked": False}
    with SignedAuditLog(path, key) as audit:
        audit.append(event)
        prefix = path.read_bytes()

        def fail_sync(fd):
            raise OSError("simulated sync failure")

        monkeypatch.setattr("week7.audit.os.fsync", fail_sync)
        with pytest.raises(AuditWriteError, match="^audit_unavailable$"):
            audit.append({**event, "call_id": "2" * 32})
        assert path.read_bytes() == prefix
        with pytest.raises(AuditWriteError, match="^audit_unavailable$"):
            audit.write_checkpoint(tmp_path / "checkpoint.json")
    assert len(verify_audit(path, signer=signer).events) == 1
