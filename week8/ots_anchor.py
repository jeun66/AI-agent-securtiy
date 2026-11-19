"""OpenTimestamps anchor for a W7 signed audit checkpoint.

Anchors the ORIGINAL signed checkpoint bytes containing the ordered Merkle root
and head, not a freshly constructed stand-in. Never claims Bitcoin confirmation
until the OTS client explicitly verifies a confirmed block.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from week7.audit import verify_audit

STATE_NAME = "anchor-status.json"


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _write_status(path, row):
    path.write_text(json.dumps(row, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _read_status(path):
    if not path.is_file():
        raise ValueError("anchor_not_initialized")
    return json.loads(path.read_text(encoding="utf-8"))


def _now():
    return datetime.now(timezone.utc).isoformat()


def inspect_evidence(directory):
    directory = Path(directory)
    signer_path = directory / "audit-signer.did"
    log, checkpoint = directory / "audit.jsonl", directory / "checkpoint.json"
    signer = signer_path.read_text(encoding="ascii").strip()
    verified = verify_audit(log, signer=signer, checkpoint=checkpoint)
    if verified.missing_executions:
        raise ValueError("audit_has_unpaired_executions")
    doc = json.loads(checkpoint.read_text(encoding="ascii"))
    if doc["merkle_root"] != verified.merkle_root:
        raise ValueError("merkle_root_mismatch")
    return {
        "signer": signer,
        "audit_sha256": digest(log),
        "checkpoint_sha256": digest(checkpoint),
        "merkle_root": verified.merkle_root,
        "records": doc["records"],
        "head": verified.head,
    }


def check_mutations(directory):
    """Regression probe on separate in-memory copies; never changes source logs."""
    directory = Path(directory)
    raw = (directory / "audit.jsonl").read_bytes()
    if not raw:
        raise ValueError("empty_audit_for_mutation_check")
    # All records are canonical JSONL; alter exactly one signed field byte.
    pos = raw.find(b'"hash":"')
    if pos < 0:
        raise ValueError("invalid_audit_record")
    start = pos + len(b'"hash":"')
    changed = bytearray(raw)
    changed[start] = ord("a") if changed[start] != ord("a") else ord("b")
    lines = raw.splitlines(keepends=True)
    import tempfile
    from week7.audit import verify_audit
    signer = (directory / "audit-signer.did").read_text(encoding="ascii").strip()
    result = {}
    with tempfile.TemporaryDirectory(prefix="w8-ots-tamper-") as folder:
        for name, data in (("tampered", bytes(changed)),
                           ("truncated", b"".join(lines[:-1]))):
            filename = Path(folder) / (name + ".jsonl")
            filename.write_bytes(data)
            try:
                verify_audit(filename, signer=signer, checkpoint=directory / "checkpoint.json")
            except ValueError as error:
                result[name] = str(error)
            else:
                raise ValueError("mutation_not_detected:" + name)
    if result["tampered"] != "audit_hash_mismatch":
        raise ValueError("unexpected_mutation_result")
    if result["truncated"] != "audit_checkpoint_mismatch":
        raise ValueError("unexpected_truncation_result")
    return result


def _command(ots, action, filename):
    try:
        result = subprocess.run([str(ots), action, str(filename)], capture_output=True,
                                text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("ots_client_unavailable_or_timed_out") from exc
    return result.returncode, (result.stdout + "\n" + result.stderr)[-4000:]


def _matched(directory, status):
    present = inspect_evidence(directory)
    if any(present[field] != status[field] for field in (
            "signer", "audit_sha256", "checkpoint_sha256",
            "merkle_root", "records", "head")):
        raise ValueError("audit_or_checkpoint_changed_since_stamp")
    return present


def anchor(directory, *, action, ots="ots"):
    directory = Path(directory)
    status_path = directory / STATE_NAME
    checkpoint = directory / "checkpoint.json"
    proof = directory / "checkpoint.json.ots"
    if action == "stamp":
        if status_path.exists() or proof.exists():
            raise ValueError("anchor_already_initialized")
        evidence = inspect_evidence(directory)
        mutations = check_mutations(directory)
        code, output = _command(ots, "stamp", checkpoint)
        if code or not proof.is_file():
            raise RuntimeError("ots_stamp_failed: " + output)
        row = {"schema": "w8-ots-anchor-v1", "state": "pending",
               **evidence, "mutations": mutations,
               "proof_sha256": digest(proof), "stamp_requested_utc": _now(),
               "status_note": "calendar response is NOT Bitcoin confirmation"}
    else:
        row = _read_status(status_path)
        if row.get("schema") != "w8-ots-anchor-v1":
            raise ValueError("invalid_anchor_manifest")
        _matched(directory, row)
        if not proof.is_file():
            raise ValueError("missing_ots_proof")
        if action == "upgrade":
            # After upgrade the legitimate .ots bytes can change.
            if digest(proof) != row["proof_sha256"]:
                raise ValueError("untracked_ots_proof_change")
            code, output = _command(ots, "upgrade", proof)
            if code:
                raise RuntimeError("ots_upgrade_failed: " + output)
            row.update(state="pending", proof_sha256=digest(proof),
                       upgrade_requested_utc=_now())
        elif action == "verify":
            if digest(proof) != row["proof_sha256"]:
                raise ValueError("untracked_ots_proof_change")
            code, output = _command(ots, "verify", proof)
            # Match the official Python OTS CLI's Bitcoin block success line.
            # Nonzero/pending output, even when a calendar accepted the stamp,
            # can NEVER count as verification.
            confirmation = bool(re.search(r"Success!\s*Bitcoin block\s+\d+\b", output))
            row.update(state="verified" if code == 0 and confirmation else "pending",
                       last_verify_utc=_now(), last_verify_exit_code=code,
                       bitcoin_block_confirmed=bool(code == 0 and confirmation))
        else:
            raise ValueError("unsupported_anchor_action")
    _write_status(status_path, row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stamp", "upgrade", "verify", "check"))
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--ots", default="ots")
    args = parser.parse_args()
    if args.action == "check":
        print(json.dumps({"evidence": inspect_evidence(args.evidence_dir),
                          "mutations": check_mutations(args.evidence_dir)},
                         ensure_ascii=False, indent=2))
    else:
        row = anchor(args.evidence_dir, action=args.action, ots=args.ots)
        print(json.dumps({"state": row["state"], "merkle_root": row["merkle_root"],
                          "proof_sha256": row["proof_sha256"]}, ensure_ascii=False))
        if args.action == "verify" and row["state"] != "verified":
            raise SystemExit(2)


if __name__ == "__main__":
    main()
