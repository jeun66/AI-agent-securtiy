"""Signed JSONL audit records and independently verifiable checkpoints."""

import argparse
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from threading import Lock
from time import time_ns
from uuid import uuid4

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from week7.identity import did_key, resolve_did_key


_GENESIS = "0" * 64
_RECORD_DOMAIN = b"agent-trust/audit-record/v1\x00"
_CHECKPOINT_DOMAIN = b"agent-trust/audit-checkpoint/v1\x00"


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _read_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or _canonical(value) + b"\n" != raw:
            raise ValueError
    except (ValueError, RecursionError):
        raise ValueError("invalid_audit_json") from None
    return value


def merkle_root(hashes: list[str]) -> str:
    """RFC 9162 tree hashing with the ordered record hashes as leaf data."""
    leaves = [sha256(b"\x00" + bytes.fromhex(digest)).digest() for digest in hashes]

    def subtree(start: int, end: int) -> bytes:
        size = end - start
        if size == 1:
            return leaves[start]
        pivot = start + (1 << ((size - 1).bit_length() - 1))
        return sha256(b"\x01" + subtree(start, pivot) + subtree(pivot, end)).digest()

    return subtree(0, len(leaves)).hex() if leaves else sha256(b"").hexdigest()


class AuditWriteError(RuntimeError):
    """The audit writer cannot durably accept a record."""


class SignedAuditLog:
    def __init__(self, path: Path, key: SigningKey):
        self._key = key
        self._log_id = uuid4().hex
        self._hashes: list[str] = []
        self._lock = Lock()
        self._failed = False
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._stream = os.fdopen(fd, "wb", buffering=0)

    @property
    def signer(self) -> str:
        return did_key(self._key.verify_key)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        with self._lock:
            self._stream.close()

    def append(self, event: dict) -> None:
        with self._lock:
            if self._failed or self._stream.closed:
                raise AuditWriteError("audit_unavailable")
            body = {
                "log_id": self._log_id, "sequence": len(self._hashes) + 1,
                "previous_hash": self._hashes[-1] if self._hashes else _GENESIS,
                "timestamp_ns": time_ns(), "event": event,
            }
            digest = sha256(_canonical(body)).digest()
            signature = self._key.sign(_RECORD_DOMAIN + digest).signature.hex()
            encoded = _canonical({**body, "hash": digest.hex(), "signature": signature}) + b"\n"
            offset = None
            try:
                offset = self._stream.tell()
                if self._stream.write(encoded) != len(encoded):
                    raise OSError("incomplete audit write")
                os.fsync(self._stream.fileno())
            except OSError:
                self._failed = True
                if offset is not None:
                    with suppress(OSError):
                        os.ftruncate(self._stream.fileno(), offset)
                        os.fsync(self._stream.fileno())
                raise AuditWriteError("audit_unavailable") from None
            self._hashes.append(digest.hex())

    def write_checkpoint(self, path: Path) -> None:
        with self._lock:
            if self._failed:
                raise AuditWriteError("audit_unavailable")
            body = _checkpoint_body(self._log_id, self._hashes)
            signature = self._key.sign(_CHECKPOINT_DOMAIN + _canonical(body)).signature.hex()
            with path.open("xb") as stream:
                stream.write(_canonical({**body, "signature": signature}) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())


def _checkpoint_body(log_id: str, hashes: list[str]) -> dict:
    return {"log_id": log_id, "records": len(hashes), "head": hashes[-1] if hashes else _GENESIS,
            "merkle_root": merkle_root(hashes)}


def _verify_signature(key: VerifyKey, message: bytes, encoded: object) -> None:
    if not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-f]{128}", encoded):
        raise ValueError("invalid_audit_signature")
    try:
        key.verify(message, bytes.fromhex(encoded))
    except BadSignatureError:
        raise ValueError("invalid_audit_signature") from None


def _missing_executions(events: list[dict]) -> tuple[str, ...]:
    seen = set()
    pending = {}
    for event in events:
        call_id = event.get("call_id")
        phase, decision = event.get("phase"), event.get("decision")
        if not isinstance(call_id, str) or not re.fullmatch(r"[0-9a-f]{32}", call_id):
            raise ValueError("invalid_audit_event")
        if phase == "decision":
            if call_id in seen or event.get("tool_invoked") is not False:
                raise ValueError("invalid_audit_event_order")
            if decision not in ("ALLOW", "DENY", "REQUIRE_APPROVAL", "ERROR"):
                raise ValueError("invalid_audit_event")
            seen.add(call_id)
            if decision == "ALLOW":
                pending[call_id] = event
        elif phase == "execution":
            initial = pending.pop(call_id, None)
            invoked = event.get("tool_invoked")
            valid_outcome = (decision in ("ALLOW", "ERROR") and invoked is True) or (decision == "DENY" and invoked is False)
            if initial is None or not valid_outcome:
                raise ValueError("invalid_audit_event_order")
            fields = ("actor_id", "request_hash", "action", "resource", "policy_version", "delegation")
            if any(initial.get(field) != event.get(field) for field in fields):
                raise ValueError("audit_execution_context_mismatch")
        else:
            raise ValueError("invalid_audit_event")
    return tuple(pending)


@dataclass(frozen=True, slots=True)
class AuditVerification:
    events: tuple[dict, ...]
    head: str
    merkle_root: str
    missing_executions: tuple[str, ...]


def verify_audit(path: Path, *, signer: str, checkpoint: Path | None = None) -> AuditVerification:
    key = resolve_did_key(signer)
    hashes: list[str] = []
    events: list[dict] = []
    log_id = None
    with path.open("rb") as stream:
        for sequence, line in enumerate(stream, start=1):
            body = _read_object(line)
            signature = body.pop("signature", None)
            recorded_hash = body.pop("hash", None)
            if set(body) != {"log_id", "sequence", "previous_hash", "timestamp_ns", "event"}:
                raise ValueError("invalid_audit_record")
            if log_id is None:
                log_id = body["log_id"]
                if not isinstance(log_id, str) or not re.fullmatch(r"[0-9a-f]{32}", log_id):
                    raise ValueError("invalid_audit_record")
            previous = hashes[-1] if hashes else _GENESIS
            if body["log_id"] != log_id or type(body["sequence"]) is not int or body["sequence"] != sequence:
                raise ValueError("audit_chain_mismatch")
            if body["previous_hash"] != previous:
                raise ValueError("audit_chain_mismatch")
            if type(body["timestamp_ns"]) is not int or not isinstance(body["event"], dict):
                raise ValueError("invalid_audit_record")
            digest = sha256(_canonical(body)).digest()
            if digest.hex() != recorded_hash:
                raise ValueError("audit_hash_mismatch")
            _verify_signature(key, _RECORD_DOMAIN + digest, signature)
            hashes.append(digest.hex())
            events.append(body["event"])

    if checkpoint is not None:
        saved = _read_object(checkpoint.read_bytes())
        signature = saved.pop("signature", None)
        _verify_signature(key, _CHECKPOINT_DOMAIN + _canonical(saved), signature)
        if log_id is None:
            log_id = saved.get("log_id")
            if not isinstance(log_id, str) or not re.fullmatch(r"[0-9a-f]{32}", log_id):
                raise ValueError("invalid_audit_checkpoint")
        if _canonical(saved) != _canonical(_checkpoint_body(log_id, hashes)):
            raise ValueError("audit_checkpoint_mismatch")
    return AuditVerification(tuple(events), hashes[-1] if hashes else _GENESIS,
                             merkle_root(hashes), _missing_executions(events))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--signer", required=True)
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()
    try:
        result = verify_audit(args.audit, signer=args.signer, checkpoint=args.checkpoint)
    except (OSError, ValueError) as exc:
        print(f"audit verification failed ({exc})")
        return 1
    print(f"records={len(result.events)} missing_executions={len(result.missing_executions)}")
    print(f"head={result.head}\nmerkle_root={result.merkle_root}")
    return 2 if result.missing_executions else 0


if __name__ == "__main__":
    raise SystemExit(main())
