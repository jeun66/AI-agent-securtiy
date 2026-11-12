"""Ed25519 did:key identities and local, single-use proof of key ownership."""

from collections.abc import Callable
from dataclasses import dataclass
import json
from secrets import token_hex
from threading import Lock
from time import monotonic

from base58 import b58decode, b58encode
from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


DID_PREFIX = "did:key:z"
ED25519_CODEC = bytes.fromhex("ed01")


def did_key(public_key: VerifyKey) -> str:
    return DID_PREFIX + b58encode(ED25519_CODEC + bytes(public_key)).decode("ascii")


def resolve_did_key(did: str) -> VerifyKey:
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise ValueError("invalid_did")
    fingerprint = did[len(DID_PREFIX):]
    if len(fingerprint) != 47:
        raise ValueError("invalid_did")
    try:
        decoded = b58decode(fingerprint)
    except ValueError:
        raise ValueError("invalid_did") from None
    if len(decoded) != 34 or not decoded.startswith(ED25519_CODEC):
        raise ValueError("invalid_did")
    public_key = decoded[len(ED25519_CODEC):]
    if not crypto_core_ed25519_is_valid_point(public_key):
        raise ValueError("invalid_did")
    key = VerifyKey(public_key)
    if did_key(key) != did:
        raise ValueError("invalid_did")
    return key


def generate_identity() -> tuple[str, SigningKey]:
    signing_key = SigningKey.generate()
    return did_key(signing_key.verify_key), signing_key


@dataclass(frozen=True, slots=True)
class Challenge:
    did: str
    audience: str
    nonce: str

    def signing_bytes(self) -> bytes:
        fields = ["agent-trust/identity-challenge/v1", self.did, self.audience, self.nonce]
        return json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@dataclass(frozen=True, slots=True)
class _PendingChallenge:
    challenge: Challenge
    verify_key: VerifyKey
    expires_at: float


class AuthenticationError(ValueError):
    """The challenge could not establish ownership of the requested DID."""


class IdentityVerifier:
    def __init__(self, audience: str, *, ttl_seconds: int = 60,
                 clock: Callable[[], float] = monotonic):
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience_required")
        if type(ttl_seconds) is not int or ttl_seconds <= 0:
            raise ValueError("invalid_challenge_ttl")
        self._audience = audience
        self._ttl = ttl_seconds
        self._clock = clock
        self._pending: dict[str, _PendingChallenge] = {}
        self._lock = Lock()

    def issue(self, did: str) -> Challenge:
        try:
            verify_key = resolve_did_key(did)
        except ValueError:
            raise AuthenticationError("invalid_did") from None
        with self._lock:
            now = self._clock()
            self._pending = {
                nonce: record for nonce, record in self._pending.items()
                if record.expires_at > now
            }
            challenge = Challenge(did, self._audience, token_hex(32))
            self._pending[challenge.nonce] = _PendingChallenge(
                challenge, verify_key, now + self._ttl,
            )
            return challenge

    def verify(self, nonce: str, signature: bytes) -> str:
        """Return the authenticated DID from the server's challenge record."""
        if not isinstance(nonce, str) or len(nonce) != 64:
            raise AuthenticationError("challenge_unknown_or_used")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise AuthenticationError("invalid_signature")
        with self._lock:
            pending = self._pending.get(nonce)
            if pending is None:
                raise AuthenticationError("challenge_unknown_or_used")
            if self._clock() >= pending.expires_at:
                del self._pending[nonce]
                raise AuthenticationError("challenge_expired")
            try:
                pending.verify_key.verify(pending.challenge.signing_bytes(), signature)
            except BadSignatureError:
                raise AuthenticationError("invalid_signature") from None
            del self._pending[nonce]
            return pending.challenge.did
