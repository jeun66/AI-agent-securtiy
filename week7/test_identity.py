from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

from base58 import b58encode
import pytest

from week7.identity import AuthenticationError, IdentityVerifier, did_key, generate_identity, resolve_did_key


# Ed25519 example from the W3C CCG did:key method draft.
REFERENCE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


def test_published_ed25519_did_round_trip():
    assert did_key(resolve_did_key(REFERENCE_DID)) == REFERENCE_DID


@pytest.mark.parametrize("did", [
    "did:web:example.org",
    REFERENCE_DID + "#key",
    REFERENCE_DID[:-1] + "0",
    REFERENCE_DID[:-1] + " ",
    REFERENCE_DID[:-1] + "한",
    "did:key:z" + "1" + REFERENCE_DID[len("did:key:z"):],
])
def test_invalid_did_rejected(did):
    with pytest.raises(AuthenticationError, match="^invalid_did$"):
        IdentityVerifier("gateway").issue(did)


def test_wrong_multicodec_rejected():
    raw = bytes(resolve_did_key(REFERENCE_DID))
    encoded = b58encode(bytes.fromhex("ec01") + raw).decode("ascii")
    with pytest.raises(ValueError, match="^invalid_did$"):
        resolve_did_key("did:key:z" + encoded)


@pytest.mark.parametrize("raw", [b"\x01" + bytes(31), bytes(32)])
def test_small_order_public_key_rejected_before_challenge(raw):
    encoded = b58encode(bytes.fromhex("ed01") + raw).decode("ascii")
    with pytest.raises(AuthenticationError, match="^invalid_did$"):
        IdentityVerifier("gateway").issue("did:key:z" + encoded)


def test_only_right_key_authenticates_and_challenge_is_single_use():
    did, owner = generate_identity()
    _, attacker = generate_identity()
    verifier = IdentityVerifier("gateway")
    challenge = verifier.issue(did)
    message = challenge.signing_bytes()
    with pytest.raises(AuthenticationError, match="^invalid_signature$"):
        verifier.verify(challenge.nonce, attacker.sign(message).signature)

    signature = owner.sign(message).signature
    assert verifier.verify(challenge.nonce, signature) == did
    with pytest.raises(AuthenticationError, match="^challenge_unknown_or_used$"):
        verifier.verify(challenge.nonce, signature)


def test_signature_is_bound_to_did_audience_and_nonce():
    did, owner = generate_identity()
    other_did, _ = generate_identity()
    verifier = IdentityVerifier("gateway")
    challenge = verifier.issue(did)
    another_challenge = verifier.issue(did)
    for changed in (
        replace(challenge, did=other_did),
        replace(challenge, audience="another-gateway"),
        another_challenge,
    ):
        with pytest.raises(AuthenticationError, match="^invalid_signature$"):
            verifier.verify(challenge.nonce, owner.sign(changed.signing_bytes()).signature)


def test_expired_at_deadline_even_with_valid_signature():
    now = 100.0
    did, owner = generate_identity()
    verifier = IdentityVerifier("gateway", ttl_seconds=2, clock=lambda: now)
    challenge = verifier.issue(did)
    signature = owner.sign(challenge.signing_bytes()).signature
    now = 102.0
    with pytest.raises(AuthenticationError, match="^challenge_expired$"):
        verifier.verify(challenge.nonce, signature)


def test_unknown_challenge_and_malformed_signature_rejected():
    did, _ = generate_identity()
    verifier = IdentityVerifier("gateway")
    challenge = verifier.issue(did)
    with pytest.raises(AuthenticationError, match="^challenge_unknown_or_used$"):
        verifier.verify("0" * 64, bytes(64))
    with pytest.raises(AuthenticationError, match="^invalid_signature$"):
        verifier.verify(challenge.nonce, bytes(63))


def test_concurrent_replay_allows_only_one_verification():
    did, owner = generate_identity()
    verifier = IdentityVerifier("gateway")
    challenge = verifier.issue(did)
    signature = owner.sign(challenge.signing_bytes()).signature
    ready = Barrier(2, timeout=5)

    def verify():
        ready.wait()
        try:
            return verifier.verify(challenge.nonce, signature)
        except AuthenticationError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(lambda _: verify(), range(2)))
    assert sorted(outcomes) == sorted([did, "challenge_unknown_or_used"])
