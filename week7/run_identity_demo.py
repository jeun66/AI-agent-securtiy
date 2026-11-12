"""Exercise the W7 challenge verifier with local, ephemeral Ed25519 keys."""

from time import sleep

from week7.identity import AuthenticationError, IdentityVerifier, generate_identity


def expect_denied(verifier, challenge, signature, label, reason):
    try:
        verifier.verify(challenge.nonce, signature)
    except AuthenticationError as exc:
        if str(exc) != reason:
            raise
        print(f"{label}: DENY ({reason})")
    else:
        raise RuntimeError(f"{label}: unexpectedly authenticated")


def main():
    verifier = IdentityVerifier("week7-local-gateway")
    for label in ("user", "agent"):
        did, key = generate_identity()
        challenge = verifier.issue(did)
        signature = key.sign(challenge.signing_bytes()).signature
        authenticated_did = verifier.verify(challenge.nonce, signature)
        if authenticated_did != did:
            raise RuntimeError("unexpected authenticated DID")
        print(f"{label}: ALLOW ({authenticated_did})")

    expect_denied(verifier, challenge, signature, "replay", "challenge_unknown_or_used")

    did, owner = generate_identity()
    _, other_key = generate_identity()
    challenge = verifier.issue(did)
    forged = other_key.sign(challenge.signing_bytes()).signature
    expect_denied(verifier, challenge, forged, "impersonation", "invalid_signature")

    expiring_verifier = IdentityVerifier("week7-local-gateway", ttl_seconds=1)
    expiring = expiring_verifier.issue(did)
    valid_signature = owner.sign(expiring.signing_bytes()).signature
    sleep(1)
    expect_denied(expiring_verifier, expiring, valid_signature, "expired", "challenge_expired")


if __name__ == "__main__":
    main()
