"""Exercise a signed delegation chain with local Ed25519 identities."""

from time import time

from week7.credentials import issue_credential
from week7.delegation import CAPABILITY_TYPE, DelegationVerifier, issue_capability
from week7.identity import IdentityVerifier, generate_identity
from week7.scope import Grant, encode_grants
from week7.signed_tokens import sign_token, verify_token


def main():
    audience = "urn:agent-trust:gateway:w7"
    now = int(time())
    read = Grant("read_file", "docs/readme.txt")
    write = Grant("write_file", "docs/readme.txt")
    read_notes = Grant("read_file", "docs/notes.txt")
    read_private = Grant("read_file", "private/secret.txt")
    user_grants = {read, write, read_notes}

    issuer, issuer_key = generate_identity()
    user, user_key = generate_identity()
    parent, parent_key = generate_identity()
    child, child_key = generate_identity()
    identity = IdentityVerifier(audience)
    challenge = identity.issue(child)
    authenticated_did = identity.verify(challenge.nonce, child_key.sign(challenge.signing_bytes()).signature)

    vc = issue_credential(issuer_key, user, audience, user_grants, valid_from=now, valid_until=now + 300)
    root = issue_capability(user_key, parent, audience, user_grants, credential=vc,
                            issued_at=now, expires_at=now + 240, remaining_depth=1)
    leaf = issue_capability(parent_key, child, audience, {read, write}, credential=vc,
                            issued_at=now, expires_at=now + 180, parent=root)
    verifier = DelegationVerifier(audience, trusted_issuers={issuer}, ceiling=user_grants,
                                  user_policies={user: user_grants})

    def check(label, requested, chain, denied_reason=None):
        try:
            result = verifier.authorize(vc, chain, authenticated_did=authenticated_did, requested=requested)
        except ValueError as exc:
            if str(exc) != denied_reason:
                raise
            print(f"{label}: DENY ({exc})")
            return
        if denied_reason is not None:
            raise RuntimeError(f"{label}: unexpectedly authorized")
        print(f"{label}: ALLOW")
        return result

    path = check("normal delegated read", read, [root, leaf]).path
    print("verified path (user, parent, child):")
    for did in path:
        print(f"  {did}")

    head, body, signature = leaf.split(".")
    changed_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    check("forged token", read, [root, f"{head}.{body}.{changed_signature}"], "invalid_token_signature")

    _, claims = verify_token(leaf, CAPABILITY_TYPE)
    widened = sign_token(parent_key, CAPABILITY_TYPE, {**claims, "scope": encode_grants({read, read_private})})
    check("valid signature with expanded scope", read_private, [root, widened], "scope_expanded")

    check("write before policy narrowing", write, [root, leaf])
    verifier.narrow_user_policy(user, {read})
    check("write after policy narrowing", write, [root, leaf], "scope_denied")
    check("read after policy narrowing", read, [root, leaf])

    verifier.revoke(root)
    check("child call after parent revocation", read, [root, leaf], "capability_revoked")


if __name__ == "__main__":
    main()
