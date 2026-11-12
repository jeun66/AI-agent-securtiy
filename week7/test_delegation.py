from types import SimpleNamespace

import pytest

from week7.credentials import issue_credential, verify_credential
from week7.delegation import CAPABILITY_TYPE, DelegationVerifier, issue_capability
from week7.identity import IdentityVerifier, generate_identity
from week7.scope import Grant, encode_grants
from week7.signed_tokens import sign_token, verify_token


NOW = 1_794_442_000
AUDIENCE = "urn:agent-trust:gateway:w7"
READ = Grant("read_file", "docs/readme.txt")
WRITE = Grant("write_file", "docs/readme.txt")
OTHER_READ = Grant("read_file", "docs/notes.txt")
GRANTS = {READ, WRITE, OTHER_READ}


@pytest.fixture
def lab():
    issuer, issuer_key = generate_identity()
    user, user_key = generate_identity()
    middle, middle_key = generate_identity()
    leaf, leaf_key = generate_identity()
    credential = issue_credential(issuer_key, user, AUDIENCE, GRANTS, valid_from=NOW - 20, valid_until=NOW + 60)
    root = issue_capability(user_key, middle, AUDIENCE, GRANTS, credential=credential,
                            issued_at=NOW - 10, expires_at=NOW + 30, remaining_depth=1)
    child = issue_capability(middle_key, leaf, AUDIENCE, GRANTS, credential=credential,
                             issued_at=NOW - 5, expires_at=NOW + 15, parent=root)
    verifier = DelegationVerifier(AUDIENCE, trusted_issuers={issuer}, ceiling=GRANTS,
                                  user_policies={user: GRANTS}, clock=lambda: NOW)
    return SimpleNamespace(issuer=issuer, issuer_key=issuer_key, user=user, user_key=user_key,
                           middle=middle, middle_key=middle_key, leaf=leaf, leaf_key=leaf_key,
                           credential=credential, root=root, child=child, verifier=verifier)


def test_valid_chain_uses_did_authenticated_in_stage_two(lab):
    identity = IdentityVerifier(AUDIENCE)
    challenge = identity.issue(lab.leaf)
    signature = lab.leaf_key.sign(challenge.signing_bytes()).signature
    actor = identity.verify(challenge.nonce, signature)
    decision = lab.verifier.authorize(lab.credential, [lab.root, lab.child], authenticated_did=actor, requested=READ)
    assert decision.path == (lab.user, lab.middle, lab.leaf)
    assert decision.effective_grants == GRANTS
    assert len(decision.token_digests) == 2


@pytest.mark.parametrize("resource", ["../docs/readme.txt", "docs/../readme.txt", "/docs/readme.txt",
                                      "docs//readme.txt", "docs/./readme.txt", "docs/*", "docs\\readme.txt"])
def test_scope_rejects_noncanonical_resources(resource):
    with pytest.raises(ValueError, match="^invalid_resource$"):
        Grant("read_file", resource)


def test_scope_does_not_combine_actions_and_resources_across_grants(lab):
    with pytest.raises(ValueError, match="^scope_denied$"):
        lab.verifier.authorize(lab.credential, [lab.root, lab.child], authenticated_did=lab.leaf,
                               requested=Grant("write_file", OTHER_READ.resource))


def test_only_the_leaf_subject_can_invoke_the_chain(lab):
    with pytest.raises(ValueError, match="^capability_subject_mismatch$"):
        lab.verifier.authorize(lab.credential, [lab.root, lab.child], authenticated_did=lab.middle, requested=READ)


def test_capability_issuance_rejects_widening_and_extra_depth(lab):
    common = {"credential": lab.credential, "issued_at": NOW - 5, "expires_at": NOW + 10, "parent": lab.root}
    with pytest.raises(ValueError, match="^scope_expanded$"):
        issue_capability(lab.middle_key, lab.leaf, AUDIENCE, {Grant("read_file", "private.txt")}, **common)
    with pytest.raises(ValueError, match="^delegation_depth_exceeded$"):
        issue_capability(lab.middle_key, lab.leaf, AUDIENCE, {READ}, remaining_depth=1, **common)


@pytest.mark.parametrize(("changes", "reason"), [
    ({"scope": encode_grants({Grant("read_file", "private.txt")})}, "scope_expanded"),
    ({"remaining_depth": 1}, "delegation_depth_exceeded"),
    ({"exp": NOW + 31}, "validity_expanded"),
    ({"exp": NOW}, "capability_inactive"),
    ({"iat": NOW + 1}, "capability_inactive"),
    ({"parent": "0" * 64}, "invalid_parent_link"),
    ({"aud": "urn:other:gateway"}, "capability_audience_mismatch"),
])
def test_runtime_rechecks_malicious_but_validly_signed_children(lab, changes, reason):
    _, body = verify_token(lab.child, CAPABILITY_TYPE)
    malicious = sign_token(lab.middle_key, CAPABILITY_TYPE, {**body, **changes})
    with pytest.raises(ValueError, match=f"^{reason}$"):
        lab.verifier.authorize(lab.credential, [lab.root, malicious], authenticated_did=lab.leaf, requested=READ)


def test_signer_must_be_parent_subject_even_if_signature_is_valid(lab):
    _, body = verify_token(lab.child, CAPABILITY_TYPE)
    malicious = sign_token(lab.user_key, CAPABILITY_TYPE, {**body, "iss": lab.user})
    with pytest.raises(ValueError, match="^invalid_parent_link$"):
        lab.verifier.authorize(lab.credential, [lab.root, malicious], authenticated_did=lab.leaf, requested=READ)


def test_root_signer_must_be_the_credential_subject(lab):
    _, body = verify_token(lab.root, CAPABILITY_TYPE)
    malicious = sign_token(lab.leaf_key, CAPABILITY_TYPE, {**body, "iss": lab.leaf})
    with pytest.raises(ValueError, match="^invalid_root_delegation$"):
        lab.verifier.authorize(lab.credential, [malicious], authenticated_did=lab.middle, requested=READ)


def test_modified_token_is_rejected_by_ed25519_signature(lab):
    header, claims, signature = lab.child.split(".")
    changed = ("A" if claims[0] != "A" else "B") + claims[1:]
    with pytest.raises(ValueError, match="^invalid_token_signature$"):
        lab.verifier.authorize(lab.credential, [lab.root, f"{header}.{changed}.{signature}"],
                               authenticated_did=lab.leaf, requested=READ)


def test_untrusted_issuer_and_wrong_credential_context_are_rejected(lab):
    _, stranger = generate_identity()
    untrusted = issue_credential(stranger, lab.user, AUDIENCE, GRANTS, valid_from=NOW - 20, valid_until=NOW + 60)
    with pytest.raises(ValueError, match="^credential_issuer_untrusted$"):
        lab.verifier.authorize(untrusted, [lab.root, lab.child], authenticated_did=lab.leaf, requested=READ)
    other_credential = issue_credential(lab.issuer_key, lab.user, AUDIENCE, GRANTS,
                                        valid_from=NOW - 19, valid_until=NOW + 60)
    with pytest.raises(ValueError, match="^capability_credential_mismatch$"):
        lab.verifier.authorize(other_credential, [lab.root, lab.child], authenticated_did=lab.leaf, requested=READ)


def test_vc_audience_and_expiry(lab):
    with pytest.raises(ValueError, match="^credential_audience_mismatch$"):
        verify_credential(lab.credential, trusted_issuers={lab.issuer}, audience="urn:other:gateway", now=NOW)
    with pytest.raises(ValueError, match="^credential_inactive$"):
        verify_credential(lab.credential, trusted_issuers={lab.issuer}, audience=AUDIENCE, now=NOW + 60)


def test_capability_cannot_be_used_as_a_vc(lab):
    with pytest.raises(ValueError, match="^invalid_token_format$"):
        verify_credential(lab.root, trusted_issuers={lab.issuer}, audience=AUDIENCE, now=NOW)


def test_ceiling_cannot_be_exceeded_even_by_a_signed_user_delegation(lab):
    verifier = DelegationVerifier(AUDIENCE, trusted_issuers={lab.issuer}, ceiling={READ},
                                  user_policies={lab.user: GRANTS}, clock=lambda: NOW)
    with pytest.raises(ValueError, match="^system_ceiling_exceeded$"):
        verifier.authorize(lab.credential, [lab.root, lab.child], authenticated_did=lab.leaf, requested=READ)


def test_policy_narrowing_updates_existing_chain_and_cannot_reexpand(lab):
    lab.verifier.narrow_user_policy(lab.user, {READ})
    chain = [lab.root, lab.child]
    decision = lab.verifier.authorize(lab.credential, chain, authenticated_did=lab.leaf, requested=READ)
    assert decision.effective_grants == {READ}
    with pytest.raises(ValueError, match="^scope_denied$"):
        lab.verifier.authorize(lab.credential, chain, authenticated_did=lab.leaf, requested=WRITE)
    with pytest.raises(ValueError, match="^user_policy_expanded$"):
        lab.verifier.narrow_user_policy(lab.user, GRANTS)


def test_parent_revocation_invalidates_already_issued_descendant(lab):
    lab.verifier.revoke(lab.root)
    lab.verifier.revoke(lab.root)
    with pytest.raises(ValueError, match="^capability_revoked$"):
        lab.verifier.authorize(lab.credential, [lab.root, lab.child], authenticated_did=lab.leaf, requested=READ)


def test_revocation_survives_resigning_the_same_token_id(lab):
    lab.verifier.revoke(lab.root)
    _, body = verify_token(lab.root, CAPABILITY_TYPE)
    alternative = sign_token(lab.user_key, CAPABILITY_TYPE, {**body, "exp": NOW + 29})
    with pytest.raises(ValueError, match="^capability_revoked$"):
        lab.verifier.authorize(lab.credential, [alternative], authenticated_did=lab.middle, requested=READ)
