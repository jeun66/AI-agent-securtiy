"""Issue and enforce attenuating, signed capability chains for the local lab."""

from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import re
from threading import Lock
from time import time
from uuid import uuid4

from nacl.signing import SigningKey

from week7.credentials import VerifiedCredential, read_signed_credential, verify_credential
from week7.identity import did_key, resolve_did_key
from week7.scope import Grant, decode_grants, encode_grants
from week7.signed_tokens import sign_token, verify_token


CAPABILITY_TYPE = "agent-capability+jwt"
MAX_CHAIN_LENGTH = 8
_CAPABILITY_FIELDS = {
    "iss", "sub", "aud", "iat", "exp", "jti", "scope", "remaining_depth", "credential", "parent",
}


@dataclass(frozen=True, slots=True)
class Capability:
    issuer: str
    subject: str
    audience: str
    issued_at: int
    expires_at: int
    grants: frozenset[Grant]
    remaining_depth: int
    credential: str
    parent: str | None
    token_id: str
    digest: str


@dataclass(frozen=True, slots=True)
class VerifiedDelegation:
    path: tuple[str, ...]
    token_digests: tuple[str, ...]
    effective_grants: frozenset[Grant]
    expires_at: int
    delegated_grants: tuple[frozenset[Grant], ...]


def _digest(token: str) -> str:
    return sha256(token.encode("ascii")).hexdigest()


def _is_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and re.fullmatch(r"[0-9a-f]+", value) is not None


def _read_capability(token: str) -> Capability:
    issuer, body = verify_token(token, CAPABILITY_TYPE)
    if set(body) != _CAPABILITY_FIELDS or body["iss"] != issuer:
        raise ValueError("invalid_capability_profile")
    resolve_did_key(body["sub"])
    if not isinstance(body["aud"], str) or not body["aud"]:
        raise ValueError("invalid_capability_audience")
    start, end, depth = body["iat"], body["exp"], body["remaining_depth"]
    if type(start) is not int or type(end) is not int or not 0 <= start < end:
        raise ValueError("invalid_capability_time")
    if type(depth) is not int or not 0 <= depth < MAX_CHAIN_LENGTH:
        raise ValueError("invalid_capability_depth")
    parent = body["parent"]
    if not _is_hex(body["jti"], 32) or not _is_hex(body["credential"], 64):
        raise ValueError("invalid_capability_reference")
    if parent is not None and not _is_hex(parent, 64):
        raise ValueError("invalid_capability_reference")
    return Capability(issuer, body["sub"], body["aud"], start, end, decode_grants(body["scope"]),
                      depth, body["credential"], parent, body["jti"], _digest(token))


def _check_root(root: Capability, credential: VerifiedCredential) -> None:
    if root.parent is not None or root.issuer != credential.subject:
        raise ValueError("invalid_root_delegation")
    if not root.grants <= credential.grants:
        raise ValueError("scope_expanded")
    if not credential.valid_from <= root.issued_at < root.expires_at <= credential.valid_until:
        raise ValueError("validity_expanded")


def _check_child(child: Capability, parent: Capability) -> None:
    if child.parent != parent.digest or child.issuer != parent.subject:
        raise ValueError("invalid_parent_link")
    if child.credential != parent.credential or child.audience != parent.audience:
        raise ValueError("invalid_parent_context")
    if not child.grants <= parent.grants:
        raise ValueError("scope_expanded")
    if not parent.issued_at <= child.issued_at < child.expires_at <= parent.expires_at:
        raise ValueError("validity_expanded")
    if child.remaining_depth >= parent.remaining_depth:
        raise ValueError("delegation_depth_exceeded")


def issue_capability(key: SigningKey, subject: str, audience: str, grants: Iterable[Grant], *,
                     credential: str, issued_at: int, expires_at: int, remaining_depth: int = 0,
                     parent: str | None = None) -> str:
    vc = read_signed_credential(credential)
    if vc.audience != audience:
        raise ValueError("credential_audience_mismatch")
    parent_cap = _read_capability(parent) if parent is not None else None
    body = {
        "iss": did_key(key.verify_key), "sub": subject, "aud": audience,
        "iat": issued_at, "exp": expires_at, "jti": uuid4().hex,
        "scope": encode_grants(grants), "remaining_depth": remaining_depth,
        "credential": _digest(credential), "parent": parent_cap.digest if parent_cap else None,
    }
    token = sign_token(key, CAPABILITY_TYPE, body)
    capability = _read_capability(token)
    if parent_cap is None:
        _check_root(capability, vc)
    else:
        _check_child(capability, parent_cap)
    return token


class DelegationVerifier:
    """In-process policy and revocation state owned by the trusted runtime."""

    def __init__(self, audience: str, *, trusted_issuers: Collection[str], ceiling: Iterable[Grant],
                 user_policies: Mapping[str, Iterable[Grant]], clock: Callable[[], float] = time):
        self._audience = audience
        self._trusted_issuers = frozenset(trusted_issuers)
        self._ceiling = frozenset(ceiling)
        self._user_policies = {did: frozenset(grants) for did, grants in user_policies.items()}
        self._clock = clock
        self._revoked: set[tuple[str, str]] = set()
        self._lock = Lock()

    @property
    def audience(self) -> str:
        return self._audience

    def require_unexpired(self, verified: VerifiedDelegation) -> None:
        if self._clock() >= verified.expires_at:
            raise ValueError("capability_inactive")

    def narrow_user_policy(self, user_did: str, grants: Iterable[Grant]) -> None:
        narrowed = frozenset(grants)
        with self._lock:
            previous = self._user_policies.get(user_did)
            if previous is None or not narrowed <= previous:
                raise ValueError("user_policy_expanded")
            self._user_policies[user_did] = narrowed

    def revoke(self, token: str) -> None:
        capability = _read_capability(token)
        if capability.audience != self._audience:
            raise ValueError("capability_audience_mismatch")
        with self._lock:
            self._revoked.add((capability.issuer, capability.token_id))

    def authorize(self, credential: str, chain: list[str] | tuple[str, ...], *, authenticated_did: str,
                  requested: Grant) -> VerifiedDelegation:
        """Authorize one action using the DID returned by the identity verifier."""
        with self.authorized(credential, chain, authenticated_did=authenticated_did, requested=requested) as verified:
            return verified

    @contextmanager
    def authorized(self, credential: str, chain: list[str] | tuple[str, ...], *, authenticated_did: str,
                   requested: Grant) -> Iterator[VerifiedDelegation]:
        """Keep the policy and revocation state stable until the guarded action finishes."""
        if not isinstance(chain, (list, tuple)):
            raise ValueError("invalid_chain_length")
        chain = tuple(chain)
        if not 1 <= len(chain) <= MAX_CHAIN_LENGTH:
            raise ValueError("invalid_chain_length")
        capabilities = tuple(_read_capability(token) for token in chain)
        root, leaf = capabilities[0], capabilities[-1]
        if leaf.subject != authenticated_did:
            raise ValueError("capability_subject_mismatch")

        with self._lock:
            now = self._clock()
            vc = verify_credential(credential, trusted_issuers=self._trusted_issuers,
                                   audience=self._audience, now=now)
            credential_digest = _digest(credential)
            for capability in capabilities:
                if (capability.issuer, capability.token_id) in self._revoked:
                    raise ValueError("capability_revoked")
                if capability.credential != credential_digest:
                    raise ValueError("capability_credential_mismatch")
                if capability.audience != self._audience:
                    raise ValueError("capability_audience_mismatch")
                if not capability.issued_at <= now < capability.expires_at:
                    raise ValueError("capability_inactive")
            _check_root(root, vc)
            if not root.grants <= self._ceiling:
                raise ValueError("system_ceiling_exceeded")
            for parent, child in zip(capabilities, capabilities[1:]):
                _check_child(child, parent)

            user_grants = self._user_policies.get(vc.subject, frozenset())
            effective = self._ceiling & user_grants & leaf.grants
            if requested not in effective:
                raise ValueError("scope_denied")
            yield VerifiedDelegation(
                (root.issuer, *(capability.subject for capability in capabilities)),
                tuple(capability.digest for capability in capabilities), effective, leaf.expires_at,
                tuple(capability.grants for capability in capabilities),
            )
