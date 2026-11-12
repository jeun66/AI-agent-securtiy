"""The lab's narrowly scoped VC Data Model 2.0 + Ed25519 JWS profile."""

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from nacl.signing import SigningKey

from week7.identity import did_key, resolve_did_key
from week7.scope import Grant, decode_grants, encode_grants
from week7.signed_tokens import sign_token, verify_token


VC_TYPE = "vc+jwt"
_VOCAB = "https://example.org/agent-trust#"
_CONTEXT = ["https://www.w3.org/ns/credentials/v2", {
    "AgentDelegationCredential": _VOCAB + "AgentDelegationCredential",
    "gatewayAudience": _VOCAB + "gatewayAudience",
    "grants": {"@id": _VOCAB + "grants", "@container": "@set"},
    "action": _VOCAB + "action",
    "resource": _VOCAB + "resource",
}]
_TYPES = ["VerifiableCredential", "AgentDelegationCredential"]
_LAST_UTC_SECOND = 253402300799  # 9999-12-31T23:59:59Z


@dataclass(frozen=True, slots=True)
class VerifiedCredential:
    issuer: str
    subject: str
    audience: str
    grants: frozenset[Grant]
    valid_from: int
    valid_until: int


def _utc_text(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: object) -> int:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise ValueError("invalid_credential_time")
    try:
        timestamp = int(datetime.fromisoformat(value).timestamp())
        if _utc_text(timestamp) != value:
            raise ValueError
    except (ValueError, OverflowError, OSError):
        raise ValueError("invalid_credential_time") from None
    return timestamp


def issue_credential(key: SigningKey, subject: str, audience: str, grants: Iterable[Grant], *,
                     valid_from: int, valid_until: int) -> str:
    resolve_did_key(subject)
    if not isinstance(audience, str) or not audience:
        raise ValueError("invalid_credential_audience")
    if type(valid_from) is not int or type(valid_until) is not int:
        raise ValueError("invalid_credential_time")
    if not 0 <= valid_from < valid_until <= _LAST_UTC_SECOND:
        raise ValueError("invalid_credential_time")
    body = {
        "@context": _CONTEXT,
        "type": _TYPES,
        "issuer": did_key(key.verify_key),
        "validFrom": _utc_text(valid_from),
        "validUntil": _utc_text(valid_until),
        "gatewayAudience": audience,
        "credentialSubject": {"id": subject, "grants": encode_grants(grants)},
    }
    return sign_token(key, VC_TYPE, body)


def read_signed_credential(token: str) -> VerifiedCredential:
    issuer, body = verify_token(token, VC_TYPE)
    expected_fields = {"@context", "type", "issuer", "validFrom", "validUntil", "gatewayAudience", "credentialSubject"}
    if set(body) != expected_fields or body["@context"] != _CONTEXT or body["type"] != _TYPES:
        raise ValueError("invalid_credential_profile")
    if body["issuer"] != issuer:
        raise ValueError("credential_issuer_mismatch")
    subject = body["credentialSubject"]
    if not isinstance(subject, dict) or set(subject) != {"id", "grants"}:
        raise ValueError("invalid_credential_subject")
    resolve_did_key(subject["id"])
    audience = body["gatewayAudience"]
    if not isinstance(audience, str) or not audience:
        raise ValueError("invalid_credential_audience")
    start, end = _parse_utc(body["validFrom"]), _parse_utc(body["validUntil"])
    if not 0 <= start < end:
        raise ValueError("invalid_credential_time")
    return VerifiedCredential(issuer, subject["id"], audience, decode_grants(subject["grants"]), start, end)


def verify_credential(token: str, *, trusted_issuers: Collection[str], audience: str,
                      now: float) -> VerifiedCredential:
    credential = read_signed_credential(token)
    if credential.issuer not in trusted_issuers:
        raise ValueError("credential_issuer_untrusted")
    if credential.audience != audience:
        raise ValueError("credential_audience_mismatch")
    if not credential.valid_from <= now < credential.valid_until:
        raise ValueError("credential_inactive")
    return credential
