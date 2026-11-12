"""Compact JWS with a fixed Ed25519 algorithm and did:key signing keys."""

import base64
import json

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from week7.identity import did_key, resolve_did_key


MAX_TOKEN_LENGTH = 16_384


def _encode_segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_segment(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    if _encode_segment(raw) != segment:
        raise ValueError("invalid_token_encoding")
    return raw


def _object_from_pairs(pairs: list) -> dict:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate_json_member")
    return value


def _decode_object(segment: str) -> dict:
    value = json.loads(_decode_segment(segment).decode("utf-8"), object_pairs_hook=_object_from_pairs)
    if not isinstance(value, dict):
        raise ValueError("invalid_token_object")
    return value


def _encode_object(value: dict) -> str:
    return _encode_segment(json.dumps(value, separators=(",", ":"), sort_keys=True,
                                      ensure_ascii=True, allow_nan=False).encode("ascii"))


def sign_token(key: SigningKey, kind: str, body: dict) -> str:
    issuer = did_key(key.verify_key)
    kid = f"{issuer}#{issuer.split(':')[-1]}"
    header = _encode_object({"alg": "Ed25519", "kid": kid, "typ": kind})
    message = f"{header}.{_encode_object(body)}"
    signature = key.sign(message.encode("ascii")).signature
    token = f"{message}.{_encode_segment(signature)}"
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("invalid_token_encoding")
    return token


def verify_token(token: str, kind: str) -> tuple[str, dict]:
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("invalid_token_encoding")
    try:
        header_segment, body_segment, signature_segment = token.split(".")
        header = _decode_object(header_segment)
        if set(header) != {"alg", "kid", "typ"} or header["alg"] != "Ed25519" or header["typ"] != kind:
            raise ValueError("invalid_token_header")
        if not isinstance(header["kid"], str):
            raise ValueError("invalid_token_key")
        issuer, _, fragment = header["kid"].partition("#")
        if fragment != issuer.split(":")[-1]:
            raise ValueError("invalid_token_key")
        key = resolve_did_key(issuer)
        signature = _decode_segment(signature_segment)
        if len(signature) != 64:
            raise ValueError("invalid_token_encoding")
        key.verify(f"{header_segment}.{body_segment}".encode("ascii"), signature)
        return issuer, _decode_object(body_segment)
    except BadSignatureError:
        raise ValueError("invalid_token_signature") from None
    except (ValueError, RecursionError):
        raise ValueError("invalid_token_format") from None
