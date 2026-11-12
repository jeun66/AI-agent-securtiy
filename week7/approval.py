"""Short-lived, single-use approval for one exact Gateway invocation."""

from collections.abc import Callable
from dataclasses import dataclass
import re
from threading import Lock
from time import time
from uuid import uuid4

from nacl.signing import SigningKey

from week7.commands import Command
from week7.identity import did_key
from week7.signed_tokens import sign_token, verify_token


APPROVAL_TYPE = "agent-approval+jwt"
MAX_APPROVAL_TTL_SECONDS = 120


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    request_hash: str
    actor: str
    approver: str
    gateway_instance: str
    command: Command

    def _claims(self) -> dict[str, str]:
        return {
            "request_hash": self.request_hash,
            "command_hash": self.command.digest(),
            "iss": self.approver,
            "sub": self.actor,
            "aud": self.command.audience,
            "gateway_instance": self.gateway_instance,
            "action": self.command.grant.action,
            "resource": self.command.grant.resource,
        }


def issue_approval(key: SigningKey, request: ApprovalRequest, *, issued_at: int | None = None,
                   ttl_seconds: int = MAX_APPROVAL_TTL_SECONDS) -> str:
    if did_key(key.verify_key) != request.approver:
        raise ValueError("approval_signer_mismatch")
    if type(ttl_seconds) is not int or not 0 < ttl_seconds <= MAX_APPROVAL_TTL_SECONDS:
        raise ValueError("invalid_approval_lifetime")
    start = int(time()) if issued_at is None else issued_at
    if type(start) is not int or start < 0:
        raise ValueError("invalid_approval_lifetime")
    body = {**request._claims(), "iat": start, "exp": start + ttl_seconds, "jti": uuid4().hex}
    return sign_token(key, APPROVAL_TYPE, body)


class ApprovalVerifier:
    def __init__(self, *, clock: Callable[[], float] = time):
        self._instance = uuid4().hex
        self._clock = clock
        self._used: set[tuple[str, str]] = set()
        self._lock = Lock()

    def request(self, request_hash: str, actor: str, approver: str, command: Command) -> ApprovalRequest:
        return ApprovalRequest(request_hash, actor, approver, self._instance, command)

    def consume(self, token: str, request: ApprovalRequest) -> None:
        try:
            signer, body = verify_token(token, APPROVAL_TYPE)
        except ValueError:
            raise ValueError("invalid_approval_token") from None
        if signer != request.approver:
            raise ValueError("approval_signer_mismatch")
        expected = request._claims()
        if set(body) != set(expected) | {"iat", "exp", "jti"}:
            raise ValueError("invalid_approval_token")
        if request.gateway_instance != self._instance or any(body[name] != value for name, value in expected.items()):
            raise ValueError("approval_request_mismatch")
        start, end, token_id = body["iat"], body["exp"], body["jti"]
        if type(start) is not int or type(end) is not int or start < 0 or not 0 < end - start <= MAX_APPROVAL_TTL_SECONDS:
            raise ValueError("invalid_approval_lifetime")
        if not isinstance(token_id, str) or not re.fullmatch(r"[0-9a-f]{32}", token_id):
            raise ValueError("invalid_approval_token")
        approval_id = (signer, token_id)
        with self._lock:
            if not start <= self._clock() < end:
                raise ValueError("approval_inactive")
            if approval_id in self._used:
                raise ValueError("approval_already_used")
            self._used.add(approval_id)
