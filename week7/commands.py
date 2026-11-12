"""Bind the initial signed command to each hop on the verified delegation path."""

from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
from uuid import uuid4

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from week7.identity import did_key, resolve_did_key
from week7.scope import Grant


def encode_fields(fields: list) -> bytes:
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True, slots=True)
class Command:
    audience: str
    instruction: str
    grant: Grant
    command_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self):
        if not all(isinstance(value, str) and value for value in (self.audience, self.instruction, self.command_id)):
            raise ValueError("invalid_command")
        if not isinstance(self.grant, Grant):
            raise ValueError("invalid_command")

    def digest(self) -> str:
        fields = ["agent-trust/command/v1", self.command_id, self.audience,
                  self.instruction, self.grant.action, self.grant.resource]
        return sha256(encode_fields(fields)).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedCommand:
    command: Command
    author: str
    signature: bytes

    def __post_init__(self):
        if not isinstance(self.command, Command) or not isinstance(self.author, str) or not isinstance(self.signature, bytes):
            raise ValueError("invalid_command_anchor")

    def signing_bytes(self) -> bytes:
        return encode_fields(["agent-trust/command-origin/v1", self.author, self.command.digest()])

    def digest(self) -> str:
        return sha256(self.signing_bytes() + self.signature).hexdigest()


@dataclass(frozen=True, slots=True)
class CommandHop:
    sender: str
    recipient: str
    previous_digest: str
    command_digest: str
    signature: bytes

    def __post_init__(self):
        fields = (self.sender, self.recipient, self.previous_digest, self.command_digest)
        if not all(isinstance(value, str) for value in fields) or not isinstance(self.signature, bytes):
            raise ValueError("invalid_command_hop")

    def signing_bytes(self) -> bytes:
        return encode_fields(["agent-trust/command-hop/v1", self.sender, self.recipient,
                              self.previous_digest, self.command_digest])

    def digest(self) -> str:
        return sha256(self.signing_bytes() + self.signature).hexdigest()


def sign_command(key: SigningKey, command: Command) -> SignedCommand:
    anchor = SignedCommand(command, did_key(key.verify_key), b"")
    return replace(anchor, signature=key.sign(anchor.signing_bytes()).signature)


def forward_command(key: SigningKey, recipient: str, command: Command,
                    previous: SignedCommand | CommandHop) -> CommandHop:
    hop = CommandHop(did_key(key.verify_key), recipient, previous.digest(), command.digest(), b"")
    return replace(hop, signature=key.sign(hop.signing_bytes()).signature)


def _verify_signature(signer: str, message: bytes, signature: bytes) -> None:
    if len(signature) != 64:
        raise ValueError("command_signature_invalid")
    try:
        resolve_did_key(signer).verify(message, signature)
    except BadSignatureError:
        raise ValueError("command_signature_invalid") from None


def verify_command_chain(anchor: SignedCommand, hops: tuple[CommandHop, ...], received: Command,
                         *, path: tuple[str, ...], audience: str) -> None:
    command_digest = received.digest()
    if received.audience != audience or command_digest != anchor.command.digest():
        raise ValueError("command_changed")
    if not path or anchor.author != path[0] or len(hops) != len(path) - 1:
        raise ValueError("command_path_mismatch")
    _verify_signature(anchor.author, anchor.signing_bytes(), anchor.signature)
    previous_digest = anchor.digest()
    for hop, sender, recipient in zip(hops, path, path[1:]):
        if (hop.sender, hop.recipient) != (sender, recipient) or hop.previous_digest != previous_digest:
            raise ValueError("command_path_mismatch")
        if hop.command_digest != command_digest:
            raise ValueError("command_changed")
        _verify_signature(sender, hop.signing_bytes(), hop.signature)
        previous_digest = hop.digest()
