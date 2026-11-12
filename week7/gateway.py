"""Authenticate a tool call and enforce the Rego decision before dispatch."""

from dataclasses import dataclass
from hashlib import sha256

from week7.commands import Command, CommandHop, SignedCommand, encode_fields, verify_command_chain
from week7.delegation import DelegationVerifier, MAX_CHAIN_LENGTH
from week7.identity import Challenge, IdentityVerifier
from week7.opa import OpaPolicy
from week7.runtime import LocalFileRuntime


@dataclass(frozen=True, slots=True)
class Invocation:
    credential: str
    capabilities: tuple[str, ...]
    anchor: SignedCommand
    hops: tuple[CommandHop, ...]
    received: Command

    def __post_init__(self):
        if not isinstance(self.credential, str) or not isinstance(self.capabilities, tuple):
            raise ValueError("invalid_invocation")
        if not 1 <= len(self.capabilities) <= MAX_CHAIN_LENGTH or not all(isinstance(token, str) for token in self.capabilities):
            raise ValueError("invalid_invocation")
        if not isinstance(self.anchor, SignedCommand) or not isinstance(self.received, Command):
            raise ValueError("invalid_invocation")
        if not isinstance(self.hops, tuple) or len(self.hops) > MAX_CHAIN_LENGTH:
            raise ValueError("invalid_invocation")
        if not all(isinstance(hop, CommandHop) for hop in self.hops):
            raise ValueError("invalid_invocation")

    def binding(self) -> str:
        fields = ["agent-trust/invocation/v1", self.credential, self.capabilities,
                  self.anchor.digest(), [hop.digest() for hop in self.hops], self.received.digest()]
        return sha256(encode_fields(fields)).hexdigest()


@dataclass(frozen=True, slots=True)
class GatewayResult:
    decision: str
    reason: str
    tool_invoked: bool = False
    output: str | None = None


class Gateway:
    def __init__(self, delegation: DelegationVerifier, policy: OpaPolicy, runtime: LocalFileRuntime):
        self._delegation = delegation
        self._identity = IdentityVerifier(delegation.audience)
        self._policy = policy
        self._runtime = runtime

    def issue_challenge(self, actor_did: str, invocation: Invocation) -> Challenge:
        if not isinstance(invocation, Invocation):
            raise ValueError("invalid_invocation")
        return self._identity.issue(actor_did, binding=invocation.binding())

    def invoke(self, invocation: Invocation, nonce: str, signature: bytes) -> GatewayResult:
        if not isinstance(invocation, Invocation):
            return GatewayResult("DENY", "invalid_invocation")
        try:
            actor = self._identity.verify(nonce, signature, binding=invocation.binding())
            grant = invocation.received.grant
            with self._delegation.authorized(invocation.credential, invocation.capabilities,
                                             authenticated_did=actor, requested=grant) as verified:
                verify_command_chain(invocation.anchor, invocation.hops, invocation.received,
                                     path=verified.path, audience=self._delegation.audience)
                policy = self._policy.evaluate(actor, grant)
                if not policy.allow:
                    return GatewayResult("DENY", "policy_denied")
                if policy.requires_approval:
                    return GatewayResult("REQUIRE_APPROVAL", "approval_required")
                self._delegation.require_unexpired(verified)
                try:
                    output = self._runtime.run(grant)
                except (OSError, ValueError):
                    return GatewayResult("ERROR", "runtime_error", tool_invoked=True)
                return GatewayResult("ALLOW", "allowed", tool_invoked=True, output=output)
        except ValueError as exc:
            return GatewayResult("DENY", str(exc))
