"""Authenticate a tool call and enforce the Rego decision before dispatch."""

from dataclasses import dataclass, field, replace
from hashlib import sha256
from uuid import uuid4

from week7.approval import ApprovalRequest, ApprovalVerifier
from week7.audit import AuditWriteError, SignedAuditLog
from week7.commands import Command, CommandHop, SignedCommand, encode_fields, verify_command_chain
from week7.delegation import DelegationVerifier, MAX_CHAIN_LENGTH, VerifiedDelegation
from week7.identity import Challenge, IdentityVerifier
from week7.opa import OpaPolicy
from week7.runtime import LocalFileRuntime
from week7.scope import Grant, encode_grants


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
    approval_request: ApprovalRequest | None = None
    audit_call_id: str | None = field(default=None, compare=False)


@dataclass(slots=True)
class _AuditContext:
    call_id: str = field(default_factory=lambda: uuid4().hex)
    request_hash: str | None = None
    actor_id: str | None = None
    grant: Grant | None = None
    policy_version: str | None = None
    delegation: VerifiedDelegation | None = None
    decision_recorded: bool = False


class Gateway:
    def __init__(self, delegation: DelegationVerifier, policy: OpaPolicy, runtime: LocalFileRuntime,
                 *, approvals: ApprovalVerifier | None = None, audit: SignedAuditLog | None = None):
        self._delegation = delegation
        self._identity = IdentityVerifier(delegation.audience)
        self._policy = policy
        self._runtime = runtime
        self._approvals = approvals if approvals is not None else ApprovalVerifier()
        self._audit = audit

    def _record(self, context: _AuditContext, phase: str, result: GatewayResult) -> None:
        if self._audit is None:
            return
        verified = context.delegation
        delegation = None if verified is None else {
            "path": list(verified.path),
            "grants": [encode_grants(grants) for grants in verified.delegated_grants],
        }
        self._audit.append({
            "call_id": context.call_id, "phase": phase, "actor_id": context.actor_id,
            "request_hash": context.request_hash, "action": context.grant.action if context.grant else None,
            "resource": context.grant.resource if context.grant else None,
            "policy_version": context.policy_version, "delegation": delegation,
            "decision": result.decision, "reason": result.reason, "tool_invoked": result.tool_invoked,
        })
        if phase == "decision":
            context.decision_recorded = True

    def issue_challenge(self, actor_did: str, invocation: Invocation) -> Challenge:
        if not isinstance(invocation, Invocation):
            raise ValueError("invalid_invocation")
        return self._identity.issue(actor_did, binding=invocation.binding())

    def invoke(self, invocation: Invocation, nonce: str, signature: bytes,
               *, approval: str | None = None) -> GatewayResult:
        context = _AuditContext()
        try:
            result = self._invoke(invocation, nonce, signature, approval, context)
            if self._audit is not None and not context.decision_recorded:
                self._record(context, "decision", result)
            return replace(result, audit_call_id=context.call_id) if self._audit is not None else result
        except AuditWriteError:
            return GatewayResult("ERROR", "audit_unavailable")

    def _invoke(self, invocation: Invocation, nonce: str, signature: bytes, approval: str | None,
                context: _AuditContext) -> GatewayResult:
        if not isinstance(invocation, Invocation):
            return GatewayResult("DENY", "invalid_invocation")
        try:
            binding = invocation.binding()
            command = invocation.received
            grant = command.grant
            context.request_hash, context.grant = binding, grant
            actor = self._identity.verify(nonce, signature, binding=binding)
            context.actor_id = actor
            with self._delegation.authorized(invocation.credential, invocation.capabilities,
                                             authenticated_did=actor, requested=grant) as verified:
                context.delegation = verified
                verify_command_chain(invocation.anchor, invocation.hops, invocation.received,
                                     path=verified.path, audience=self._delegation.audience)
                policy = self._policy.evaluate(actor, grant)
                context.policy_version = policy.version
                if not policy.allow:
                    return GatewayResult("DENY", "policy_denied")
                self._delegation.require_unexpired(verified)
                approval_expires_at = None
                if policy.requires_approval:
                    request = self._approvals.request(binding, actor, verified.path[0], command)
                    if approval is None:
                        return GatewayResult("REQUIRE_APPROVAL", "approval_required", approval_request=request)
                    approval_expires_at = self._approvals.consume(approval, request)
                elif command.write_content is not None:
                    return GatewayResult("DENY", "approval_policy_required")
                elif approval is not None:
                    return GatewayResult("DENY", "approval_not_applicable")

                return self._dispatch(command, context, verified, approval_expires_at)
        except ValueError as exc:
            return GatewayResult("DENY", str(exc))

    def _dispatch(self, command: Command, context: _AuditContext, verified: VerifiedDelegation,
                  approval_expires_at: int | None) -> GatewayResult:
        self._record(context, "decision", GatewayResult("ALLOW", "allowed"))
        try:
            self._delegation.require_unexpired(verified)
            if approval_expires_at is not None:
                self._approvals.require_unexpired(approval_expires_at)
        except ValueError as exc:
            result = GatewayResult("DENY", str(exc))
        else:
            try:
                if command.write_content is None:
                    output = self._runtime.run(command.grant)
                else:
                    output = self._runtime.run(command.grant, write_content=command.write_content)
            except (OSError, ValueError):
                result = GatewayResult("ERROR", "runtime_error", tool_invoked=True)
            else:
                result = GatewayResult("ALLOW", "allowed", tool_invoked=True, output=output)

        try:
            self._record(context, "execution", result)
        except AuditWriteError:
            return GatewayResult("ERROR", "audit_result_unavailable", tool_invoked=result.tool_invoked)
        return result
