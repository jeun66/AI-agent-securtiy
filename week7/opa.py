"""Call the local OPA CLI and require a complete authorization decision."""

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess

from week7.scope import Grant


DEFAULT_POLICY = Path(__file__).with_name("authz.rego")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allow: bool
    requires_approval: bool
    version: str | None = None


class OpaPolicy:
    def __init__(self, executable: str | Path = "opa", *, policy_path: Path = DEFAULT_POLICY,
                 timeout_seconds: float = 3):
        self._executable = str(executable)
        self._policy_path = policy_path
        self._timeout = timeout_seconds

    def evaluate(self, actor: str, grant: Grant) -> PolicyDecision:
        """Evaluate an invocation only after the Gateway verifies its security claims."""
        data = {
            "actor": actor, "action": grant.action, "resource": grant.resource,
            "authenticated": True, "delegation_valid": True, "command_integrity": True,
        }
        return self._query("data.agent.authz.decision", data)

    def evaluate_tool(self, grant: Grant) -> PolicyDecision:
        return self._query("data.agent.authz.policy_only_decision",
                           {"action": grant.action, "resource": grant.resource})

    def _query(self, query: str, data: dict) -> PolicyDecision:
        command = [self._executable, "eval", "--fail", "--strict-builtin-errors", "--format=raw",
                   "--stdin-input", "--data", str(self._policy_path), query]
        try:
            completed = subprocess.run(command, input=json.dumps(data).encode("ascii"), capture_output=True,
                                       check=True, timeout=self._timeout)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("policy_unavailable") from None
        try:
            decision = json.loads(completed.stdout)
        except (ValueError, RecursionError):
            raise ValueError("invalid_policy_decision") from None
        required = {"allow", "requires_approval"}
        if not isinstance(decision, dict) or set(decision) not in (required, required | {"policy_version"}):
            raise ValueError("invalid_policy_decision")
        allow, requires_approval = decision["allow"], decision["requires_approval"]
        if type(allow) is not bool or type(requires_approval) is not bool or (requires_approval and not allow):
            raise ValueError("invalid_policy_decision")
        version = decision.get("policy_version")
        if "policy_version" in decision and (not isinstance(version, str) or not version):
            raise ValueError("invalid_policy_decision")
        return PolicyDecision(allow, requires_approval, version)
