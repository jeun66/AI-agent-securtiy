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
        command = [self._executable, "eval", "--fail", "--strict-builtin-errors", "--format=raw",
                   "--stdin-input", "--data", str(self._policy_path), "data.agent.authz.decision"]
        try:
            completed = subprocess.run(command, input=json.dumps(data).encode("ascii"), capture_output=True,
                                       check=True, timeout=self._timeout)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("policy_unavailable") from None
        try:
            decision = json.loads(completed.stdout)
        except (ValueError, RecursionError):
            raise ValueError("invalid_policy_decision") from None
        if not isinstance(decision, dict) or set(decision) != {"allow", "requires_approval"}:
            raise ValueError("invalid_policy_decision")
        allow, requires_approval = decision["allow"], decision["requires_approval"]
        if type(allow) is not bool or type(requires_approval) is not bool or (requires_approval and not allow):
            raise ValueError("invalid_policy_decision")
        return PolicyDecision(allow, requires_approval)
