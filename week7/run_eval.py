"""Compare three defenses on the same scripted local attack and utility cases."""

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from week7.approval import issue_approval
from week7.attack_cases import APPROVED_CONTENT, BLOCKED_NOTE, ORIGINAL_NOTE, SCENARIOS, prepare_trial
from week7.audit import SignedAuditLog, verify_audit
from week7.eval_report import MODES, Attempt, markdown, summarize
from week7.gateway import Gateway, GatewayResult
from week7.identity import generate_identity
from week7.opa import DEFAULT_POLICY, OpaPolicy
from week7.run_audit_demo import check_audit_mutations
from week7.runtime import LocalFileRuntime
from week7.scope import Grant


def _invoke(gateway, trial, invocation, approval=None):
    challenge = gateway.issue_challenge(trial.actor, invocation)
    signature = trial.actor_key.sign(challenge.signing_bytes()).signature
    return gateway.invoke(invocation, challenge.nonce, signature, approval=approval)


def _unverified_call(mode, command, policy, runtime):
    if mode == "policy_only":
        try:
            decision = policy.evaluate_tool(command.grant)
        except ValueError as exc:
            return GatewayResult("DENY", str(exc))
        if not decision.allow:
            return GatewayResult("DENY", "policy_denied")
        if decision.requires_approval:
            return GatewayResult("REQUIRE_APPROVAL", "approval_required")
    try:
        output = runtime.run(command.grant, write_content=command.write_content)
    except (OSError, ValueError):
        return GatewayResult("ERROR", "runtime_error", tool_invoked=True)
    return GatewayResult("ALLOW", "allowed", tool_invoked=True, output=output)


def _observe_files(paths):
    return {path: (path.stat().st_ino, path.read_bytes()) for path in paths}


def _run_attempt(case, mode, repeat, opa_executable, audit):
    trial = prepare_trial(case)
    with TemporaryDirectory(prefix="w7-eval-") as directory:
        base = Path(directory).resolve()
        sandbox = base / "sandbox"
        sandbox.mkdir()
        note, blocked, outside = sandbox / "note.txt", sandbox / "blocked.txt", base / "outside.txt"
        note.write_text(ORIGINAL_NOTE, encoding="utf-8")
        blocked.write_text(BLOCKED_NOTE, encoding="utf-8")
        outside.write_text("W7 outside sandbox\n", encoding="utf-8")
        runtime = LocalFileRuntime(sandbox)
        policy = OpaPolicy(base / "missing-opa" if case.id == "opa_unavailable" else opa_executable)
        gateway = Gateway(trial.verifier, policy, runtime, audit=audit) if mode == "full" else None
        token = None
        if gateway is not None and trial.review_invocation is not None:
            pending = _invoke(gateway, trial, trial.review_invocation)
            if pending.decision != "REQUIRE_APPROVAL" or pending.approval_request is None:
                raise ValueError(f"approval_setup_failed: {case.id}/{pending.reason}")
            token = issue_approval(trial.user_key, pending.approval_request)
            if case.id == "approval_replay":
                primed = _invoke(gateway, trial, trial.review_invocation, token)
                if not primed.tool_invoked or primed.decision != "ALLOW" or note.read_bytes() != APPROVED_CONTENT.encode("utf-8"):
                    raise ValueError(f"replay_setup_failed: {primed.reason}")
        elif case.id == "approval_replay":
            # Match the post-approval starting file without counting setup as an attempt.
            note.write_text(APPROVED_CONTENT, encoding="utf-8")

        paths = (note, blocked, outside)
        before = _observe_files(paths)
        command = trial.invocation.received
        started = perf_counter_ns()
        if case.id == "path_traversal":
            try:
                Grant("read_file", "../outside.txt")
            except ValueError:
                result = (gateway.invoke(None, "", b"") if gateway is not None
                          else GatewayResult("DENY", "invalid_resource"))
            else:
                raise ValueError("path_traversal_validator_failed")
        elif gateway is not None:
            result = _invoke(gateway, trial, trial.invocation, token)
        else:
            result = _unverified_call(mode, command, policy, runtime)
        elapsed_ms = (perf_counter_ns() - started) / 1_000_000

        after = _observe_files(paths)
        changed = {path for path in paths if before[path] != after[path]}
        target = sandbox / command.grant.resource
        if case.id == "path_traversal":
            target = outside
        if command.write_content is None:
            reached = result.output == before[target][1].decode("utf-8")
            side_effect = result.output is not None or bool(changed)
        else:
            reached = target in changed and after[target][1] == command.write_content.encode("utf-8")
            side_effect = bool(changed)
        return Attempt(mode, case.id, repeat, result.decision, result.reason, result.tool_invoked,
                       reached, side_effect, elapsed_ms, result.audit_call_id)


def run_evaluation(output_dir: Path, *, opa_executable: str, repeats: int) -> dict:
    if type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError("repeats must be between 1 and 100")
    version = subprocess.run([opa_executable, "version"], check=True, capture_output=True,
                             text=True, timeout=5).stdout.splitlines()[0]
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("output directory must be empty")
    log, checkpoint = output_dir / "audit.jsonl", output_dir / "checkpoint.json"
    signer, key = generate_identity()
    attempts = []
    with SignedAuditLog(log, key) as audit:
        for repeat in range(1, repeats + 1):
            offset = (repeat - 1) % len(MODES)
            order = MODES[offset:] + MODES[:offset]
            for case in SCENARIOS:
                for mode in order:
                    attempts.append(_run_attempt(case, mode, repeat, opa_executable, audit))
        audit.write_checkpoint(checkpoint)
    (output_dir / "audit-signer.did").write_text(signer + "\n", encoding="ascii")
    verified = verify_audit(log, signer=signer, checkpoint=checkpoint)
    mutations = check_audit_mutations(log, checkpoint, signer)
    report = {
        "environment": {"system": platform.system(), "machine": platform.machine(),
                        "os_version": platform.mac_ver()[0] or platform.release(),
                        "python": platform.python_version(), "opa": f"OPA {version.removeprefix('Version: ')}",
                        "policy_sha256": sha256(DEFAULT_POLICY.read_bytes()).hexdigest()},
        "repeats": repeats,
        "modes": summarize(attempts, repeats=repeats, audit_events=verified.events,
                           missing_executions=verified.missing_executions),
        "audit": {"records": len(verified.events), "missing_executions": len(verified.missing_executions),
                  "merkle_root": verified.merkle_root, "mutations": mutations},
        "attempts": [asdict(row) for row in attempts],
    }
    (output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "report.md").write_text(markdown(report), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opa", default=os.environ.get("OPA_BIN", "opa"))
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_evaluation(args.output_dir, opa_executable=args.opa, repeats=args.repeats)
    print(markdown(report), end="")
    print(f"evidence_dir={args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
