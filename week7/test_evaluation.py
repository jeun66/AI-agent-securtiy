import os
import shutil

import pytest

from week7.run_eval import run_evaluation


def test_repeated_local_evaluation_counts_cases_and_checks_signed_trace(tmp_path):
    opa = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not opa:
        pytest.skip("install OPA or set OPA_BIN for CLI integration tests")
    report = run_evaluation(tmp_path / "evidence", opa_executable=opa, repeats=2)
    baseline, policy, full = (report["modes"][mode] for mode in ("baseline", "policy_only", "full"))
    assert [row["attack_cases"] for row in (baseline, policy, full)] == [11, 11, 11]
    assert [row["attack_successes"] for row in (baseline, policy, full)] == [10, 6, 0]
    assert [row["normal_successes"] for row in (baseline, policy, full)] == [2, 1, 2]
    assert full["trace_coverage"] == {"complete": 28, "total": 28}
    assert full["latency"]["count"] == 26
    assert full["cases"]["normal_read"]["latency"]["count"] == 2
    assert full["cases"]["approval_replay"]["reason"] == "approval_already_used"
    assert not full["cases"]["approval_replay"]["side_effect"]
    assert full["cases"]["opa_unavailable"]["reason"] == "policy_unavailable"
    assert report["audit"]["mutations"] == {
        "tampered": "audit_hash_mismatch", "truncated": "audit_checkpoint_mismatch",
    }
