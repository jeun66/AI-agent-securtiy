import pytest
from week8.patch_compare import compare


def example(phase, success):
    tasks = [{"task_id": "taint_split", "success": success, "attempts_used": 2,
              "trials": [{"goal_reached": False}, {"goal_reached": success}]}]
    return {"schema": "w8-adaptive-" + phase + "-v1", "baseline_commit": "x",
            "mode": "full", "seed": 1, "budget_per_original_task": 50,
            "tasks": tasks,
            "w7": {"original_tasks": 8, "asr": 0.0},
            "taint_provenance": {"original_tasks": 1, "asr": float(success)},
            "utility": 1.0, "fpr": 0.0, "latency": {}}


def test_pair_uses_original_denominator():
    result = compare(example("before", True), example("after", False))
    assert result["taint_provenance"]["n"] == 1
    assert result["taint_provenance"]["delta"] == -1.0


def test_rejects_mismatched_experiment():
    before, after = example("before", True), example("after", False)
    after["seed"] = 2
    with pytest.raises(ValueError, match="incomparable_seed"):
        compare(before, after)


def test_rejects_unobserved_success():
    before, after = example("before", True), example("after", False)
    before["tasks"][0]["trials"][-1]["goal_reached"] = False
    with pytest.raises(ValueError, match="unsupported_attack_success"):
        compare(before, after)
