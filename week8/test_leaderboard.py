"""Score assembly is unit-tested with fabricated fixtures, not reported as runs."""
import pytest
from week8.leaderboard import _baseline_rows, _adaptive_row, _ablation_rows, aggregate
from week8.ablation import LAYERS, conditions


def test_empty_run_yields_only_null_scores():
    result = aggregate({})
    assert len(result["scores"]) == 3 + 2 + 15
    assert all(row["ASR"] is None and row["adaptive_ASR"] is None
               for row in result["scores"])
    assert not result["report_inputs_present"]


def test_denominators_are_not_mixed():
    cases = {"baseline": (10, 2), "policy_only": (6, 1), "full": (0, 2)}
    row = {mode: {"attack_cases": 11, "attack_successes": attack,
                  "asr": attack / 11, "normal_cases": 2, "normal_successes": normal,
                  "utility": normal / 2, "fpr": 1 - normal / 2,
                  "latency": {"p50_ms": 1.0, "p95_ms": 2.0}}
           for mode, (attack, normal) in cases.items()}
    w7 = _baseline_rows({"modes": row})
    assert all(x["attack_tasks"] == 11 for x in w7)
    adaptive = {"schema": "w8-adaptive-before-v1", "mode": "w7_plus_taint_guard",
                "w7": {"original_tasks": 8, "asr": 0.0},
                "tasks": [{"task_id": str(i), "success": False} for i in range(8)] +
                         [{"task_id": "taint_split", "success": True}],
                "utility": 1., "fpr": 0., "latency": {"p50_ms": 2., "p95_ms": 4.}}
    val = _adaptive_row(adaptive, "before")
    assert val["adaptive_ASR"] == 0 and val["attack_tasks"] == 8
    assert val["ASR"] is None


def test_ablation_matrix_checks_real_switches():
    configs = []
    for name, enabled, kind in conditions():
        configs.append({"config": name, "enabled_layers": list(enabled),
                        "condition_kind": kind, "w7_attack_cases": 12,
                        "w7_attack_successes": 0, "asr": 0.,
                        "normal_cases": 2, "normal_successes": 2,
                        "utility": 1., "fpr": 0., "latency": {"p50_ms": 1., "p95_ms": 3.}})
    report = {"schema": "w8-real-layer-ablation-v1", "configs": configs}
    assert len(_ablation_rows(report)) == 15
    configs[1]["enabled_layers"] = ["policy"]
    with pytest.raises(ValueError, match="mismatched_ablation_switches"):
        _ablation_rows(report)