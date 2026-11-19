"""Fast rule-policy unit checks; real OPA and measurements are deferred."""
from week8.ablation import LAYERS, ATTACKS, NORMALS, conditions, one_case, taint_probe
from week8.test_pipeline import FixedPolicy


def test_matrix_includes_cumulative_and_one_layer_off():
    rows = conditions()
    assert rows[0] == ("none", frozenset(), "cumulative")
    assert len(rows) == 1 + len(LAYERS) + len(LAYERS)
    assert sum(kind == "leave_one_out" for _, _, kind in rows) == 7
    assert all(set(enabled) <= set(LAYERS) for _, enabled, _ in rows)


def test_full_defense_rejects_adaptive_and_normal_passes():
    enabled = frozenset(LAYERS)
    for attack in ATTACKS:
        row = one_case(attack, enabled, FixedPolicy)
        assert not row["success"], (attack, row["reason"])
    for normal in NORMALS:
        assert one_case(normal, enabled, FixedPolicy)["success"]


def test_one_at_a_time_disabled_actually_changes_corresponding_boundary():
    full = frozenset(LAYERS)
    isolated = {
        "identity": "identity_spoof",
        "delegation": "parent_link",
        "command": "command_rewrite",
        "approval": "approval_swap",
        "policy": "policy_escape",
        "taint": "tainted_source",
        "guard": "guard_injection",
    }
    for layer, case in isolated.items():
        row = one_case(case, full - {layer}, FixedPolicy)
        assert row["success"], (layer, case, row["reason"])
        assert not one_case(case, full, FixedPolicy)["success"]


def test_provenance_mock_is_separate_and_untrusted():
    full = frozenset(LAYERS)
    assert not taint_probe(full)[0]
    assert taint_probe(full - {"taint"})[0]
