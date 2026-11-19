"""The injected model double is for offline testing, not an actual inference run."""
import pytest
from week5.guards import GuardResult
from week8.model_pipeline import integration_probes
from week8.test_pipeline import FixedPolicy


class SyntheticModelTestDouble:
    kind = "model"  # protocol test double; never persisted as model evidence
    name = "unit-test-model-double"

    def check(self, request):
        decision = "block" if "Ignore previous instructions" in request.text else "allow"
        return GuardResult(decision, self.name, self.kind)


def test_model_is_called_before_file_and_signed_audit_records_actions(tmp_path, monkeypatch):
    import week8.model_pipeline as mod
    monkeypatch.setattr(mod, "OpaPolicy", FixedPolicy)
    report = integration_probes(SyntheticModelTestDouble(), tmp_path / "record", opa="unit")
    cases = {r["case"]: r for r in report["probes"]}
    assert len(cases) == 4
    assert cases["normal_read"]["outcome"]["tool_invoked"]
    assert not cases["suspicious_signed_input"]["outcome"]["tool_invoked"]
    assert cases["approved_write"]["actual_file_replaced"]
    assert cases["output_pii_block"]["outcome"]["tool_invoked"]
    assert not cases["output_pii_block"]["outcome"]["output_released"]
    assert report["audit"]["records"] >= 7


def test_mock_guard_not_accepted_as_real(tmp_path):
    from week5.guards import MockGuard
    with pytest.raises(ValueError, match="real_model_guard_required"):
        integration_probes(MockGuard(), tmp_path / "none")