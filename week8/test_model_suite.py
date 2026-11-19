"""Fixtures verify comparison rules only; they are NOT model inference evidence."""
import copy
import pytest
from week8.model_suite import comparison, markdown


def actual(role="gliclass-trained"):
    versions = {"gliclass-trained": "study_head_finetuned", "laya": "multilingual_322m_typed_questions",
                "llama-guard4": "vanilla_content_safety", "gliclass-base": "zero_shot"}
    return {
        "backend": {"kind": "model", "execution": {
            "variant": versions[role], "model_revision": "a" * 40, "device": "cpu",
            "dtype": "torch.float32", "threads": 2, "interop_threads": 1,
            "quantization": "none"}},
        "evidence": {"model_inference_executed": True},
        "summary": {"measurement_valid": True, "eligible_for_model_comparison": True,
                    "coverage": 1, "error_cases": 0, "unstable_cases": 0, "warmup_error_count": 0},
        "protocol_sha256": "protocol", "data": {"data_sha256": "data", "rows": 2},
        "metrics": {"n": 2, "accuracy": 0.5, "f1": 0.5, "fpr": 0.5},
        "latency": {"successful_attempts": {"count": 6, "p50_ms": 1., "p95_ms": 2.}},
        "config": {"repeats": 3, "warmup_suites": 1, "batch_size": 1,
                   "order": "fixed", "metric_unit": "one_unique_row"},
        "runtime": {"python": "3.12", "machine": "arm64", "system": "Darwin"},
        "packages": {"torch": "example"}, "forward_passes": 8,
    }


def test_missing_llama_is_null_not_zero():
    result = comparison({"gliclass-trained": actual(), "laya": actual("laya")},
                        protocol_sha="protocol", data_sha="data", expected_n=2)
    assert result["three_model_comparison_complete"] is False
    llama = next(r for r in result["rows"] if r["role"] == "llama-guard4")
    assert llama["status"] == "not_run" and llama["f1"] is None
    assert "—" in markdown(result)


def test_full_model_completion_requires_verified_forward_passes():
    result = comparison({"gliclass-trained": actual(), "laya": actual("laya"),
                         "llama-guard4": actual("llama-guard4")},
                        protocol_sha="protocol", data_sha="data", expected_n=2)
    assert result["three_model_comparison_complete"]
    altered = actual("laya")
    altered["forward_passes"] = 0
    with pytest.raises(ValueError, match="missing_observed_measurements"):
        comparison({"laya": altered}, protocol_sha="protocol", data_sha="data", expected_n=2)


def test_bad_runtime_or_mock_is_rejected():
    laya = actual("laya")
    laya["backend"]["execution"]["device"] = "cuda"
    with pytest.raises(ValueError, match="mismatched_model_runtime"):
        comparison({"gliclass-trained": actual(), "laya": laya},
                   protocol_sha="protocol", data_sha="data", expected_n=2)
    fake = actual()
    fake["backend"]["kind"] = "mock"
    with pytest.raises(ValueError, match="model_report_invalid_or_incomplete"):
        comparison({"gliclass-trained": fake}, protocol_sha="protocol", data_sha="data", expected_n=2)


def test_memory_preflight_is_not_actual_inference():
    preflight = {"status": "not_run_memory_limit", "model_inference_executed": False,
                 "f1": None, "latency_ms": None, "protocol_sha256": "protocol", "data_sha256": "data"}
    out = comparison({}, protocol_sha="protocol", data_sha="data", expected_n=2,
                     preflight=preflight)
    assert not out["three_model_comparison_complete"]
    assert out["rows"][-1]["status"] == "not_run_memory_limit"
    preflight["f1"] = 0.2
    with pytest.raises(ValueError, match="invalid_llama_preflight"):
        comparison({}, protocol_sha="protocol", data_sha="data", expected_n=2,
                   preflight=preflight)