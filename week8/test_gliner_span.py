"""Span test double checks metric plumbing; no GLiNER weights are loaded."""
from week5.guards import GuardResult
from week5.span_study import build_span_rows
from week8.gliner_span import measure


class EmptySpanModelDouble:
    kind = "model"
    name = "synthetic-span-double"

    def check(self, request):
        return GuardResult("allow", self.name, self.kind)


def test_exact_spans_and_latency_are_separate_from_classifier_metrics():
    result = measure(EmptySpanModelDouble(), build_span_rows(), repeats=2, warmup=0)
    assert result["test_rows"] == 10
    assert result["latency"]["count"] == 20
    assert result["span_metrics"]["tp"] == 0
    assert result["span_metrics"]["fn"] == 8