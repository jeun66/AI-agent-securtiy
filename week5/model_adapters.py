"""Optional model adapters. Construct pipelines explicitly before injecting them.

No torch, GLiClass or GLiNER imports are required for the Python 3.9 core tests.
"""
from week5.guards import Finding, GuardResult


class GLiClassGuard:
    name = "gliclass"
    kind = "model"
    labels = ("benign", "prompt_injection", "jailbreak", "system_prompt_extraction")

    def __init__(self, pipeline, threshold=0.5, model_id="unspecified"):
        if not 0 < threshold <= 1:
            raise ValueError("threshold must be in (0, 1]")
        self.pipeline = pipeline
        self.threshold = threshold
        self.name = "gliclass:" + model_id

    def check(self, request):
        if request.direction != "input":
            raise ValueError("GLiClass adapter requires a separate output PII guard")
        text = request.text + "\n" + request.context
        rows = self.pipeline(text, list(self.labels), threshold=self.threshold)
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], list):
            raise ValueError("unexpected GLiClass output shape")
        hits = []
        for row in rows[0]:
            if row["label"] not in self.labels:
                raise ValueError("unknown GLiClass label")
            finding = Finding(row["label"], float(row["score"]))
            if finding.label != "benign" and finding.score >= self.threshold:
                hits.append(finding)
        return GuardResult("block" if hits else "allow", self.name, self.kind, tuple(hits))


class GLiNERGuard:
    name = "gliner"
    kind = "model"
    labels = ("person", "resident_id", "api_key", "email")

    def __init__(self, model, threshold=0.5, model_id="unspecified"):
        if not 0 < threshold <= 1:
            raise ValueError("threshold must be in (0, 1]")
        self.model = model
        self.threshold = threshold
        self.name = "gliner:" + model_id

    def check(self, request):
        if request.direction != "output":
            raise ValueError("GLiNER adapter only provides output span detection")
        rows = self.model.predict_entities(request.text, list(self.labels), threshold=self.threshold)
        if not isinstance(rows, list):
            raise ValueError("unexpected GLiNER output shape")
        hits = []
        for row in rows:
            if row["label"] not in self.labels:
                raise ValueError("unknown GLiNER label")
            finding = Finding(row["label"], float(row["score"]), row["start"], row["end"])
            if finding.end > len(request.text):
                raise ValueError("PII span exceeds output length")
            if finding.score >= self.threshold:
                hits.append(finding)
        return GuardResult("block" if hits else "allow", self.name, self.kind, tuple(hits))
