"""Strict model adapters; importing this module does not import torch or load weights."""
import copy
import hashlib
import json
import math
from pathlib import Path
import re

from week5.guards import Finding, GuardResult


def read_protocol():
    path = Path(__file__).with_name("model_protocol.json")
    protocol = json.loads(path.read_text(encoding="utf-8"))
    return protocol, hashlib.sha256(path.read_bytes()).hexdigest()


def verify_snapshot(manifest_path, model_id, required, revision=None):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("model_id") != model_id or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("revision", "")):
        raise ValueError("unexpected model identity/revision")
    if revision is not None and manifest["revision"] != revision:
        raise ValueError("model revision differs from the frozen protocol")
    files = manifest.get("files", {})
    if not set(required).issubset(files):
        raise ValueError("incomplete local snapshot")
    snapshot = Path(manifest["snapshot_path"]).resolve()
    for name, info in files.items():
        path = (snapshot / name).resolve()
        if snapshot not in path.parents or not path.is_file():
            raise ValueError("snapshot path escapes its root or is missing")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if path.stat().st_size != info["bytes"] or digest.hexdigest() != info["sha256"]:
            raise ValueError("snapshot checksum mismatch: " + name)
    return snapshot, manifest


class LayaGuard:
    kind = "model"

    def __init__(self, agent, identity, protocol):
        self.agent = agent
        self.name = "laya:" + identity
        self.protocol = copy.deepcopy(protocol)
        self.calls = 0
        self.last_scores = None

    def check(self, request):
        if request.direction != "input":
            raise ValueError("Laya benchmark adapter only supports input")
        text = request.text + ("\n" + request.context if request.context else "")
        result = self.agent.predict({"prompt": text}, copy.deepcopy(self.protocol["laya"]["questions"]),
                                    max_len=self.protocol["laya"]["max_len"],
                                    head_max_len=self.protocol["laya"]["head_max_len"], min_confidence=None)
        usage = result.get("usage", {})
        if usage.get("truncated") is not False:
            raise ValueError("Laya input truncation or missing truncation evidence")
        answers = result.get("answers", {})
        labels = set(self.protocol["laya"]["questions"])
        if set(answers) != labels:
            raise ValueError("incomplete Laya answers")
        scores = {}
        for label in sorted(labels):
            answer = answers[label]
            score = answer.get("noul")
            if answer.get("type") != "noul" or isinstance(score, bool) or not isinstance(score, (int, float)):
                raise ValueError("malformed Laya probability")
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("invalid Laya probability")
            if answer.get("abstention") is True:
                raise ValueError("Laya abstained")
            scores[label] = float(score)
        self.calls += 1
        self.last_scores = scores
        hits = tuple(Finding(k, v) for k, v in scores.items() if v >= self.protocol["threshold"])
        return GuardResult("block" if hits else "allow", self.name, self.kind, hits)


def parse_llama_verdict(text):
    if not isinstance(text, str):
        raise ValueError("Llama Guard returned non-text output")
    lines = [s.strip() for s in text.strip().splitlines() if s.strip()]
    if lines == ["safe"]:
        return "allow", ()
    if not lines or lines[0] != "unsafe" or len(lines) != 2:
        raise ValueError("unrecognized Llama Guard verdict")
    labels = [s.strip() for s in lines[1].split(",")]
    if len(labels) != len(set(labels)) or not all(re.fullmatch(r"S(?:[1-9]|1[0-4])", label) for label in labels):
        raise ValueError("invalid Llama Guard safety categories")
    return "block", tuple(Finding(label) for label in labels)


class LlamaGuard4:
    kind = "model"

    def __init__(self, classify_text, identity):
        self.classify_text = classify_text
        self.name = "llama-guard4:" + identity

    def check(self, request):
        if request.direction != "input":
            raise ValueError("Llama benchmark adapter only supports input")
        verdict, findings = parse_llama_verdict(self.classify_text(request.text))
        return GuardResult(verdict, self.name, self.kind, findings)


def llama_memory_preflight(total_memory_bytes, protocol):
    if type(total_memory_bytes) is not int or total_memory_bytes <= 0:
        raise ValueError("physical memory must be a positive byte count")
    params = protocol["llama_guard4"]["memory_preflight_parameters"]
    # Current protocol requires CPU float32 for every backend, not BF16/GPU offloading.
    weight_bytes = params * 4
    required = math.ceil(weight_bytes * protocol["llama_guard4"]["memory_overhead_factor"])
    return {"model": "Llama Guard 4 12B", "status": "memory_sufficient_access_unverified" if total_memory_bytes >= required else "not_run_memory_limit",
            "physical_memory_bytes": total_memory_bytes, "estimated_weight_bytes_float32": weight_bytes,
            "required_memory_bytes_estimate": required, "device": "cpu", "dtype": "torch.float32",
            "f1": None, "latency_ms": None, "model_inference_executed": False,
            "gated_access": "not_checked_no_terms_accepted", "quantization": "none"}
