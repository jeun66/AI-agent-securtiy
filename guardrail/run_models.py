"""Offline CPU model runner. Never downloads weights or substitutes mock results."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from guardrail.benchmark import evaluate_file, save_report
from guardrail.model_backends import (LayaGuard, LlamaGuard4, llama_memory_preflight,
                                     read_protocol, verify_snapshot)
from guardrail.validate_data import audit_files, load_jsonl
from week5.model_adapters import GLiClassGuard


class InferenceGuard:
    def __init__(self, guard, torch):
        self.guard, self.torch = guard, torch
        self.kind, self.name = guard.kind, guard.name

    def check(self, request):
        with self.torch.inference_mode():
            return self.guard.check(request)


def packages():
    names = ("torch", "transformers", "gliclass", "laya", "numpy", "safetensors", "huggingface-hub")
    result = {}
    for name in names:
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = None
    return result


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def verify_trained(path, manifest_path, data_manifest):
    from week5.evaluate_study import verify_study_checkpoint
    path, report = verify_study_checkpoint(path)
    base = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    provenance = json.loads(Path(data_manifest).read_text(encoding="utf-8"))
    previous = [r for r in provenance["provenance_inputs"] if r["origin"] == "local_history/week5/fixtures/study_classification.jsonl"]
    if (len(previous) != 1 or report["data_sha256"] != previous[0]["file_sha256"] or
            report["base_model"] != base["model_id"] or report["base_revision"] != base["revision"]):
        raise ValueError("trained checkpoint origin is not covered by the excluded training data")
    return path, report


@contextmanager
def load_backend(name, model_manifest, trained_checkpoint, data_manifest, rows, protocol):
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    os.environ["USE_TF"] = "0"
    started = time.perf_counter()
    import torch
    details = {}
    temporary = None
    if name in ("gliclass-base", "gliclass-trained"):
        from week5.run_zero_shot import AuditedPipeline, load_local_model, verify_manifest
        snapshot, manifest = verify_manifest(model_manifest)
        revision = manifest["revision"]
        variant = "zero_shot"
        if name == "gliclass-trained":
            snapshot, training = verify_trained(trained_checkpoint, model_manifest, data_manifest)
            revision = training["trained_weight_sha256"]
            variant = "study_head_finetuned"
            details["previous_training"] = {"data_sha256": training["data_sha256"],
                                             "optimizer_steps": training["optimizer_steps"],
                                             "encoder_frozen": training["config"]["encoder_frozen"]}
        pipeline, model_info = load_local_model(snapshot, protocol["threads"])
        model = pipeline.pipe.model
        lengths = [len(pipeline.pipe.tokenizer(
            pipeline.pipe.prepare_input(r["text"] + "\n", protocol["labels"]), truncation=False)["input_ids"]) for r in rows]
        if max(lengths) > pipeline.pipe.max_length:
            raise ValueError("GLiClass input would be truncated")
        audited = AuditedPipeline(pipeline)
        guard = GLiClassGuard(audited, threshold=protocol["threshold"],
                              model_id=manifest["model_id"] + "@" + revision + ":" + variant)
        details.update(checkpoint_loading=model_info["checkpoint_loading"],
                       checkpoint_parameter_prefixes_matched=model_info["checkpoint_parameter_prefixes_matched"],
                       maximum_input_tokens=max(lengths), truncation_detected=False,
                       weight_sha256=digest(snapshot / "model.safetensors"))
        execution = dict(model_id=manifest["model_id"], model_revision=revision, variant=variant,
                         decision_policy="multi-label; any non-benign score >= 0.5; labels fixed in model_protocol.json")
    elif name == "laya":
        if importlib.metadata.version("laya") != protocol["laya"]["package_version"]:
            raise ValueError("Laya package version differs from the frozen protocol")
        import laya
        spec = protocol["laya"]
        snapshot, manifest = verify_snapshot(model_manifest, spec["model_id"],
            ("model.safetensors", "rl_agent_config.json", "encoder/config.json", "tokenizer/tokenizer.json", "tokenizer/tokenizer_config.json"), spec["revision"])
        if manifest.get("subfolder") != "multilingual":
            raise ValueError("Laya must use the multilingual checkpoint")
        torch.set_num_threads(protocol["threads"])
        torch.set_num_interop_threads(protocol["interop_threads"])
        torch.manual_seed(0)
        # SDK may normalize tokenizer config. Copy metadata so pinned sources stay intact.
        temporary = tempfile.TemporaryDirectory(prefix="r3-laya-runtime-")
        runtime = Path(temporary.name)
        for relative in manifest["files"]:
            target = runtime / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == "model.safetensors":
                target.symlink_to(snapshot / relative)
            else:
                shutil.copy2(snapshot / relative, target)
        try:
            agent = laya.load(str(runtime), device="cpu", backend="eager", compile=False, fast=False)
        except Exception:
            temporary.cleanup()
            raise
        agent.amp_enabled = False
        agent.dtype = torch.float32
        agent.model.float().eval()
        model = agent.model
        guard = LayaGuard(agent, manifest["model_id"] + "@" + manifest["revision"] + "/multilingual", protocol)
        execution = dict(model_id=manifest["model_id"], model_revision=manifest["revision"],
                         variant="multilingual_322m_typed_questions", decision_policy=spec["question_policy"])
        details.update(weight_sha256=manifest["files"]["model.safetensors"]["sha256"],
                       original_tokenizer_config_sha256=manifest["files"]["tokenizer/tokenizer_config.json"]["sha256"],
                       runtime_tokenizer_config_sha256=digest(runtime / "tokenizer/tokenizer_config.json"),
                       truncation_policy="usage.truncated must be false on every call",
                       question_count=len(spec["questions"]), automatic_language_routing=False, backend="eager")
    else:
        # Full CPU float32 loading is intentionally separate from a failed preflight.
        from transformers import AutoProcessor, Llama4ForConditionalGeneration
        spec = protocol["llama_guard4"]
        snapshot, manifest = verify_snapshot(model_manifest, spec["model_id"], ("config.json", "tokenizer_config.json"))
        torch.set_num_threads(protocol["threads"])
        torch.set_num_interop_threads(protocol["interop_threads"])
        processor = AutoProcessor.from_pretrained(str(snapshot), local_files_only=True, trust_remote_code=False)
        model, loading = Llama4ForConditionalGeneration.from_pretrained(
            str(snapshot), local_files_only=True, trust_remote_code=False,
            dtype=torch.float32, output_loading_info=True)
        if any(loading.get(k) for k in ("missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs")):
            raise ValueError("Llama Guard checkpoint did not load exactly")
        model.to("cpu").eval()
        def classify(text):
            inputs = processor.apply_chat_template(
                [{"role": "user", "content": [{"type": "text", "text": text}]}],
                add_generation_prompt=True, tokenize=True, return_dict=True, return_tensors="pt")
            outputs = model.generate(**inputs, max_new_tokens=spec["max_new_tokens"], do_sample=False)
            return processor.batch_decode(outputs[:, inputs["input_ids"].shape[-1]:], skip_special_tokens=True)[0]
        guard = LlamaGuard4(classify, manifest["model_id"] + "@" + manifest["revision"])
        execution = dict(model_id=manifest["model_id"], model_revision=manifest["revision"],
                         variant="vanilla_content_safety", decision_policy=spec["policy"])
        details["checkpoint_loading"] = loading
    actual_device = str(next(model.parameters()).device)
    actual_dtype = str(next(model.parameters()).dtype)
    if actual_device != protocol["device"] or actual_dtype != protocol["dtype"]:
        if temporary:
            temporary.cleanup()
        raise ValueError("actual model device/dtype differs from the protocol")
    execution.update(device=actual_device, dtype=actual_dtype, threads=torch.get_num_threads(),
                     interop_threads=torch.get_num_interop_threads(), quantization="none",
                     parameter_count=sum(p.numel() for p in model.parameters()),
                     model_loading_ms_including_verification=(time.perf_counter() - started) * 1000)
    counter = {"forward_passes": 0}
    def counted(module, args, output):
        counter["forward_passes"] += 1
    hook = model.register_forward_hook(counted)
    try:
        yield InferenceGuard(guard, torch), execution, details, counter
    finally:
        hook.remove()
        if temporary:
            temporary.cleanup()


def physical_memory():
    return int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], text=True).strip())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument("--backend", choices=("gliclass-base", "gliclass-trained", "laya", "llama-guard4"), required=True)
    parser.add_argument("--model-manifest", type=Path)
    parser.add_argument("--trained-checkpoint", type=Path)
    parser.add_argument("--data", type=Path, default=root / "eval.jsonl")
    parser.add_argument("--manifest", type=Path, default=root / "data_manifest.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    package = root.resolve()
    if args.output.suffix != ".json" or any(package == p or package in p.parents for p in
            (args.output.resolve(), args.output.with_suffix(".csv").resolve())):
        parser.error("write .json reports outside guardrail/")
    protected = [args.data, args.manifest, args.model_manifest]
    if any(p and args.output.resolve() == p.resolve() for p in protected):
        parser.error("do not overwrite input manifests/data")
    protocol, protocol_sha = read_protocol()
    audit_files(args.data, args.manifest, "benchmark")
    if args.backend == "llama-guard4":
        preflight = llama_memory_preflight(physical_memory(), protocol)
        if preflight["status"] == "not_run_memory_limit":
            preflight.update(protocol_sha256=protocol_sha, data_sha256=digest(args.data))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(preflight, indent=2) + "\n", encoding="utf-8")
            print("MODEL_INFERENCE=false STATUS=not_run_memory_limit")
            print(json.dumps(preflight, sort_keys=True))
            return 3
    if args.model_manifest is None or (args.backend == "gliclass-trained" and args.trained_checkpoint is None):
        parser.error("local model manifest (and trained checkpoint for trained variant) required")
    rows = load_jsonl(args.data)
    with load_backend(args.backend, args.model_manifest, args.trained_checkpoint, args.manifest, rows, protocol) as loaded:
        guard, execution, details, counter = loaded
        report = evaluate_file(guard, args.data, args.manifest, execution=execution,
                               repeats=protocol["repeats"], warmup=protocol["warmup_suites"])
        report["model_verification"] = details
        report["protocol_sha256"] = protocol_sha
        report["packages"] = packages()
        report["forward_passes"] = counter["forward_passes"]
        expected = len(rows) * (protocol["repeats"] + protocol["warmup_suites"])
        if args.backend != "llama-guard4" and counter["forward_passes"] != expected:
            report["summary"]["eligible_for_model_comparison"] = False
            report["summary"]["measurement_valid"] = False
            report["metrics"] = None
            report["forward_count_error"] = {"expected": expected, "observed": counter["forward_passes"]}
        report["latency"]["model_loading_ms"] = execution["model_loading_ms_including_verification"]
        for name in ("run_models.py", "model_backends.py", "model_protocol.json"):
            report["runtime"]["source_files_sha256"]["guardrail/" + name] = digest(root / name)
        save_report(report, args.output)
    print("MODEL_INFERENCE=true BACKEND=" + args.backend)
    print("METRICS=" + json.dumps(report["metrics"], sort_keys=True))
    print("LATENCY=" + json.dumps(report["latency"]["successful_attempts"], sort_keys=True))
    print("FORWARD_PASSES=" + str(report["forward_passes"]))
    print("REPORT=" + str(args.output))
    return 0 if report["summary"]["measurement_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
