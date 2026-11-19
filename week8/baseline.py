"""Pin the untouched W7 sources and rerun the original unit/evaluation baseline.

Run at repository root: OPA_BIN=opa python -m week8.baseline --output-dir results/w8-baseline
No ML models or network tools are called.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from week7.run_eval import run_evaluation

ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path(__file__).with_name("eval_config.json")


def _git(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True,
                                       stderr=subprocess.DEVNULL, timeout=5).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def manifest():
    config_bytes = CONFIG.read_bytes()
    config = json.loads(config_bytes)
    files = {path: sha256((ROOT / path).read_bytes()).hexdigest()
             for path in config["pinned_files"]}
    packages = {}
    for package in ("pytest", "PyNaCl", "base58", "torch", "transformers", "laya", "gliclass"):
        try:
            packages[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            packages[package] = None
    return {
        "manifest_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_commit": config["baseline_commit"],
        "checked_out_commit": _git("rev-parse", "HEAD"),
        "working_tree_dirty": bool(_git("status", "--porcelain")),
        "config_sha256": sha256(config_bytes).hexdigest(),
        "pinned_file_sha256": files,
        "environment": {"python": sys.version.split()[0], "os": platform.platform(),
                        "machine": platform.machine(), "packages": packages},
        "config": config,
    }


def run(output_dir: Path, *, opa="opa", repeats=None, run_tests=True):
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata = manifest()
    manifest_file = output_dir / "manifest.json"
    manifest_file.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if run_tests:
        with (output_dir / "pytest.log").open("w", encoding="utf-8") as stream:
            test = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "week7"],
                                  cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                  env={**os.environ, "OPA_BIN": opa}, check=False)
        metadata["pytest_exit_code"] = test.returncode
        manifest_file.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if test.returncode:
            raise RuntimeError("W7 baseline pytest failed (see pytest.log)")
    report = run_evaluation(output_dir / "w7", opa_executable=opa,
                            repeats=repeats or metadata["config"]["baseline_repeats"])
    if report["modes"]["full"]["attack_successes"] != 0:
        raise RuntimeError("unexpected existing W7 attack success; inspect baseline report")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--opa", default=os.environ.get("OPA_BIN", "opa"))
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    report = run(args.output_dir, opa=args.opa, repeats=args.repeats,
                 run_tests=not args.skip_tests)
    print(json.dumps({"full_asr": report["modes"]["full"]["asr"],
                      "full_utility": report["modes"]["full"]["utility"],
                      "evidence_dir": str(args.output_dir)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
