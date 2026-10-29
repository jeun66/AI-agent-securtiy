"""Explicitly download the pinned public snapshot; never download Python model code."""
import argparse
import hashlib
import json
from pathlib import Path

MODEL_ID = "knowledgator/gliclass-small-v1.0"
REVISION = "21edefaf7951f68c68c505f9139ba536d3b448f7"
FILES = {"added_tokens.json", "config.json", "model.safetensors", "special_tokens_map.json",
         "spm.model", "tokenizer.json", "tokenizer_config.json"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    from huggingface_hub import HfApi, snapshot_download
    info = HfApi().model_info(MODEL_ID, revision=REVISION, token=False, files_metadata=True)
    available = {entry.rfilename: entry.size for entry in info.siblings}
    if info.sha != REVISION or not FILES.issubset(available):
        raise ValueError("unexpected snapshot identity or missing files")
    root = args.destination.resolve()
    snapshot = Path(snapshot_download(MODEL_ID, revision=REVISION, allow_patterns=sorted(FILES),
                                     local_dir=root / "model" / REVISION, token=False, max_workers=2))
    files = {}
    for name in sorted(FILES):
        path = snapshot / name
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        files[name] = {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}
    manifest = root / "model-manifest.json"
    manifest.write_text(json.dumps({"model_id": MODEL_ID, "revision": REVISION,
                                    "snapshot_path": str(snapshot), "files": files}, indent=2) + "\n")
    print("MODEL_MANIFEST=" + str(manifest))
    print("MODEL_DOWNLOAD=true MODEL_INFERENCE=false")


if __name__ == "__main__":
    main()
