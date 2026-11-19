# W8 stages 7–8 — real-model evaluation and evidence leaderboard

The W8 stages 1–6 implementations are in the same repository. **This commit
adds runnable code and unit-test fixtures, not measured W8 results.** All
benchmarks must be run on the actual pinned CPU/model environment. Do not label
a fake test guard as a model measurement or fill missing model cells with zero.

## Stage 7 — input-classification models

The existing `guardrail.run_models` executes real local inference with fixed
`guardrail/model_protocol.json`, frozen `guardrail/eval.jsonl` (24 texts),
verified weight manifests, CPU float32 and warmup/repeats. It writes per-model
JSON and CSV with actual forward passes and p50/p95. Model downloads and
training are **not** part of this step.

Run from repository root with the prepared Python 3.12 model environment,
local manifests and pinned checkpoints (replace the variables with paths
available on the measuring machine):

```bash
MODEL_PY=python
GLICLASS_MANIFEST=/path/to/pinned/gliclass-model-manifest.json
GLICLASS_HEAD=/path/to/pinned/trained-study
LAYA_MANIFEST=guardrail/manifests/laya-multilingual.local.json
mkdir -p /tmp/w8-models
"$MODEL_PY" -B -m guardrail.run_models --backend gliclass-base \
  --model-manifest "$GLICLASS_MANIFEST" --output /tmp/w8-models/gliclass-base.json
"$MODEL_PY" -B -m guardrail.run_models --backend gliclass-trained \
  --model-manifest "$GLICLASS_MANIFEST" --trained-checkpoint "$GLICLASS_HEAD" \
  --output /tmp/w8-models/gliclass-trained.json
"$MODEL_PY" -B -m guardrail.run_models --backend laya \
  --model-manifest "$LAYA_MANIFEST" --output /tmp/w8-models/laya.json
```

Llama Guard 4 requires local gated checkpoint access and sufficient physical
memory under the frozen **CPU float32, no-quantization** protocol. On the
previous 16GiB Mac the 12B model was correctly reported
`not_run_memory_limit` (expected exit status 3), with no fabricated F1/latency:

```bash
"$MODEL_PY" -B -m guardrail.run_models --backend llama-guard4 \
  --output /tmp/w8-models/llama-preflight.json
# With appropriate hardware/access: pass --model-manifest and write llama-guard4.json.
```

Compare only actual new-run reports (omit `--llama-guard4` unless real inference
completed):

```bash
"$MODEL_PY" -B -m week8.model_suite \
  --gliclass-base /tmp/w8-models/gliclass-base.json \
  --gliclass-trained /tmp/w8-models/gliclass-trained.json \
  --laya /tmp/w8-models/laya.json \
  --llama-preflight /tmp/w8-models/llama-preflight.json \
  --output-dir /tmp/w8-model-comparison
```

This produces `comparison.json` and `comparison.md`. The script verifies
model kind, actual inference flag, complete row/forward counts, frozen dataset
and protocol hashes, hardware, package and repeated-run comparability.
`three_model_comparison_complete` is false unless all three primary models
(GLiClass-trained, Laya, Llama Guard 4) have actual valid reports. The
zero-shot GLiClass is an additional baseline.

### Plug a real classifier into the integrated W7 pipeline

The following is **a separate local integration measurement**, not an
attack-success-rate experiment. Each model is loaded from the verified
snapshot with the same `guardrail.run_models.load_backend` method and injected
into W5 `DefenseHook` input checks. A W5 rule-based output guard handles the
PII output boundary; W7 still verifies identity, signed delegation, command,
OPA and an automatic **synthetic-test approval**. `model_pipeline` records
four probe outcomes and W7 signed audit events without raw prompts/tokens.

```bash
OPA_BIN=opa "$MODEL_PY" -B -m week8.model_pipeline --backend gliclass-trained \
  --model-manifest "$GLICLASS_MANIFEST" --trained-checkpoint "$GLICLASS_HEAD" \
  --output-dir /tmp/w8-pipeline-gliclass
OPA_BIN=opa "$MODEL_PY" -B -m week8.model_pipeline --backend laya \
  --model-manifest "$LAYA_MANIFEST" \
  --output-dir /tmp/w8-pipeline-laya
# Llama Guard: only after compatible hardware and local model manifest exist.
```

The cases are normal read, a deliberately signed unsafe instruction, approved
write, and a synthetic PII output. They are **not** counted as true
unauthorized W7 tool-action ASR. A guard `allow` does not imply a successful
unauthorized read/write. For genuine adaptive ASR use the stage-3/4 runner.

### Optional GLiNER output span evaluation

GLiNER is **not** compared to input-classification F1. The separate optional
runner requires a locally pinned SHA-256 manifest including model weights and
runs real CPU inference on the existing W5 synthetic **test-only** PII span
dataset, measuring exact character-span precision/recall/F1 and p50/p95:

```bash
"$MODEL_PY" -B -m week8.gliner_span \
  --model-manifest /path/to/pinned/gliner-manifest.json \
  --output-dir /tmp/w8-gliner-spans
```

Without a usable local GLiNER model, **leave the span result unmeasured**.

## Stage 8 — integrated leaderboard, files and evidence index

The leaderboard uses **three distinct attack scopes**, never merges their
denominators: W7 11 original cases, W8 adaptive 8 original W7 tasks, W8
ablation 12 cases (8 original plus 4 layer-isolation probes). The taint
laundering goal is separate from W7 ASR; model binary F1 from 24 fixed text
inputs is separate again. A legitimate model pipeline probe is not evidence
of unauthorised exploitation.

```bash
"$MODEL_PY" -B -m week8.leaderboard \
  --w7-baseline /tmp/w8-baseline-before/w7/report.json \
  --adaptive-before /tmp/w8-adapt-before/report.json \
  --adaptive-after /tmp/w8-adapt-after/report.json \
  --ablation /tmp/w8-ablation/report.json \
  --model-comparison /tmp/w8-model-comparison/comparison.json \
  --model-pipeline gliclass-trained=/tmp/w8-pipeline-gliclass/pipeline.json \
  --model-pipeline laya=/tmp/w8-pipeline-laya/pipeline.json \
  --output-dir /tmp/w8-final
```

To include GLiNER, append `--gliner-span /tmp/w8-gliner-spans/span-report.json`.
To include the signed external timestamp evidence append
`--anchor-evidence-dir /tmp/w8-adapt-after`. Add `--verify-anchor` only when
you want to contact the configured OpenTimestamps/Bitcoin verification CLI;
merely having `.ots` or a saved `verified` string is **not** newly verified
Bitcoin proof. `leaderboard` checks the signed W7 audit/checkpoint and report
hashes and emits:

- `leaderboard.json` and `leaderboard.md`: separated measured scores
- `evidence-index.json`: paths, SHA-256, signer DID and Merkle roots
- `CAPTURE_CHECKLIST.md`: reproducible evidence screenshots to collect

It also runs in partial mode when report paths are omitted, with all missing
measurements `null`; a partial table is **not** a completed gate.

## Local test commands (no weight downloads)

```bash
python -B -m pytest -q -p no:cacheprovider \
  week8/test_model_suite.py week8/test_model_pipeline.py \
  week8/test_gliner_span.py week8/test_leaderboard.py
```

These tests use synthetic doubles only for interface checks and never record
model performance evidence. For a full integration sign-off, run W7/W8 tests,
the actual model forward-pass suites, pre/post measurements, signed audit and
confirmed OTS validation on the user's prepared machine.