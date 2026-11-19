# Week 8 — W7 integration and adaptive attack (steps 1–3)

**Base commit:** `5e2ed4372b454940393373cf6b8b2233e79487f6` on
`jeun66/AI-agent-securtiy`. This is a **pre-patch** experiment: do not edit
`week4/taint.py` before collecting the before-run. Actual OpenTimestamps,
layer ablation and ML model benchmarking are **steps 4–8, not completed here**.

## Stage 1. Freeze the baseline

Run at the existing repository root, with your Python environment active:

```bash
python -m pip install -r week7/requirements.txt pytest PyYAML
# Use the already installed OPA; previously recorded version 1.22.3.
opa version
OPA_BIN=opa python -B -m week8.baseline --output-dir /tmp/w8-baseline-before
```

This runs the original `week7` pytest suite and `week7.run_eval`, then saves
`manifest.json`, `pytest.log`, `w7/report.json`, `w7/report.md`, `w7/audit.jsonl`,
`w7/checkpoint.json`, and signer DID. The manifest SHA-256-pins W4/W5/W7 code,
fixed evaluation data and existing model protocol; it records CPU/OS, Python,
package versions and git HEAD. The historical `week7/RESULTS.md` must **not**
be represented as a fresh run. Model inference is **not** executed here.

Fixed plan: `eval_config.json` uses seed `20261119`, 50 proposals per original
attack task, 3 baseline repeats, two normal requests and real tool effects as
success evidence. Record the exact OPA version used; do not substitute a mock
policy for measured baseline or adaptive results.

## Stage 2. Integrated call path

`week8.pipeline.Pipeline` reuses **the original W7 Gateway** for identity DID,
VC/delegation, command hash chain, OPA and single-use approval. It adds the
W4 `Tainted` provenance check and W5 `DefenseHook`/`RuleGuard` input-output
checks **before release**. Modes are `none`, `policy_only`, `w7_full`,
`w7_plus_taint`, `w7_plus_taint_guard`. The outputs include a per-layer
`allow/block/not_reached/disabled` trace and actual `tool_invoked` bit.
For W7-internal stages, the intermediate labels are reconstructed from the
verified Gateway path and final reason; they are not independent timing probes.
The provenance and W5 guard verdicts are captured at execution time.

`none` and `policy_only` are intentionally insecure controls but still use
`LocalFileRuntime` and a disposable sandbox. `w7_plus_taint_guard` uses the
W5 **rule** guard, **not GLiClass inference**. For high-risk writes the actual
user-approved command is exactly bound to the short-lived approval token.

Output filtering occurs after execution and can withhold the result, **not**
undo a read or a write. The W7 signed audit records whether the underlying
tool executed; the W8 pipeline separately records whether its output was
released. The pipeline never includes raw tokens, prompts or file content in
its exported JSON trace.

```bash
python -B -m pytest -q -p no:cacheprovider week8/test_pipeline.py
```


Adaptive attack runner is added in the next patch.
