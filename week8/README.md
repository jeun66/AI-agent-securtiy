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

## Stage 3. Adaptive white-box evaluation (before patch)

```bash
OPA_BIN=opa python -B -m week8.adaptive \
  --mode w7_plus_taint_guard --budget 50 --seed 20261119 \
  --output-dir /tmp/w8-adapt-before

# Optional reference condition, using a NEW output directory:
OPA_BIN=opa python -B -m week8.adaptive \
  --mode w7_full --budget 50 --seed 20261119 \
  --output-dir /tmp/w8-adapt-w7only
```

Candidate exploration is bounded and feedback-conditioned. Exercises eight
W7 attack tasks: capability forgery, parent link, depth/scope widening, command
replacement, signature substitution, approval swap/replay. The ninth task
checks W4 `Tainted.split()` laundering through **mock-only** `http_get`. Each
candidate records its mutation label, hashed identifier, rejection reason,
all reached layer verdicts and actual observed sandbox/mock call evidence.
The first successful variation stops exploration of its original task.

**Crucial metric rule:** W7 adaptive ASR denominator is **8 original W7
attack tasks**, never `8 × 50`; source-taint laundering is reported in a
**separate 1-task provenance metric**. A taint-propagation escape is not proof
of W7 credential/approval bypass. Failed searches mean "no bypass found
within this budget", not "proven secure".

`report.json`, `audit.jsonl`, `checkpoint.json` and `audit-signer.did` are
saved in the requested evidence directory. The external Bitcoin timestamp
anchor has not been performed. Run with a reachable OPA binary; the harness
fails rather than silently treating OPA outages as a defense result.

## Screenshot checklist

- **Stage 1:** W7 pytest summary, `manifest.json` source hashes and baseline report table
- **Stage 2:** `PipelineOutcome.layers` showing ordered decisions, `tool_invoked`, `output_released`, approval preview with operation/target/risk (via existing `python -m week7.run_approval_demo`)
- **Stage 3:** per-task results and 50-attempt budget, the W4 `taint_split` mock execution trace, signed audit checkpoint

The pre-patch reports are evidence **only after** someone runs the commands.
This folder itself does not contain fabricated benchmark outcomes.

## Stage 4 — patched provenance and repeatable comparison

The W4 `Tainted.split()` laundering defect is patched together with tuple/list
source propagation, indexing and join. Collect a *real* before report at frozen
pre-patch commit `aa58fc6`; do not create it by running the patched checkout.
No measured ASR changes are claimed in this source commit.

```bash
git worktree add --detach /tmp/w8-prepatch aa58fc6
(cd /tmp/w8-prepatch && OPA_BIN=opa python -m week8.adaptive --output-dir /tmp/w8-adapt-before --seed 20261119 --budget 50)
OPA_BIN=opa python -m week8.adaptive --phase after --output-dir /tmp/w8-adapt-after --seed 20261119 --budget 50
python -m week8.patch_compare --before /tmp/w8-adapt-before/report.json --after /tmp/w8-adapt-after/report.json --output-dir /tmp/w8-patch-compare
python -m pytest -q week4/test_taint_propagation.py week8/test_pipeline.py week8/test_patch_compare.py
```
