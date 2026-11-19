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


Remaining stages will be added in the following patches.
