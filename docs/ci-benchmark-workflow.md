# CI Benchmark Workflow

Reference documentation for the `gym-smoke.yml` GitHub Actions workflow that
gates every pull request with a benchmark quality check.

## Overview

The **Gym Smoke** workflow runs on every pull request and contains two jobs:

| Job | Purpose | Runtime estimate |
|-----|---------|-----------------|
| `gym-smoke` | Quick sanity smoke test (5 fixture cases, pattern mode) | ~3 min |
| `ci-benchmark` | Full fixture suite + Juliet 20-case subset, F1 gate | 30–60 min |

Both jobs run on `ubuntu-latest`. Neither has an explicit `timeout-minutes`,
so they are governed by GitHub Actions' platform-level default of **6 hours**.
This ensures long-running benchmarks complete instead of being cancelled.

## Job: gym-smoke

A fast smoke test that confirms the build is healthy and pattern detection
produces results.

### Steps

1. **Checkout / toolchain / cache** — standard Rust setup via
   `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`,
   `Swatinem/rust-cache@v2`.
2. **Build** — `cargo build` (debug profile).
3. **Gym smoke test** — runs 5 fixture cases in `--quick` (pattern-only) mode:
   ```
   ./target/debug/skwaq gym run fixtures --max-cases 5 --quick
   ```
4. **Gym report** — generates a JSON report and saves it as the
   `gym-smoke-results` artifact.

This job does **not** enforce an F1 threshold — it only verifies the binary
builds and the gym pipeline executes without crashing.

## Job: ci-benchmark

A full benchmark run with an F1 quality gate. This job must pass for a PR to
merge.

### Steps

1. **Checkout / toolchain / cache** — same as `gym-smoke`.
2. **Build** — `cargo build`.
3. **Fixtures benchmark** — all fixture cases in pattern mode:
   ```
   ./target/debug/skwaq gym run fixtures --quick
   ```
4. **Juliet subset benchmark** — 20 Juliet Suite cases in pattern mode. The
   step uses `|| true` so a missing dataset does not fail the job; a warning
   is printed instead.
   ```
   ./target/debug/skwaq gym run juliet --max-cases 20 --quick || true
   ```
5. **Generate benchmark report** — writes `ci-benchmark-results.json`.
6. **Check F1 threshold** — parses the JSON report and compares the `f1` field
   against the `GYM_F1_THRESHOLD` environment variable. Exits non-zero if the
   score is below threshold.
7. **Upload artifact** — saves `ci-benchmark-results.json` as the
   `ci-benchmark-results` artifact for inspection.

### F1 Quality Gate

The gate is configured via a workflow-level environment variable:

```yaml
env:
  GYM_F1_THRESHOLD: "0.10"
```

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `GYM_F1_THRESHOLD` | float string | `"0.10"` | Minimum F1 score (0.0–1.0) to pass |

To raise the bar as detection quality improves, update `GYM_F1_THRESHOLD` in
`.github/workflows/gym-smoke.yml`. The threshold change takes effect on the
next PR run without any other code changes.

**Example gate output (pass):**
```
F1 score: 0.9167
Threshold: 0.10
PASS: F1 0.9167 >= threshold 0.1000
```

**Example gate output (fail):**
```
F1 score: 0.0500
Threshold: 0.10
FAIL: F1 0.0500 is below threshold 0.1000
Error: Process completed with exit code 1.
```

## Timeout Policy

Neither `gym-smoke` nor `ci-benchmark` sets `timeout-minutes`. This is
intentional.

The `ci-benchmark` job runs the full fixture suite plus a Juliet subset, which
takes 30–60 minutes depending on runner load. An explicit 5-minute timeout
cancelled the job before it could complete. Removing the timeout lets the job
run to its natural end and report a real F1 score against the gate.

**Backstop**: GitHub Actions enforces a hard platform ceiling of **6 hours**
per job. Any genuine hang is caught there without requiring a per-job override.

## Artifacts

After each run, two artifacts are available in the Actions summary:

| Artifact | Job | Contents |
|----------|-----|---------|
| `gym-smoke-results` | `gym-smoke` | JSON report from the 5-case smoke run |
| `ci-benchmark-results` | `ci-benchmark` | JSON report used for the F1 gate |

Download artifacts from the **Actions** tab → select a workflow run →
**Artifacts** section.

## Adjusting the Benchmark

### Raising the F1 threshold

Edit `GYM_F1_THRESHOLD` in `.github/workflows/gym-smoke.yml`:

```yaml
env:
  GYM_F1_THRESHOLD: "0.85"   # raise to 85% once detection is stable
```

### Changing the Juliet case count

Edit the `--max-cases` argument in the *Run juliet subset benchmark* step:

```yaml
- name: Run juliet subset benchmark (20 cases, pattern mode)
  run: |
    ./target/debug/skwaq gym run juliet --max-cases 20 --quick || true
```

Increase the count to improve statistical coverage; decrease it to reduce
CI minutes when iteration speed matters more than precision.

### Adding a new suite

Add a new step before *Generate benchmark report*:

```yaml
- name: Run owasp subset benchmark
  run: |
    ./target/debug/skwaq gym run owasp --max-cases 20 --quick || true
    echo "OWASP subset completed"
```

The `skwaq gym report` command aggregates across all suites run in the same
process lifetime, so the combined F1 is automatically included in the gate.

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---------|-------------|-----------|
| Job cancelled after 6 hours | Genuine hang in benchmark | Check for LLM rate-limiting or network issues; re-run |
| F1 gate fails at 0.0 | `ci-benchmark-results.json` not found or malformed | Check the *Generate benchmark report* step logs |
| Juliet step skipped/warning | Dataset not present on runner | Expected — Juliet data must be pre-committed or fetched separately |
| Rust cache miss on every run | `Cargo.lock` changed | Normal; full rebuild on first run after dependency updates |
