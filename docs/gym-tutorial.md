# Tutorial: Running a Gym Improvement Cycle

Step-by-step guide to improving skwaq's vulnerability detection using the
self-improvement loop. This tutorial walks through a complete cycle on the
expanded fixtures suite (65 CyberSecEval + 12 CGC + original test cases).

## Prerequisites

- Rust toolchain (stable)
- GitHub Copilot CLI authenticated (`gh auth login`)
- Built skwaq: `cargo build -p skwaq --release`

Verify your environment:

```bash
cargo run -p skwaq -- gym preflight
```

Expected output:

```
[OK] Copilot backend reachable
[OK] Model: claude-opus-4.6
[OK] No fallback model configured
[OK] Token budget: 3,000,000 per cycle
```

## Step 1: Establish Baseline

Run the benchmark in pattern-only mode to get a fast baseline:

```bash
cargo run -p skwaq -- gym eval --suites fixtures --quick
```

This evaluates all ~99 fixture cases using regex pattern detection only (no
LLM agents). Typical output:

```
fixtures: F1=86.3%  Precision=95.8%  Recall=78.4%  TP=91 FP=4 FN=25 TN=12
```

Record these numbers — they are your before-improvement baseline.

## Step 2: Review False Negatives

Before running the improvement loop, inspect which cases are being missed:

```bash
cargo run -p skwaq -- gym case-diff --suite fixtures
```

Common false negative categories:

| Category | Example Cases | Typical Cause |
|----------|--------------|---------------|
| Multi-file vulnerabilities | `multi_file` | Cross-file taint paths not fully traced |
| Subtle race conditions | `race_condition` | Agent lacks TOCTOU graph traversal instructions |
| Complex integer flows | `int_wrap`, `signedness` | Missing taint sources for integer conversion APIs |
| Language-specific idioms | `cpp_vulns` | Missing data source/sink entries for C++ APIs |

## Step 3: Run the Improvement Cycle

```bash
cargo run -p skwaq -- gym improve fixtures --max-cases 20
```

The cycle executes five phases:

```
Phase 1: Benchmark .................. done (99 cases, 25 FN)
Phase 2: Failure analysis ........... done (15 cases analyzed)
Phase 3: Overfitting review ......... done (3 proposals → 1 accepted, 2 rejected)
Phase 4: Patch application .......... done (1 patch applied)
Phase 5: Verification ............... done (no regression)
```

### What happens during each phase

**Phase 1** splits cases into training (80%) and holdout (20%). Only training
cases are shown to the failure analyst.

**Phase 2** sends each false negative to the `failure-analyst` LLM agent with
the vulnerable source code, graph context (imports, data sources, cross-file
call graph, string references), and knowledge base context. The analyst
checks for graph context gaps first, then produces structured `Improvement`
proposals prioritized as: `AgentPrompt` > `TaintRule` > `CweMapping` >
`NewPattern`.

**Phase 3** runs every proposal through the `overfitting-reviewer` agent,
which assigns a verdict (`Accept`, `Reject`, `Modify`) and overfitting risk
rating (`Low`, `Medium`, `High`).

**Phase 4** applies accepted proposals. File-based proposals (`NewPattern`,
`AgentPrompt`, `CweMapping`) use find/replace patching. Database proposals
(`TaintRule`) insert directly into the CPG. All file paths are
canonicalized and directory-checked.

**Phase 5** re-runs the benchmark on the full case set (including holdout) and
checks the regression gate: F1 must not decrease, precision drop ≤ 2%, no
per-CWE detection rate regression > 2%.

### Filtering to a specific CWE

To focus the improvement on a single vulnerability class:

```bash
cargo run -p skwaq -- gym improve fixtures --cwe CWE-362 --max-cases 10
```

This limits analysis to false negatives involving CWE-362 (race conditions)
and analyzes at most 10 cases.

## Step 4: Verify the Improvement

Re-run the full evaluation:

```bash
cargo run -p skwaq -- gym eval --suites fixtures --quick
```

Compare against the baseline:

```bash
cargo run -p skwaq -- gym compare
```

Example output:

```
Run 42 vs Run 41 (fixtures, quick mode)

  Metric     Before   After    Delta
  ─────────  ───────  ───────  ──────
  F1         86.3%    86.3%    +0.0%
  Precision  95.8%    95.8%    +0.0%
  Recall     78.4%    78.4%    +0.0%

  Per-CWE changes: none

  Verdict: NO REGRESSION
```

A "no regression" result is a valid outcome — it means the accepted proposals
did not make things worse, even if they did not measurably improve the score.
This is common when the remaining false negatives require architectural
changes (like multi-file analysis) rather than pattern additions.

## Step 5: Cross-Validate

Verify that accepted patterns generalize beyond the fixtures suite:

```bash
cargo run -p skwaq -- gym eval --suites juliet,owasp --quick
```

If any suite shows a regression, investigate with `gym case-diff` before
committing.

## Step 6: Review Knowledge Artifacts

The cycle appends insights to two files:

**`data/knowledge/fn-insights.md`** — Per-case analysis of why each false
negative was missed. Review these to understand the remaining detection gaps:

```bash
tail -50 data/knowledge/fn-insights.md
```

**`data/knowledge/learned-patterns.md`** — Patterns discovered and accepted
during this cycle:

```bash
tail -20 data/knowledge/learned-patterns.md
```

## Step 7: Commit and PR

```bash
git add crates/core/src/analysis/patterns_source.rs \
       crates/gym/src/scoring.rs \
       agents/ \
       data/knowledge/fn-insights.md \
       data/knowledge/learned-patterns.md

git commit -m "gym: improve fixtures F1 86.3% (no regression from baseline)

Improvement cycle results:
- Baseline: F1=86.3%, Prec=95.8%, Rec=78.4%
- Post:     F1=86.3%, Prec=95.8%, Rec=78.4%
- Delta:    none (remaining FNs require architectural changes)
- Accepted: 1 proposal (MODIFY verdict)
- Rejected: 2 proposals (overfitting risk)
"
```

## Common Scenarios

### Improvement cycle finds no proposals

```
Phase 2: Failure analysis ........... done (0 proposals)
```

This happens when all false negatives are caused by limitations that neither
graph context enrichment nor pattern changes can address (e.g., binary-only
cases, aliased function pointers). Check `fn-insights.md` for the analyst's
reasoning.

### Verification fails — automatic rollback

```
Phase 5: Verification ............... FAILED
  CWE-119 detection rate: 90% → 85% (regression > 2%)
  Rolling back all patches...
```

All patches from this cycle are reverted. Try with:
- `--max-cases 10` for more conservative proposals
- `--cwe CWE-XXX` to focus on a single vulnerability class
- Review rejected proposals in `fn-insights.md` for ideas

### LLM backend unavailable

```
error: preflight check failed: Copilot backend unreachable
```

Run `gh auth login` to refresh your GitHub authentication, then retry
`skwaq gym preflight`.

### Holdout validation catches overfitting

If a proposal improves training-set scores but the holdout cases show no
improvement or regression, the overfitting reviewer will flag it. The proposal
receives a `Reject` verdict with `overfitting_risk: High`.

## Advanced: Multi-Suite Improvement

Run improvement cycles against multiple suites to build broad detection
capability:

```bash
# Cycle 1: Fixtures (fast iteration)
cargo run -p skwaq -- gym improve fixtures --max-cases 20

# Cycle 2: Juliet (NIST reference)
cargo run -p skwaq -- gym improve juliet --max-cases 15

# Cycle 3: Cross-validate everything
cargo run -p skwaq -- gym eval --suites fixtures,juliet,owasp,cyberseceval --quick
cargo run -p skwaq -- gym compare
```

Each cycle is independent — proposals from the fixtures cycle are tested
against juliet during cross-validation, and vice versa.

## Advanced: Configuring the Holdout Split

The default holdout fraction is 20%. For small suites, you may want to reduce
it to ensure enough training cases:

```bash
cargo run -p skwaq -- gym improve fixtures --holdout-fraction 0.1
```

Valid range: (0.0, 0.5]. Values outside this range are rejected:

```
error: holdout-fraction must be in (0.0, 0.5], got 0.8
```

## Advanced: Proposal Cap

Limit the number of accepted proposals per cycle to reduce churn:

```bash
cargo run -p skwaq -- gym improve fixtures --max-improvements 3
```

Valid range: [1, 10]. Fewer proposals per cycle means smaller, more reviewable
diffs.

## Understanding the Expanded Fixture Set

The fixtures suite (v3.0) contains three categories of test cases:

| Category | Count | Source | Languages |
|----------|-------|--------|-----------|
| Original fixtures | 22 | Hand-crafted | C, C++, Python, JS |
| CyberSecEval (CSE) | 65 | Anthropic CyberSecEval | C, Python |
| Cyber Grand Challenge (CGC) | 12 | DARPA CGC corpus | C |

### CSE Fixtures

CyberSecEval cases test detection of OWASP Top 10 and CWE Top 25
vulnerability patterns. They include both vulnerable and patched variants,
providing balanced positive/negative coverage.

### CGC Fixtures

CGC cases are derived from the DARPA Cyber Grand Challenge corpus and focus
on low-level memory safety: stack smashing, heap metadata corruption, type
confusion, off-by-one errors, uninitialized stack variables, double fetch,
array out-of-bounds, signedness issues, format string writes, dangling
pointers, integer wraps, and null dereference via function pointer.

### Adding New Fixtures

1. Add the source file to `tests/fixtures/`
2. Add a `[[cases]]` entry to `data/gym/ground_truth/fixtures.toml`
3. Run `cargo run -p skwaq -- gym run fixtures --quick` to verify scoring
4. Optionally compile a binary and set `binary_path`

```toml
[[cases]]
id = "my_new_case"
path = "my_new_case.c"
expected_cwes = [787]
is_negative = false
language = "c"
```

Path values must be relative with no `..` segments.

## Advanced: Model Comparison with Profiles

Compare how different models perform on the same benchmark using profiles:

```bash
# Create profiles for two models
skwaq gym profile create opus --backend copilot --model claude-opus-4.6
skwaq gym profile create sonnet --backend copilot --model claude-sonnet-4.6

# Run identical evaluations
skwaq gym eval --suites fixtures --profile opus
skwaq gym eval --suites fixtures --profile sonnet

# View results independently
skwaq gym report --profile opus
skwaq gym report --profile sonnet

# Run improvement cycles per model
skwaq gym improve fixtures --max-cases 20 --profile opus
skwaq gym improve fixtures --max-cases 20 --profile sonnet
```

Each profile has its own results database, memory graph, and telemetry — no
cross-contamination between model evaluations. See [Gym Model
Profiles](gym-profiles.md) for the full reference.

## Next Steps

- [Gym Model Profiles](gym-profiles.md) — Side-by-side model comparisons
- [Graph-Agent Gym Cycle](graph-agent-gym-cycle.md) — Running cycles that
  generate AgentPrompt and TaintRule proposals (not just regex patterns)
- [Gym Configuration](gym-configuration.md) — Full configuration reference
- [Gym Safety Hardening](gym-safety-hardening.md) — Security controls
