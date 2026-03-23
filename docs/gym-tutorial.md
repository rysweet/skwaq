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

Run the benchmark to get a baseline. Since PR #292 (interprocedural taint,
FP fixes, Juliet CWE expansion), the fixtures baseline is:

```bash
cargo run -p skwaq -- gym eval --suites fixtures --procs 5 -j 2
```

This evaluates all ~128 fixture cases. Typical output on the current
codebase:

```
fixtures: F1=87.9%  Precision=100%  Recall=78.4%  TP=91 FP=0 FN=25 TN=12
```

Key baseline properties:
- **100% precision** (0 FP) — restored by PR #292's fixture fixes
- **25 false negatives** — the improvement target
- **Interprocedural taint active** — cross-function flows are in the graph

Record these numbers — they are your before-improvement baseline.

For a comprehensive baseline across all suites:

```bash
for suite in fixtures juliet owasp cyberseceval cgc; do
  cargo run -p skwaq -- gym eval --suites "$suite" --procs 5 -j 2
done
```

## Step 2: Review False Negatives

Before running the improvement loop, inspect which cases are being missed:

```bash
cargo run -p skwaq -- gym case-diff --suite fixtures
```

Common false negative categories (post-PR #292):

| Category | Example Cases | Typical Cause | Interprocedural Taint Helps? |
|----------|--------------|---------------|------------------------------|
| Multi-file vulnerabilities | `multi_file` | Cross-file taint paths not fully traced | Yes — interprocedural edges now cross function boundaries |
| Subtle race conditions | `race_condition` | Agent lacks TOCTOU graph traversal instructions | Partially — taint shows access/open sequences across functions |
| Complex integer flows | `int_wrap`, `signedness` | Missing taint sources for integer conversion APIs | Yes — integer casts across function calls now tracked |
| Language-specific idioms | `cpp_vulns` | Missing data source/sink entries for C++ APIs | No — requires TaintRule proposals for new APIs |
| Wrapper function chains | `cse_*` wrappers | Taint lost through helper functions | Yes — caller-to-callee taint propagation |

## Step 3: Run the Improvement Cycle

```bash
cargo run -p skwaq -- gym improve fixtures \
  --max-improvements 5 --holdout-fraction 0.2 --timeout 30
```

The cycle executes five phases:

```
Phase 1: Benchmark .................. done (128 cases, 25 FN)
Phase 2: Failure analysis ........... done (20 training cases analyzed)
Phase 3: Overfitting review ......... done (5 proposals → 3 accepted, 2 rejected)
Phase 4: Patch application .......... done (3 patches applied)
Phase 5: Verification ............... done (F1 improved, 0 FP)
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
Run 44 vs Run 43 (fixtures)

  Metric     Before   After    Delta
  ─────────  ───────  ───────  ──────
  F1         87.9%    90.1%    +2.2%
  Precision  100.0%   100.0%   +0.0%
  Recall     78.4%    81.7%    +3.3%

  Per-CWE changes:
    CWE-78:  80% → 100%  (+20%)  [interprocedural taint caught multi_file]
    CWE-362: 60% →  80%  (+20%)  [AgentPrompt added TOCTOU tracing]

  Verdict: IMPROVED (F1 +2.2%, P maintained at 100%)
```

A "no regression" result is also a valid outcome — it means the accepted
proposals did not make things worse. This is common when remaining false
negatives require fundamental changes beyond what the improvement loop can
propose.

**Important:** With the post-292 baseline at 100% precision, any FP
introduction is an immediate rejection signal. The improvement loop must
maintain P=100% — this is a hard constraint, not a target.

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

Include a before/after comparison table in the commit message. The PR
should show per-suite baselines and improvement results.

```bash
git add agents/ \
       crates/core/src/analysis/patterns_source.rs \
       crates/gym/src/scoring.rs \
       data/knowledge/fn-insights.md \
       data/knowledge/learned-patterns.md

git commit -m "gym: improve fixtures F1 87.9%→90.1% (+2.2%)

Improvement cycle results (post-PR #292 baseline):
- Before: F1=87.9%, P=100%, R=78.4% (91 TP, 0 FP, 25 FN, 12 TN)
- After:  F1=90.1%, P=100%, R=81.7% (95 TP, 0 FP, 22 FN, 12 TN)
- Accepted: 2 AgentPrompt, 1 TaintRule
- Rejected: 2 proposals (overfitting risk)
- Key improvement: interprocedural taint enables cross-function FN resolution

Proposal details:
- AgentPrompt: vuln-hunter cross-file taint path traversal (CWE-78)
- AgentPrompt: vuln-hunter TOCTOU detection via access/open sequences (CWE-362)
- TaintRule: add missing source/sink for wrapper function chains
"
```

The commit must include at least one AgentPrompt or TaintRule change — not
just regex patterns. This ensures the improvement loop exercises the full
graph-agent pipeline, not just the pattern detector.

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

## Advanced: Multi-Suite Baseline and Improvement

Record baselines across all 5 suites before running improvement cycles.
This establishes comprehensive metrics in the history database for
before/after comparison in PRs.

```bash
# Baseline all suites (sequential to avoid LLM rate limits)
for suite in fixtures juliet owasp cyberseceval cgc; do
  cargo run -p skwaq -- gym eval --suites "$suite" --procs 5 -j 2
done

# Improve on fixtures (max 2 cycles, 5 improvements each)
cargo run -p skwaq -- gym improve fixtures \
  --max-improvements 5 --holdout-fraction 0.2 --timeout 30

# If F1 ≤ 87.9% or R ≤ 78.4%, run a second cycle
cargo run -p skwaq -- gym improve fixtures \
  --max-improvements 5 --holdout-fraction 0.2 --timeout 30

# Cross-validate against other suites
cargo run -p skwaq -- gym eval --suites juliet,owasp --procs 5 -j 2
cargo run -p skwaq -- gym compare
```

Each cycle is independent — proposals from the fixtures cycle are tested
against juliet during cross-validation, and vice versa.

**CGC suite note:** The CGC suite involves binary analysis and may timeout
on some cases. CGC eval failures are non-blocking for the improvement
workflow. Record whatever results complete — partial CGC baselines are
still valuable for tracking trends.

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

## Next Steps

- [Graph-Agent Gym Cycle](graph-agent-gym-cycle.md) — Running cycles that
  generate AgentPrompt and TaintRule proposals (not just regex patterns)
- [Gym Configuration](gym-configuration.md) — Full configuration reference
- [Gym Safety Hardening](gym-safety-hardening.md) — Security controls
