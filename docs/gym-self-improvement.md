# Gym Self-Improvement Loop

The `skwaq gym improve` command runs an automated self-improvement cycle that
analyzes detection failures, proposes targeted fixes, reviews them for
overfitting, and applies accepted patches — then verifies the result.

## Quick Start

```bash
# 1. Establish baseline (all 5 suites)
skwaq gym eval --suites fixtures,juliet,owasp,cyberseceval,cgc --procs 5 -j 2

# 2. Run improvement cycle (with holdout validation)
skwaq gym improve fixtures --max-improvements 5 --holdout-fraction 0.2 --timeout 30

# 3. Verify improvement
skwaq gym eval --suites fixtures --procs 5 -j 2
skwaq gym compare
```

## How It Works

The improvement loop executes five phases:

```
Benchmark → Failure Analysis → Proposal Generation → Overfitting Review → Patch Application
    ↑                                                                           |
    └───────────────────── Re-benchmark & Verify ───────────────────────────────┘
```

### Phase 1: Benchmark & Collect Outcomes

Runs the selected suite and scores every case. False negatives (missed
vulnerabilities) are collected with their source code for analysis.

The case set is split into training and holdout partitions. Only training
cases feed the failure analyst. The holdout set validates that improvements
generalize and are not overfit to specific test inputs.

### Phase 2: Failure Analysis

The **failure-analyst** LLM agent examines each false negative using
enriched graph context (imports, data sources, cross-file call graph,
interprocedural taint flows, and string references):

- Reads the vulnerable source code and graph context
- Queries the knowledge base for relevant CWE patterns
- Checks for graph context gaps (missing taint flows, sparse call graph,
  absent data sources, missing interprocedural taint edges)
- Identifies why the vulnerability was missed and produces structured
  improvement proposals
- Prioritizes graph-aware proposals (`AgentPrompt`, `TaintRule`) over regex
  patterns (`NewPattern`)

Since PR #292, the failure analyst has access to **interprocedural taint
flows** — taint edges that cross function boundaries. When a tainted value
passes from a caller to a callee (or vice versa via return values), the
graph builder creates `taint_flows` entries linking caller sources to callee
sinks. The failure analyst uses these edges to diagnose false negatives
caused by incomplete cross-function data flow tracking.

A heuristic analyzer runs in parallel, checking for graph context gaps
before falling back to regex-based analysis. It detects: missing taint flows
for functions handling external data (including interprocedural flows),
sparse cross-file call graphs, missing data source entries, and unmapped
CWE families.

### Phase 3: Overfitting Review

Every proposal passes through the **overfitting-reviewer** agent, which
evaluates:

- **Real-world applicability** — would this pattern fire on production code?
- **Overfitting risk** — is this too specific to the test fixture?
- **Side effects** — could this increase false positives?

Proposals receive a verdict: `Accept`, `Reject`, or `Modify`. Only accepted
proposals proceed to application. Rejected proposals and their reasoning are
logged to `data/knowledge/fn-insights.md` for future reference.

### Phase 4: Patch Application

Accepted proposals are applied automatically. Each proposal type has its own
application strategy:

| Proposal Kind     | Target | Strategy |
|-------------------|--------|----------|
| `NewPattern`      | `crates/core/src/analysis/patterns_source.rs` | Find/replace or append to pattern array |
| `AgentPrompt`     | `agents/*.md` | Find/replace or append after last `##` heading |
| `CweMapping`      | `crates/gym/src/scoring.rs` | Find/replace patch on CWE mapping functions |
| `TaintRule`       | SQLite database (`data_sources` / `data_sinks` table) | `INSERT OR IGNORE` via parameterized SQL |
| `GroundTruthFix`  | `data/gym/ground_truth/fixtures.toml` | Find/replace |

**File-based proposals** (`NewPattern`, `AgentPrompt`, `CweMapping`,
`GroundTruthFix`) use exact string matching. If the target string is not
found, the patch is skipped with a warning — never a partial apply. File
paths are canonicalized and directory-checked to prevent traversal attacks.

**Database proposals** (`TaintRule`) use pipe-delimited format
(`name|source_type|location`) and insert directly into the CPG database.
The database ID is generated server-side. Strictly validated: exactly 3
fields with length limits (name: 256, type: 64, location: 512).

### Phase 5: Verification

After patches are applied, the benchmark re-runs. The cycle is accepted only
if:

- F1 score does not decrease
- Precision drops no more than 2%
- No per-CWE detection rate regresses by more than the noise margin (2%)

If verification fails, all patches are rolled back automatically.

## CLI Reference

### `skwaq gym improve`

Run one improvement cycle on a benchmark suite.

```
skwaq gym improve <SUITE> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `SUITE`  | Benchmark suite name (`fixtures`, `juliet`, `owasp`, etc.) |

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-cases <N>` | 20 | Maximum false-negative cases to analyze |
| `--cwe <CWE-XXX>` | (all) | Filter analysis to a specific CWE |

**Example:**

```bash
# Improve detection of race conditions in the fixtures suite
skwaq gym improve fixtures --cwe CWE-362 --max-cases 10
```

### `skwaq gym eval`

Run full evaluation across multiple suites. Use this to establish baselines
before and after improvement cycles.

```
skwaq gym eval [OPTIONS]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--suites <LIST>` | all registered | Comma-separated suite names |
| `--procs <N>` | 5 | Parallel processes per suite |
| `-j <N>` | 2 | In-process async concurrency per shard |
| `--quick` | false | Pattern-only mode (no LLM agents) |
| `--llm-only` | false | LLM agents only (no patterns) |
| `--adaptive` | false | AIMD rate throttling for API calls |
| `--output <DIR>` | `data/gym/results/` | Results directory |

**Example:**

```bash
# Full evaluation of fixtures and juliet suites
skwaq gym eval --suites fixtures,juliet --procs 5 -j 2 --quick
```

### `skwaq gym compare`

Compare the two most recent benchmark runs to see score deltas.

```bash
skwaq gym compare
```

Output shows per-metric deltas and per-CWE detection rate changes.

### `skwaq gym case-diff`

Show per-case outcome changes between runs (which cases flipped TP/FN/FP).

```bash
skwaq gym case-diff
```

## Proposal Types

The improvement engine generates five types of proposals:

### NewPattern

Adds a regex pattern to the pattern detector for a specific CWE.

```
Kind: NewPattern
Target: crates/core/src/analysis/patterns_source.rs
Example: \baccess\s*\( → detects TOCTOU race conditions (CWE-367)
```

Patterns use the `regex` crate (linear-time guarantee), so LLM-generated
regexes cannot cause ReDoS.

### CweMapping

Adds or corrects CWE family mappings in the scoring engine so that detected
findings are properly attributed to expected CWEs.

```
Kind: CweMapping
Target: crates/gym/src/scoring.rs
Example: Map CWE-367 → CWE-362 family (race conditions)
```

### TaintRule

Adds taint sources or sinks to the CPG database to expand dataflow analysis
coverage. Unlike other proposal types, TaintRule proposals modify the database
directly rather than patching source files.

```
Kind: TaintRule
Target: SQLite database (data_sources / data_sinks table)
Format: name|source_type|location (pipe-delimited, 3 fields required)
Example: mktemp|function|libc_tempfile → adds mktemp() as taint source
Security: Server-side UUID, parameterized SQL, field length validation
```

### AgentPrompt

Modifies an agent's Markdown role card to improve its graph traversal
strategy or detection behavior. Supports two modes:

- **Append mode** (empty `patch.find`): New content is inserted after the
  last `##` heading in the file, or at EOF if no headings exist
- **Replace mode** (`patch.find` contains text): Exact find/replace on
  the agent file

```
Kind: AgentPrompt
Target: agents/*.md
Example: Add TOCTOU graph-traversal instructions to vuln-hunter.md
Security: File path canonicalized and verified within agents/ directory
```

### GroundTruthFix

Corrects the ground truth when the analyst determines a fixture is
mislabeled (wrong CWE, wrong is_negative flag).

```
Kind: GroundTruthFix
Target: data/gym/ground_truth/fixtures.toml
```

Ground truth fixes are rare and receive extra scrutiny from the overfitting
reviewer.

## Scoring Metrics

The gym uses standard information retrieval metrics:

| Metric | Formula | Description |
|--------|---------|-------------|
| **Precision** | TP / (TP + FP) | How many detections are real vulnerabilities |
| **Recall** | TP / (TP + FN) | How many real vulnerabilities are detected |
| **F1** | 2 * P * R / (P + R) | Harmonic mean of precision and recall |

### Per-CWE Scoring

Each CWE family gets its own detection rate and precision score. The
`cwe_family()` function maps specific CWEs to their parent family (e.g.,
CWE-121 buffer overflow maps to the CWE-119 memory safety family).

### Negative Case Calibration

Negative (patched/safe) test cases track the false positive rate separately.
Only findings with `severity = "critical"` and CWEs matching the original
vulnerability count as false positives on negative cases — this prevents
pattern-matching noise from inflating FP counts.

### Regression Detection

The verification gate uses a 2% noise margin (`CWE_REGRESSION_NOISE_MARGIN`).
A per-CWE detection rate drop exceeding this margin triggers a rollback.

## Knowledge Artifacts

Each improvement cycle appends insights to two knowledge files:

### `data/knowledge/fn-insights.md`

Contains per-case false negative analysis: which CWEs were expected, what was
detected, why detection failed, and what the failure-analyst recommended.

### `data/knowledge/learned-patterns.md`

Contains patterns discovered across improvement cycles, organized by date and
suite. Each entry records the regex, target CWE, source case, and priority.

These files serve as persistent memory for future improvement cycles — the
failure analyst reads them to avoid re-proposing rejected ideas or
duplicating existing patterns.

Both files are capped at 50KB per write to prevent unbounded growth.

## Configuration

The improvement loop uses the same LLM backend configuration as the rest of
skwaq. The failure-analyst and overfitting-reviewer agents require an
Opus-class model.

```toml
[llm]
reasoning = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
```

Run `skwaq gym preflight` to verify your LLM backend is configured correctly
before starting an improvement cycle.

### Token Budget

The improvement loop budgets tokens conservatively:

| Parameter | Value |
|-----------|-------|
| Budget per case (target) | 50,000 tokens |
| Budget per case (max) | 100,000 tokens |
| Max cases per cycle | 20 |
| Max KB queries per cycle | 6 CWE queries, 2 hits each |
| Total cycle cap | 3M tokens (defense-in-depth) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required if `reasoning = "anthropic"` |
| `GHIDRA_INSTALL_DIR` | Path to Ghidra (for binary analysis suites) |

API keys are read from environment variables only — never logged, stored in
the database, or written to knowledge files.

## Fixtures Format

Ground truth is defined in TOML manifests at `data/gym/ground_truth/`.

```toml
suite = "fixtures"
version = "3.0"

[[cases]]
id = "buffer_overflow"
path = "buffer_overflow.c"
binary_path = "binaries/buffer_overflow_O0"    # optional
expected_cwes = [121, 134]
is_negative = false
language = "c"

[[cases]]
id = "buffer_overflow_patched"
path = "buffer_overflow_patched.c"
expected_cwes = [121]
is_negative = true                             # patched — should NOT detect
language = "c"
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique case identifier within the suite |
| `path` | yes | Relative path to source file |
| `binary_path` | no | Relative path to compiled binary |
| `expected_cwes` | yes | List of CWE IDs expected in this case |
| `is_negative` | yes | `true` = patched/safe, `false` = vulnerable |
| `language` | yes | Source language (`c`, `java`, `python`) |

Path values are validated: `..` segments and absolute paths are rejected.

## Interprocedural Taint in Improvement Cycles

Since PR #292, the graph builder creates interprocedural `taint_flows`
entries that link tainted data across function boundaries. This
significantly improves the failure analyst's ability to diagnose false
negatives in multi-function vulnerability patterns.

### How interprocedural taint affects proposals

When the failure analyst examines a false negative, it now sees taint paths
that cross function boundaries:

```
Source: getenv() in main()
  → Interprocedural edge: main() calls process_input()
  → Sink: system() in process_input()
```

This enables three types of proposals that were previously not possible:

| Scenario | Pre-292 Proposal | Post-292 Proposal |
|----------|-----------------|-------------------|
| Cross-function injection | `NewPattern` (regex for `system()`) | `TaintRule` (link caller source to callee sink) |
| Wrapper function chains | `AgentPrompt` (tell agent to read more code) | `AgentPrompt` (tell agent to follow interprocedural taint paths) |
| Multi-file data flow | Often no proposal (gap too large) | `TaintRule` + `AgentPrompt` (taint edge + traversal instruction) |

### Verifying interprocedural coverage

To check whether interprocedural taint flows are being created for a
specific case:

```bash
# Query the CPG for cross-function taint edges
skwaq query "SELECT ds.name as source, dk.name as sink, tf.path
             FROM taint_flows tf
             JOIN data_sources ds ON tf.source_id = ds.id
             JOIN data_sinks dk ON tf.sink_id = dk.id
             WHERE tf.path LIKE '%→%'"
```

If no interprocedural edges appear for a case that should have them, the
graph builder may be missing call edges. File an issue with the case ID.

## Supported Benchmark Suites

| Suite | Description | Cases |
|-------|-------------|-------|
| `fixtures` | Pre-bundled C test cases | ~99 |
| `juliet` | NIST Juliet Test Suite (C/Java) | ~200+ |
| `owasp` | OWASP Benchmark (Java web) | ~2700 |
| `cgc` | DARPA Cyber Grand Challenge | ~130 |
| `cyberseceval` | Anthropic CyberSecEval | varies |
| `realworld` | Real-world vulnerable code | varies |
| `binpool` | BinPool binaries (requires download) | ~150 |
| `cybergym` | CyberGym (with patch diffs) | varies |

## Workflow: Running a Full Improvement Cycle

This example shows a complete cycle starting from the post-PR #292 baseline
(interprocedural taint, 0 FP, expanded CWE mappings).

```bash
# Step 1: Verify environment
skwaq gym preflight

# Step 2: Create feature branch
git checkout -b improve/gym-cycle-post-292

# Step 3: Baseline all suites (sequential to avoid LLM rate limits)
skwaq gym eval --suites fixtures --procs 5 -j 2
# → fixtures: F1=87.9%  P=100%  R=78.4%  TP=91 FP=0 FN=25 TN=12
skwaq gym eval --suites juliet --procs 5 -j 2
skwaq gym eval --suites owasp --procs 5 -j 2
skwaq gym eval --suites cyberseceval --procs 5 -j 2
skwaq gym eval --suites cgc --procs 5 -j 2

# Step 4: Run improvement with holdout validation
skwaq gym improve fixtures --max-improvements 5 --holdout-fraction 0.2 --timeout 30
# → Analyzes 25 false negatives (20 training, 5 holdout)
# → Generates proposals (AgentPrompt, TaintRule, NewPattern)
# → Overfitting reviewer gates each proposal
# → Applies accepted patches

# Step 5: Verify — F1 must exceed 87.9%, precision must stay at 100%
skwaq gym eval --suites fixtures --procs 5 -j 2
skwaq gym compare
# → F1: 87.9% → 90.1% (+2.2%)
# → Precision: 100% → 100% (no regression)
# → Recall: 78.4% → 81.7% (+3.3%, 3 fewer FN)

# Step 6: If targets not met, run a second cycle (cap: 2 total)
skwaq gym improve fixtures --max-improvements 5 --holdout-fraction 0.2 --timeout 30

# Step 7: Review per-CWE changes
skwaq gym case-diff
# → CWE-78 detection: 80% → 100% (interprocedural taint caught multi_file)
# → CWE-362 detection: 60% → 80% (AgentPrompt added TOCTOU tracing)

# Step 8: Commit with before/after table
git add agents/ crates/core/src/analysis/patterns_source.rs \
       crates/gym/src/scoring.rs data/knowledge/
git commit -m "gym: improve fixtures F1 87.9%→90.1% (+2.2%)

Improvement cycle results (post-PR #292 baseline):
- Before: F1=87.9%, P=100%, R=78.4% (91 TP, 0 FP, 25 FN, 12 TN)
- After:  F1=90.1%, P=100%, R=81.7% (95 TP, 0 FP, 22 FN, 12 TN)
- Accepted: 2 AgentPrompt, 1 TaintRule
- Key: interprocedural taint enables cross-function FN resolution
"

# Step 9: Create PR
gh pr create --title "gym: improve fixtures F1 87.9%→90.1%" --base main
```

### Multi-Suite Baseline Recording

When recording baselines across all 5 suites, run them sequentially to
avoid LLM rate-limit contention. Each suite records independently to the
history database at `~/.skwaq/gym/results.db`:

```bash
for suite in fixtures juliet owasp cyberseceval cgc; do
  skwaq gym eval --suites "$suite" --procs 5 -j 2
done
```

The CGC suite may timeout on some cases due to binary analysis complexity.
CGC eval failures are non-blocking — record whatever results complete.
Partial CGC results are still valuable as a baseline for future cycles.

## Security Considerations

- **Regex size limits** — LLM-proposed patterns are compiled with
  `RegexBuilder::size_limit(200_000)` to prevent NFA memory exhaustion, in
  addition to the `regex` crate's linear-time guarantee (no ReDoS)
- **Structured pattern insertion** — LLM output is never interpolated into
  Rust source via `format!()`. Proposals use typed `SourcePattern` struct
  construction with validated fields
- **CLI argument validation** — Numeric arguments enforce ranges at parse time
  (`holdout_fraction ∈ (0.0, 0.5]`, `max_improvements ∈ [1, 10]`,
  `timeout ∈ [5, 600]`) to prevent degenerate configurations
- **Regression gate as security control** — The 2% regression threshold
  (`CWE_REGRESSION_NOISE_MARGIN`) is a compile-time constant, not a CLI flag
- API keys come from environment variables only — never logged, committed, or
  stored in the history database
- Fixture source code is wrapped in XML delimiters in agent prompts to reduce
  prompt injection surface
- Compile-then-test gate: `cargo build` + `cargo test` must pass after
  applying patches, before any commit
- History database is `.gitignore`d — no API metadata is committed
- Knowledge file writes are capped at 50KB per operation
- Path validation on fixture manifests rejects `..` traversals and absolute
  paths
- SQL queries use parameterized `?` placeholders exclusively (no `format!()`)

For the full security model, see [Gym Safety Hardening](gym-safety-hardening.md).

For running improvement cycles that target agent behavior and taint coverage
(rather than regex patterns), see [Graph-Agent Gym Cycle](graph-agent-gym-cycle.md).

## Troubleshooting

### "No false negatives found"

The suite is at 100% recall. Try a different suite or add new test cases.

### "LLM backend unavailable"

The failure analyst requires an Opus-class model. Run `skwaq gym preflight`
to verify your configuration. If using Copilot, ensure `gh auth login` is
current.

### "Patch target not found"

The find/replace string in a proposal didn't match the current file contents.
This happens when the LLM hallucinates a code fragment. The patch is skipped
safely — no partial edits occur.

### "Verification failed — rolling back"

The post-improvement benchmark showed a regression (F1 drop or precision loss
> 2%). All patches are reverted. Try with `--max-cases 10` for more
conservative proposals, or filter to a specific CWE with `--cwe`.

### "Token budget exhausted"

The cycle hit the 3M token defense-in-depth cap. Reduce `--max-cases` or
filter to a specific CWE to focus the analysis.
