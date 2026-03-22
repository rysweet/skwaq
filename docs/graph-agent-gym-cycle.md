# Graph-Agent Gym Cycle

Running self-improvement cycles that exercise the graph-aware proposal pipeline
(AgentPrompt, TaintRule) in addition to regex patterns (NewPattern). This guide
covers the end-to-end workflow for improving vulnerability detection through
graph-agent instruction tuning.

## Overview

After the graph-agent architecture refactoring (PR #288), the improvement loop
generates proposals that modify agent behavior and taint coverage, not just
regex patterns. A graph-agent gym cycle validates that:

1. The failure-analyst produces AgentPrompt and TaintRule proposals
2. The overfitting-reviewer accepts graph-aware proposals
3. `apply_accepted_proposals()` correctly patches agent Markdown files and
   inserts taint rules into the CPG database
4. No regression occurs in pattern-only evaluation

## Quick Start

```bash
# Build (catches compile issues from recent refactoring)
cargo build -p skwaq

# Baseline
cargo run -p skwaq -- gym eval --suites fixtures --quick

# Improvement cycle
cargo run -p skwaq -- gym improve fixtures

# Post-improvement verification
cargo run -p skwaq -- gym eval --suites fixtures --quick
cargo run -p skwaq -- gym compare
```

## Understanding Proposal Types

The improvement cycle generates five proposal types. Graph-agent cycles
prioritize the first two:

| Priority | Kind | Target | Eval Signal |
|----------|------|--------|-------------|
| 1 | `AgentPrompt` | `agents/*.md` | Hybrid mode only |
| 2 | `TaintRule` | SQLite CPG database | Hybrid mode only |
| 3 | `CweMapping` | `crates/gym/src/scoring.rs` | Both modes |
| 4 | `NewPattern` | `crates/core/src/analysis/patterns_source.rs` | Pattern-only (quick) |
| 5 | `GroundTruthFix` | `data/gym/ground_truth/*.toml` | Both modes |

### Why AgentPrompt and TaintRule show 0% delta in quick mode

Quick mode (`--quick`) runs pattern-only analysis. AgentPrompt proposals modify
agent instructions that are only active during LLM-based analysis (hybrid mode).
TaintRule proposals add taint sources/sinks that are queried during agent tool
calls, not during regex pattern matching.

A 0% delta in quick mode is the **expected result** for a cycle that produces
only AgentPrompt and TaintRule proposals. It confirms:

- No regression from the patches themselves
- The proposals are correctly classified as agent-behavioral changes
- Pattern detection is unaffected

To measure the actual detection improvement, run a hybrid evaluation:

```bash
# Full hybrid eval (pattern + LLM agents) — takes 1-3 hours
cargo run -p skwaq -- gym eval --suites fixtures
```

## Step-by-Step: Running a Graph-Agent Cycle

### 1. Verify prerequisites

```bash
# Compile check (important after merging refactoring PRs)
cargo build -p skwaq

# LLM readiness (optional — heuristic fallback exists)
cargo run -p skwaq -- gym preflight
```

If the LLM backend is unavailable, the improvement engine falls back to
heuristic gap detection, which still produces AgentPrompt and TaintRule
proposals based on graph context analysis.

### 2. Establish baseline

```bash
cargo run -p skwaq -- gym eval --suites fixtures --quick
```

Record the baseline metrics. Example:

```
fixtures: F1=86.3%  Precision=95.8%  Recall=78.4%  TP=91 FP=4 FN=25 TN=12
```

### 3. Run improvement cycle

```bash
cargo run -p skwaq -- gym improve fixtures
```

The cycle runs five phases:

```
Phase 1: Benchmark .................. done (99 cases, 25 FN)
Phase 2: Failure analysis ........... done (15 cases analyzed)
Phase 3: Overfitting review ......... done (4 proposals → 2 accepted)
Phase 4: Patch application .......... done (2 patches applied)
Phase 5: Verification ............... done (no regression)
```

### 4. Inspect proposals for graph-aware types

After the cycle completes, review the proposals. A successful graph-agent
cycle includes at least one AgentPrompt or TaintRule proposal:

```
Accepted proposals:
  [1] AgentPrompt — Add cross-file taint tracing to vuln-hunter
      Target: agents/vuln-hunter.md
      CWEs: [78]
      Priority: High
      Evidence: graph context shows multi_file case has cross-compilation-unit
                command injection hidden in processor.c

  [2] AgentPrompt — Use get_taint_paths for wrapper function chains
      Target: agents/vuln-hunter.md
      CWEs: [78]
      Priority: High
      Evidence: taint path from user input through wrapper to system() not
                traced without explicit cross-file call graph traversal

Rejected proposals:
  [3] NewPattern — \bsystem\s*\(.*argv
      Verdict: Reject (overfitting_risk: High)
      Reason: Too specific to multi_file fixture naming convention
```

If all proposals are NewPattern, the graph-agent pipeline may not be working
correctly. Check:

- Is the failure-analyst agent card up to date? (See `agents/failure-analyst.md`)
- Does the CPG have data for the failing cases? (Check `data_sources` table)
- Are the graph tools registered? (See `crates/agents/src/tool_definitions.rs`)

### 5. Verify no regression

```bash
cargo run -p skwaq -- gym eval --suites fixtures --quick
cargo run -p skwaq -- gym compare
```

Expected output for a graph-agent cycle:

```
Run 42 vs Run 41 (fixtures, quick mode)

  Metric     Before   After    Delta
  ---------  -------  -------  ------
  F1         86.3%    86.3%    +0.0%
  Precision  95.8%    95.8%    +0.0%
  Recall     78.4%    78.4%    +0.0%

  Per-CWE changes: none

  Verdict: NO REGRESSION
```

### 6. Run gym tests

```bash
cargo test -p skwaq-gym
```

Confirms the proposals did not break any gym infrastructure.

### 7. Commit and PR

```bash
git add agents/ data/knowledge/fn-insights.md data/knowledge/learned-patterns.md
git commit -m "gym: graph-agent improvement cycle

Improvement cycle results:
- Baseline: F1=86.3%, Prec=95.8%, Rec=78.4%
- Post:     F1=86.3% (no regression)
- Accepted: 2 AgentPrompt proposals (cross-file taint tracing)
- Rejected: 1 NewPattern (overfitting risk)
- Key case: multi_file (CWE-78 cross-compilation-unit injection)
"
```

## Multi-File Vulnerability Detection

The primary use case for graph-agent proposals is detecting vulnerabilities
that span multiple source files. These are invisible to single-file pattern
matching.

### Example: `multi_file` case (CWE-78)

The `multi_file` fixture contains a command injection where:

1. `main.c` reads user input via `getenv()`
2. `main.c` passes the input to `process_data()` in `processor.c`
3. `processor.c` calls `system()` with the unsanitized input

Pattern-only analysis detects `system()` in `processor.c` but cannot trace the
data flow from `getenv()` in `main.c`. The AgentPrompt proposal adds
instructions to the vuln-hunter agent to:

- Use `get_cross_file_calls` to identify cross-file callers of `system()`
- Use `get_taint_paths` to trace data flow from external sources through
  wrapper functions
- Follow the call chain across compilation units before confirming or
  dismissing a finding

## Interpreting Results

### Pattern-only delta vs. hybrid delta

| Scenario | Quick (pattern-only) | Hybrid (pattern + agent) |
|----------|---------------------|--------------------------|
| Only NewPattern proposals | Delta visible | Delta visible |
| Only AgentPrompt proposals | 0% delta | Delta visible |
| Only TaintRule proposals | 0% delta | Delta visible |
| Mixed proposals | Partial delta | Full delta |

### When to run hybrid evaluation

Run a full hybrid eval when:

- You have accepted AgentPrompt or TaintRule proposals and want to measure
  their impact
- You are preparing a release and need comprehensive metrics
- You suspect agent-level improvements are masking pattern-level regressions

```bash
# Full hybrid eval (no --quick flag)
cargo run -p skwaq -- gym eval --suites fixtures
```

Hybrid evaluation runs the full 5-layer analysis pipeline (ingest, pattern,
dataflow, agent, synthesis) on every case. This takes 1-3 hours depending on
the suite size and LLM backend throughput.

### Healthy cycle indicators

A well-functioning graph-agent cycle shows:

- At least one AgentPrompt or TaintRule in accepted proposals
- Proposals reference specific graph context gaps (missing taint paths,
  sparse cross-file call graph)
- Rejected proposals have clear overfitting reasoning
- Quick-mode delta is 0% or positive (never negative)
- Knowledge files updated with FN analysis insights

### Warning signs

| Symptom | Possible Cause | Fix |
|---------|---------------|-----|
| All proposals are NewPattern | failure-analyst not using graph context | Check agent card tools list |
| AgentPrompt proposals rejected as overfitting | Proposals too specific to fixture names | Review anti-overfitting rules in failure-analyst.md |
| TaintRule proposals skipped with "no database" | `db=None` in quick mode | Expected — TaintRule inserts need DB connection |
| Quick-mode regression after AgentPrompt patches | Agent .md file syntax broken | Check for malformed Markdown in agents/ |

## Heuristic Fallback

When the LLM backend is unavailable, the improvement engine uses a heuristic
analyzer that checks for graph context gaps:

| Gap Detected | Heuristic Proposal |
|-------------|-------------------|
| Function handles external data but no `taint_flows` rows | `TaintRule` — add missing source/sink |
| Function has < 2 callers/callees in multi-file project | `AgentPrompt` — improve cross-file tracing |
| Investigation has zero `data_sources` entries | `TaintRule` — add data source entries |
| Expected CWE has no `cwe_family()` mapping | `CweMapping` — add family mapping |
| No graph gap found | `NewPattern` — add detection pattern (fallback) |

The heuristic analyzer runs in parallel with the LLM failure-analyst. If the
LLM is available, its proposals take precedence. If not, heuristic proposals
are used.

## Configuration

Graph-agent cycles use the same configuration as standard improvement cycles.
No additional configuration is required.

### Relevant options

| Flag | Default | Effect on graph-agent cycle |
|------|---------|----------------------------|
| `--max-cases` | 20 | More FN cases = more graph-aware proposals |
| `--max-improvements` | 5 | Cap on total accepted proposals per cycle |
| `--holdout-fraction` | 0.2 | Holdout cases validate generalization |
| `--cwe CWE-XXX` | all | Focus on specific CWE (e.g., `CWE-78` for injection) |

### Token budget

The enriched graph context adds ~20K characters per case. The per-case token
budget (50K target, 100K max) accommodates this without adjustment. The source
code section was reduced from 40K to 30K characters to offset the graph context
overhead.

## Iterating: Multiple Cycles

Run successive cycles to incrementally improve agent behavior:

```bash
# Cycle 1: General improvement
cargo run -p skwaq -- gym improve fixtures

# Cycle 2: Focus on injection vulnerabilities
cargo run -p skwaq -- gym improve fixtures --cwe CWE-78

# Cycle 3: Focus on race conditions
cargo run -p skwaq -- gym improve fixtures --cwe CWE-362

# Cross-validate against other suites
cargo run -p skwaq -- gym eval --suites fixtures,juliet --quick
```

Each cycle appends to `data/knowledge/fn-insights.md` and
`data/knowledge/learned-patterns.md`. The failure-analyst reads these files
to avoid re-proposing rejected ideas.

### Pattern growth control

Successive cycles accumulate patterns and agent instructions. Monitor growth:

- Check `agents/vuln-hunter.md` size — agent cards over 5KB may benefit from
  consolidation
- Check pattern count in `patterns_source.rs` — a ceiling of ~500 patterns
  is recommended
- Review `learned-patterns.md` for duplicate or superseded entries

## Related Documentation

- [Graph-Agent Architecture](graph-agent-architecture.md) — Architecture and
  security model for graph-first agent detection
- [Gym Self-Improvement Loop](gym-self-improvement.md) — Complete reference
  for the improvement loop
- [Gym Tutorial](gym-tutorial.md) — Step-by-step walkthrough of a standard
  improvement cycle
- [Gym Agents](gym-agents.md) — Agent card format and tool definitions
- [Gym Safety Hardening](gym-safety-hardening.md) — Security controls for
  LLM-generated proposals
- [Gym API Reference](gym-api-reference.md) — Internal Rust API types
- [Gym Configuration](gym-configuration.md) — All configuration options
