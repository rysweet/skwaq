# Gym Configuration Reference

Complete reference for configuring the skwaq gym benchmark and improvement
system.

## LLM Backend

The gym uses the same LLM configuration as the rest of skwaq. The
failure-analyst and overfitting-reviewer agents require an Opus-class model.

```toml
[llm]
reasoning = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
```

Supported backends:

| Backend | Config Value | Auth |
|---------|-------------|------|
| GitHub Copilot | `"copilot"` | `gh auth login` |
| Anthropic API | `"anthropic"` | `ANTHROPIC_API_KEY` env var |

Run `skwaq gym preflight` to verify connectivity, model availability, and
no-fallback readiness before starting an improvement cycle.

## BenchmarkConfig Fields

The `BenchmarkConfig` struct controls all benchmark and improvement behavior.
CLI flags map directly to these fields:

| Field | CLI Flag | Type | Default | Range | Description |
|-------|----------|------|---------|-------|-------------|
| `quick_mode` | `--quick` | bool | false | — | Pattern-only analysis (no LLM agents) |
| `llm_only` | `--llm-only` | bool | false | — | LLM agents only (no pattern detection) |
| `cwe_filter` | `--cwe` | Vec\<u32\> | all | — | Filter to specific CWE IDs |
| `max_cases` | `--max-cases` | usize | 20 | [1, 50] | Maximum cases per suite |
| `parallelism` | `--procs` | usize | 5 | [1, 50] | Parallel processes per suite |
| `concurrency` | `-j` | usize | 2 | [1, 16] | In-process async concurrency |
| `timeout_secs` | `--timeout` | u64 | 120 | [5, 600] | Per-case timeout in seconds |
| `holdout_fraction` | `--holdout-fraction` | f64 | 0.2 | (0.0, 0.5] | Fraction reserved for validation |
| `max_improvements_per_cycle` | `--max-improvements` | usize | 5 | [1, 10] | Cap on accepted proposals |
| `skip` | `--skip` | usize | 0 | — | Skip first N cases (for sharding) |
| `binary_mode` | `--source-only` (inverted) | bool | true | — | Include binary analysis |

`--quick` and `--llm-only` are mutually exclusive. Specifying both produces an
error.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | If `reasoning = "anthropic"` | Anthropic API key |
| `GHIDRA_INSTALL_DIR` | For binary analysis suites | Path to Ghidra installation |
| `SKWAQ_GYM_DATA` | No | Override default data directory (`data/gym/`) |
| `RUST_LOG` | No | Tracing filter (e.g., `skwaq_gym=debug`) |

API keys are read from environment variables only — never logged, stored in
the database, or written to knowledge files.

## Token Budgets

| Parameter | Value | Scope |
|-----------|-------|-------|
| Per-case target budget | 50,000 tokens | Failure analyst per FN case |
| Per-case hard cap | 100,000 tokens | Aborts analysis if exceeded |
| Total cycle cap | 3,000,000 tokens | Defense-in-depth cycle limit |
| KB snippet length | 700 chars | Per knowledge base search hit |
| KB CWE queries per cycle | 6 | Knowledge base CWE lookups |
| KB results per query | 2 | Hits returned per lookup |
| KB fixed queries | `["methodology", "cwe-families"]` | Always-queried topics |

## Analysis Context Budgets

The agent analysis context has a total 100K character limit, split across
six sections. Empty sections are omitted entirely:

| Section | Budget | Row Limit | Description |
|---------|--------|-----------|-------------|
| Functions | 10K chars | — | Function names and addresses |
| Imports & Symbols | 5K chars | 50 rows | `symbols` table entries |
| Data Sources | 3K chars | 30 rows | `data_sources` table entries |
| Cross-File Call Graph | 8K chars | 40 paths | 2-hop cross-file call chains |
| String References | 4K chars | 30 strings | String literals referenced by functions |
| Source Code | 30K chars | — | Raw source with line numbers |

These are compile-time constants. The source code budget was reduced from
40K to 30K to accommodate the graph context sections (~20K total).

## Regression Gate Thresholds

These are compile-time constants, not configurable at runtime — they are
treated as security controls:

| Constant | Value | Location |
|----------|-------|----------|
| `CWE_REGRESSION_NOISE_MARGIN` | 0.02 (2%) | `scoring.rs` |
| F1 regression tolerance | 0 (any drop fails) | `improve.rs` |
| Precision regression tolerance | 0.02 (2%) | `improve.rs` |

## Pattern Compilation

LLM-proposed regex patterns are compiled with safety limits:

| Parameter | Value | Description |
|-----------|-------|-------------|
| NFA size limit | 10,000 bytes | `RegexBuilder::size_limit()` |
| Regex engine | `regex` crate | Linear-time guarantee, no backtracking |

Patterns exceeding the size limit are rejected and the proposal is skipped.

## Benchmark Suites

Suites are defined by TOML manifests in `data/gym/ground_truth/`:

| Suite | Manifest | Cases | Languages | Description |
|-------|----------|-------|-----------|-------------|
| `fixtures` | `fixtures.toml` | ~99 | C, C++, Python, JS | Pre-bundled test cases (65 CSE + 12 CGC + original) |
| `juliet` | `juliet.toml` | ~200+ | C, Java | NIST Juliet Test Suite |
| `owasp` | `owasp.toml` | ~2700 | Java | OWASP Benchmark (web) |
| `cgc` | `cgc.toml` | ~130 | C | DARPA Cyber Grand Challenge |
| `cyberseceval` | `cyberseceval.toml` | varies | Python | Anthropic CyberSecEval |
| `realworld` | `realworld.toml` | varies | mixed | Real-world CVE reproductions |
| `binpool` | `binpool.toml` | ~150 | — | Binary-only (requires download) |
| `cybergym` | `cybergym.toml` | varies | C | CyberGym (with patch diffs) |

### Fixture TOML Schema

```toml
suite = "fixtures"
version = "3.0"
download_url = ""
download_sha256 = ""

[[cases]]
id = "buffer_overflow"            # Unique case ID
path = "buffer_overflow.c"        # Relative source path (no ../ allowed)
binary_path = "binaries/bo_O0"    # Optional compiled binary
expected_cwes = [121, 134]        # Expected CWE IDs
is_negative = false               # true = patched/safe, false = vulnerable
language = "c"                    # c, cpp, java, python, javascript
```

Path fields are validated at load time: absolute paths and `..` traversals
are rejected.

## Knowledge Files

The improvement loop reads and writes two knowledge files:

| File | Purpose | Growth control |
|------|---------|---------------|
| `data/knowledge/fn-insights.md` | Per-case false negative analysis log | 50KB cap per write |
| `data/knowledge/learned-patterns.md` | Pattern discoveries across cycles | 50KB cap per write |

These serve as persistent memory for the failure-analyst agent, preventing
re-proposal of previously rejected ideas and duplication of existing patterns.

Additional read-only knowledge files queried during analysis:

| File | Purpose |
|------|---------|
| `data/knowledge/cwe-families.md` | CWE family reference with detection signals |
| `data/knowledge/vuln-analysis-methodology.md` | 10-step evaluation methodology |
| `data/knowledge/research-approaches.md` | CodeQL and symbolic execution patterns |
| `data/knowledge/codeql-variant-analysis.md` | CodeQL dataflow templates |

## Agent Configuration

Improvement loop agents are defined in `agents/`:

| Agent | File | Model | Max Turns | Role |
|-------|------|-------|-----------|------|
| failure-analyst | `agents/failure-analyst.md` | claude-opus-4.6 | 25 | Diagnose false negatives |
| overfitting-reviewer | `agents/overfitting-reviewer.md` | claude-opus-4.6 | 25 | Gate proposals for quality |

Agent cards use YAML frontmatter for configuration:

```yaml
---
name: failure-analyst
description: Analyzes why vulnerabilities were missed
model: claude-opus-4.6
tools:
  - query_graph
  - read_function
  - lookup_cwe
  - lookup_knowledge
  - search_similar
  - store_memory
  - recall_memory
max_turns: 25
---
```

## History Database

Benchmark run history is stored in a SQLite database at
`data/gym/history.db`. This database is `.gitignore`d and contains:

- Run timestamps and suite identifiers
- Aggregate scores (F1, precision, recall)
- Per-CWE detection rates
- Per-case outcomes (for `case-diff` and `compare`)

The database uses parameterized queries exclusively — no string interpolation.

When using `--profile`, the history database is located at
`~/.skwaq/profiles/<name>/results.db` instead. See [Gym Model
Profiles](gym-profiles.md) for details.

## Model Profiles

Profiles provide isolated environments for comparing different LLM backends
and models. Each profile gets its own `results.db`, `memory_graph/`, and
`telemetry/` directories while sharing the binary, agent prompts, ground
truth, and benchmark cache.

```bash
# Create and use a profile
skwaq gym profile create opus --backend copilot --model claude-opus-4.6
skwaq gym eval --suites fixtures --profile opus
```

A profile's `config.toml` contains only `[llm]` section overrides. During
loading, the profile's LLM config replaces the base `skwaq.toml` LLM config
entirely.

For the full reference, see [Gym Model Profiles](gym-profiles.md).
