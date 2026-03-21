# Gym Safety Hardening

Defense-in-depth controls that protect the improvement loop from LLM-generated
proposals that could introduce ReDoS, code injection, or overfitting.

## Regex Size Limits

All LLM-proposed regex patterns are compiled with a size limit to prevent
catastrophic resource consumption. Even though the `regex` crate guarantees
linear-time matching (no backtracking), unbounded NFA construction can still
exhaust memory.

```rust
use regex::RegexBuilder;

let re = RegexBuilder::new(&proposed_pattern)
    .size_limit(200_000)
    .build()?;
```

The 10,000-byte NFA size limit is enforced in two locations:

| Location | File | Purpose |
|----------|------|---------|
| Pattern compilation | `crates/core/src/analysis/patterns_source.rs` | Runtime pattern loading |
| Proposal application | `crates/gym/src/improve.rs` | Validating LLM-proposed patterns before commit |

Patterns exceeding the limit are rejected with a clear error and the proposal
is marked as failed — the cycle continues with remaining proposals.

### Why 10,000 bytes?

The largest legitimate pattern in the codebase compiles to ~2,500 bytes of NFA.
A 4x headroom accommodates complex but valid patterns while blocking
pathological constructs (deeply nested alternations, excessive character
classes) that LLMs occasionally generate.

## Structured Pattern Insertion

LLM output is never interpolated directly into Rust source code. The
`apply_accepted_proposals()` function constructs `SourcePattern` entries using
typed struct fields:

```rust
// Correct: structured insertion
let pattern = SourcePattern {
    regex: &validated_regex,
    category: DangerCategory::from_str(&proposal.category)?,
    severity: Severity::from_str(&proposal.severity)?,
    reason: &proposal.reason,
};

// NEVER: format!() interpolation of LLM strings into source
// format!("SourcePattern {{ regex: r\"{}\", ... }}", llm_output)  // ← prohibited
```

This prevents:
- Rust syntax injection via crafted regex strings containing `}`
- Arbitrary code execution via `reason` fields with embedded expressions
- Malformed pattern entries that would cause compile errors

The find/replace `Patch` mechanism uses exact string matching on the target
file. If the `find` string is not present, the patch is silently skipped —
partial matches never occur.

## CLI Argument Validation

The `gym improve` and `gym eval` commands enforce range constraints on
numeric arguments to prevent resource exhaustion or degenerate configurations:

| Argument | Range | Default | Rationale |
|----------|-------|---------|-----------|
| `--holdout-fraction` | (0.0, 0.5] | 0.2 | >0 ensures validation set exists; ≤0.5 ensures enough training data |
| `--max-improvements` | [1, 10] | 5 | Caps per-cycle churn; prevents runaway pattern accumulation |
| `--timeout` | [5, 600] seconds | 120 | Prevents accidental zero-timeout or multi-hour hangs |
| `--max-cases` | [1, 50] | 20 | Bounds token spend per cycle |
| `--procs` | [1, 50] | 5 | Prevents fork-bombing the host |
| `-j` / `--concurrency` | [1, 16] | 2 | Limits async task pressure on LLM backend |

Out-of-range values produce an immediate error with the valid range displayed:

```
error: holdout-fraction must be in (0.0, 0.5], got 0.8
```

## Regression Gate

The 2% regression gate (`CWE_REGRESSION_NOISE_MARGIN = 0.02`) is treated as a
security control, not a tunable parameter. It is enforced automatically after
every improvement cycle and cannot be bypassed via CLI flags.

Three conditions must hold for proposals to be accepted:

1. **F1 must not decrease** (any drop → rollback)
2. **Precision drop ≤ 2%** (prevents trading precision for recall)
3. **No per-CWE detection rate regresses > 2%** (prevents robbing Peter to pay Paul)

If any condition fails, `gym compare` reports the regression and all patches
from the cycle are reverted.

## Path Validation

Fixture `path` and `binary_path` fields in TOML manifests are validated:

- Must be relative paths (no leading `/`)
- Must not contain `..` segments
- Are canonicalized and checked against the allowed data directory

This prevents a malicious or corrupted TOML manifest from reading files
outside the benchmark data directory.

## SQL Safety

The history database (`rusqlite`) uses parameterized queries exclusively:

```rust
// Correct: parameterized
conn.execute("INSERT INTO runs (suite, f1) VALUES (?1, ?2)", params![suite, f1])?;

// NEVER: format!() SQL
// conn.execute(&format!("INSERT INTO runs (suite) VALUES ('{}')", suite), [])?;
```

## API Key Hygiene

API keys (`ANTHROPIC_API_KEY`, GitHub Copilot tokens) are:

- Read from environment variables only
- Never included in `tracing` spans or structured logs
- Never written to the SQLite history database
- Never appended to knowledge files (`fn-insights.md`, `learned-patterns.md`)
- Excluded from error messages (connection errors redact the token)

## Token Budget Defense-in-Depth

Even with per-case budgets, a total cycle cap of **3M tokens** prevents
runaway spending if the LLM generates unusually verbose responses:

| Budget Layer | Limit | Scope |
|-------------|-------|-------|
| Per-case target | 50,000 tokens | Normal analysis |
| Per-case hard cap | 100,000 tokens | Aborts case analysis |
| Per-cycle total | 3,000,000 tokens | Aborts entire cycle |
| KB snippet length | 700 chars | Per knowledge base hit |
| KB queries per cycle | 6 CWE + 2 fixed | Total KB lookups |

## Knowledge File Growth Control

Knowledge files (`fn-insights.md`, `learned-patterns.md`) are capped at 50KB
per write operation. If a cycle would push a file past this limit, the oldest
entries are truncated to make room. This prevents unbounded growth across
hundreds of improvement cycles.

## Overfitting Mitigation

Multiple layers prevent the improvement loop from overfitting to the benchmark
suite:

1. **Holdout validation** — 20% of cases are reserved and never shown to the
   failure analyst. Post-cycle benchmarks run on the full set.
2. **Overfitting reviewer agent** — Every proposal is reviewed for real-world
   applicability before acceptance.
3. **Per-cycle proposal cap** — Maximum 5 accepted proposals per cycle (configurable
   to 10 via `--max-improvements`).
4. **Cross-validation** — After a fixtures cycle, running `gym eval --suites
   juliet,owasp` verifies patterns generalize to other suites.
5. **Single-cycle design** — Each invocation runs exactly one cycle. Compound
   overfitting from automated multi-cycle loops is prevented by requiring
   explicit re-invocation.
