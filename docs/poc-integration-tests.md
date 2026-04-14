# PoC System Integration Tests

Integration test suite for the Proof-of-Compromise (PoC) system. These tests
validate the full disagree → prove → adjudicate flow and document known bugs
with regression-preventing assertions.

**Location:** `crates/gym/tests/poc_integration_test.rs`

## Running the Tests

```bash
# Run only PoC integration tests
cargo test --test poc_integration_test

# Run with output visible (useful for debugging)
cargo test --test poc_integration_test -- --nocapture

# Run a specific test group
cargo test --test poc_integration_test score      # Group A: scoring
cargo test --test poc_integration_test disagree   # Group B: DB CRUD
cargo test --test poc_integration_test c1_fk      # Group C: FK bug
cargo test --test poc_integration_test prove      # Group D: full flow
```

All tests run against ephemeral databases (in-memory or tempfile-backed) and
require no external services.

## Test Groups

### Group A: Evidence Scoring (4 tests)

Pure-function tests for `score_evidence()`. No database required.

| Test | Asserts |
|------|---------|
| `score_empty_evidence_is_inconclusive` | Empty evidence → `Insufficient` / `Inconclusive` |
| `score_disproof_wins_over_proof` | Disproof-first: any sanitizer evidence overrides proof |
| `score_strong_proof_is_proven` | 4+ proof items → `Strong` / `Proven` |
| `score_moderate_proof_is_proven` | 3 proof items → `Moderate` / `Proven` |

These tests validate the deterministic scoring logic that the PoC system uses
to adjudicate disagreements. The disproof-first protocol means a single
sanitizer evidence item outweighs any amount of proof evidence.

### Group B: DB CRUD Round-Trips (2 tests)

End-to-end validation of `HistoryDb` disagreement lifecycle.

| Test | Asserts |
|------|---------|
| `disagree_insert_and_pending_round_trip` | Insert disagreement → appears in `pending_disagreements()` |
| `adjudicate_removes_from_pending` | After `adjudicate_disagreement()` → no longer pending |

### Group C: FK Violation Bug — C1 (2 tests)

These tests document **bug C1**: `insert_poc_result()` fabricates
`disagreement_id` as `"bd-{case_id}-{cwe}"` (history.rs:741) instead of
using the actual disagreement record's ID. With foreign key enforcement
enabled, this causes a constraint violation when the disagreement ID doesn't
match the fabricated format.

| Test | Asserts |
|------|---------|
| `c1_fk_violation_on_insert_poc_result` | File-backed DB (`open()`) → FK error |
| `c1_fk_violation_also_in_memory` | In-memory DB → FK error (SQLite compiled with `SQLITE_DEFAULT_FOREIGN_KEYS=1`) |

**Why two paths?** `HistoryDb::open()` explicitly sets `PRAGMA foreign_keys=ON`.
`HistoryDb::in_memory()` does not — but the SQLite build used by rusqlite has
`SQLITE_DEFAULT_FOREIGN_KEYS=1`, so both paths enforce FK constraints. These
tests verify the bug manifests on both paths and will detect if the SQLite
build flags change.

**When C1 is fixed**, these tests should be updated: the FK violation assertions
become passing-insert assertions, and the tests should verify the inserted
`poc_results` row references the correct disagreement.

### Group D: Full Flow — prove_pending (2 tests)

End-to-end tests of the `prove_pending()` orchestrator.

| Test | Asserts |
|------|---------|
| `prove_pending_dry_run_skips_db_write` | dry_run=true → summary counts correct, DB unchanged |
| `prove_pending_non_dry_run_hits_fk_bug` | dry_run=false with UUID-style disagreement ID → FK error |

The dry-run test also documents **M4** (all strategies are stubs): every case
produces `Inconclusive` because all CWE-specific proof strategies return
empty evidence vectors.

## Known Bugs Covered

| ID | Severity | Description | Test(s) |
|----|----------|-------------|---------|
| C1 | Critical | `insert_poc_result` fabricates disagreement_id instead of using actual ID | `c1_fk_violation_on_insert_poc_result`, `c1_fk_violation_also_in_memory`, `prove_pending_non_dry_run_hits_fk_bug` |
| H2 | High | `--case-id` CLI argument silently ignored (`_case_id` prefix) | Documented in comments (CLI-level, not unit-testable) |
| M4 | Medium | All proof strategies are stubs returning empty evidence | `prove_pending_dry_run_skips_db_write` (asserts all Inconclusive) |

## API Reference

### Types Used

```rust
use skwaq_gym::history::{DisagreementRecord, HistoryDb, RunMetadata};
use skwaq_gym::poc::{
    prove_pending, score_evidence,
    Evidence, EvidenceKind, EvidenceScore,
    PocVerdict, ProofOfCompromise, ProveConfig,
};
```

### `score_evidence(disproof: &[Evidence], proof: &[Evidence]) -> (EvidenceScore, PocVerdict)`

Deterministic scoring function. Disproof-first protocol:
1. If any disproof evidence exists → `(Disproven, Disproven)`
2. If 4+ proof items → `(Strong, Proven)`
3. If 3 proof items → `(Moderate, Proven)`
4. Otherwise → `(Insufficient, Inconclusive)`

### `prove_pending(history: &HistoryDb, run_id: &str, config: &ProveConfig) -> Result<ProveSummary>`

Iterates all pending disagreements for `run_id`, runs CWE-specific proof
strategies, scores evidence, and optionally writes results to the database.

**`ProveConfig` fields:**
- `dry_run: bool` — When true, skips `insert_poc_result()` and `adjudicate_disagreement()`.
- `min_score_for_auto: EvidenceScore` — Minimum evidence score for auto-adjudication (default: `Moderate`).
- `max_cases: Option<usize>` — Maximum BD cases to prove in one batch (default: `None` = all).

### `HistoryDb::in_memory() -> Result<HistoryDb>`

Creates an ephemeral in-memory database with full schema. FK enforcement is
active due to `SQLITE_DEFAULT_FOREIGN_KEYS=1` in the SQLite build.

### `HistoryDb::open(path: &Path) -> Result<HistoryDb>`

Opens a file-backed database. Explicitly sets `PRAGMA foreign_keys=ON`.

## Adding New Tests

When implementing a proof strategy (fixing M4), add tests following this pattern:

```rust
#[test]
fn strategy_injection_produces_evidence() {
    let (db, run_id) = setup_db_with_disagreement();
    // Change the CWE to match the strategy under test
    let record = make_disagreement(&run_id, "sqli-case", 89);
    db.insert_disagreement(&record).expect("insert");

    let config = ProveConfig {
        dry_run: true,
        ..Default::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove");
    // After strategy implementation, this should produce evidence:
    assert!(summary.proven > 0 || summary.disproven > 0,
        "Implemented strategy should produce a definitive verdict");
}
```

When fixing C1 (FK bug), update the Group C tests:

```rust
#[test]
fn insert_poc_result_uses_actual_disagreement_id() {
    let (db, run_id) = setup_db_with_disagreement();
    let poc = ProofOfCompromise { /* ... */ };
    // After fix: should succeed, not FK-violate
    db.insert_poc_result(&poc).expect("insert should succeed after C1 fix");
}
```

## CI Integration

These tests run as part of `cargo test --all` in CI. No additional
configuration is needed — all tests use ephemeral databases and have no
external dependencies.

```yaml
# In .github/workflows/ci.yml (already included via cargo test --all)
- name: Run tests
  run: cargo test --all
```
