//! Integration tests for the Proof-of-Compromise (PoC) system.
//!
//! These tests exercise the full disagree → prove → adjudicate flow and document
//! three known bugs:
//!
//! - **C1 (Critical)**: `insert_poc_result` fabricates `disagreement_id` as
//!   `"bd-{case_id}-{cwe}"` but actual disagreement IDs are user-provided strings.
//!   FK enforcement is active on both `HistoryDb::open` and `HistoryDb::in_memory`,
//!   so non-dry-run `prove_pending` always fails with an FK constraint violation.
//!
//! - **H2 (High)**: The `--case-id` CLI argument in `skwaq gym prove` is bound to
//!   `_case_id` and silently ignored. (CLI-level; documented here, not directly testable.)
//!
//! - **M4 (Medium)**: All proof strategies are stubs returning empty evidence vectors,
//!   so every case produces `PocVerdict::Inconclusive`.

use skwaq_gym::history::{DisagreementRecord, HistoryDb, RunMetadata};
use skwaq_gym::poc::{
    prove_pending, score_evidence, Evidence, EvidenceKind, EvidenceScore, PocVerdict, ProveConfig,
};
use std::time::Duration;
use tempfile::NamedTempFile;

/// Helper: create a HistoryDb backed by a temp file (FK enforcement ON).
fn open_temp_db() -> (HistoryDb, NamedTempFile) {
    let tmp = NamedTempFile::new().expect("failed to create temp file");
    let db = HistoryDb::open(tmp.path()).expect("failed to open HistoryDb");
    (db, tmp)
}

/// Helper: insert a run and return its ID.
fn insert_run(db: &HistoryDb) -> String {
    let meta = RunMetadata::default();
    db.start_run("test-suite", "abc123", &meta)
        .expect("start_run failed")
}

/// Helper: insert a disagreement with a known ID.
fn insert_disagreement(db: &HistoryDb, run_id: &str, disagree_id: &str, case_id: &str, cwe: u32) {
    let record = DisagreementRecord {
        id: disagree_id.to_string(),
        run_id: run_id.to_string(),
        suite: "test-suite".to_string(),
        case_id: case_id.to_string(),
        detected_cwes: format!("[{}]", cwe),
        finding_id: "finding-001".to_string(),
        adjudication: None,
        adjudicated_at: None,
        adjudicated_by: None,
    };
    db.insert_disagreement(&record)
        .expect("insert_disagreement failed");
}

// ---------------------------------------------------------------------------
// H1: Strategies now produce real evidence (no longer stubs)
// ---------------------------------------------------------------------------

#[test]
fn h1_strategies_produce_evidence() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);
    insert_disagreement(&db, &run_id, "disagree-m4-1", "case-001", 89);
    insert_disagreement(&db, &run_id, "disagree-m4-2", "case-002", 79);
    insert_disagreement(&db, &run_id, "disagree-m4-3", "case-003", 22);

    let config = ProveConfig {
        dry_run: true,
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending failed");

    assert_eq!(summary.total_cases, 3, "should process all 3 disagreements");
    // Strategies now produce real evidence — cases should not all be Inconclusive
    assert_eq!(summary.failed, 0, "no cases should fail");
    assert_eq!(summary.results.len(), 3, "all 3 cases should have results");
    // Each result should have non-empty evidence from the implemented strategies
    for result in &summary.results {
        let has_evidence =
            !result.disproof_evidence.is_empty() || !result.proof_evidence.is_empty();
        assert!(
            has_evidence,
            "H1: strategy for CWE-{} should produce evidence, got empty",
            result.cwe
        );
    }
}

// ---------------------------------------------------------------------------
// C1: FK constraint violation — insert_poc_result uses fabricated disagreement_id
// ---------------------------------------------------------------------------

#[test]
fn c1_fixed_real_disagreement_id_used() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);

    // Insert disagreement with ID "disagree-c1"
    insert_disagreement(&db, &run_id, "disagree-c1", "case-fk", 89);

    // Non-dry-run: prove_pending now passes the real disagreement_id
    // to insert_poc_result, so the FK constraint is satisfied.
    let config = ProveConfig {
        dry_run: false,
        ..ProveConfig::default()
    };

    let result = prove_pending(&db, &run_id, &config);
    assert!(
        result.is_ok(),
        "C1 fix: insert_poc_result should use real disagreement_id and succeed, got: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// dry_run=true skips DB writes (no FK error, no adjudication stored)
// ---------------------------------------------------------------------------

#[test]
fn dry_run_skips_db_writes() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);
    insert_disagreement(&db, &run_id, "disagree-dry", "case-dry", 79);

    let config = ProveConfig {
        dry_run: true,
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("dry_run should succeed");
    assert_eq!(summary.total_cases, 1);
    assert_eq!(summary.auto_adjudicated, 0, "dry_run must not adjudicate");

    // The disagreement should still be pending (no adjudication written)
    let pending = db
        .pending_disagreements(&run_id)
        .expect("pending_disagreements failed");
    assert_eq!(
        pending.len(),
        1,
        "disagreement should remain pending after dry_run"
    );
    assert!(pending[0].adjudication.is_none());
}

// ---------------------------------------------------------------------------
// Happy-path: verify adjudication logic using dry_run
// ---------------------------------------------------------------------------

#[test]
fn happy_path_adjudication_dry_run() {
    // Due to C1 (FK bug), non-dry-run always fails. Use dry_run to test the
    // summary/verdict logic in isolation.
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);
    insert_disagreement(&db, &run_id, "disagree-happy", "case-happy", 89);

    let config = ProveConfig {
        dry_run: true,
        min_score_for_auto: EvidenceScore::Moderate,
        max_cases: None,
        case_id: None,
        timeout: None,
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending failed");
    assert_eq!(summary.total_cases, 1);

    // dry_run skips insert_poc_result and adjudication writes
    assert_eq!(
        summary.auto_adjudicated, 0,
        "dry_run must not auto-adjudicate"
    );

    // Disagreement should still be pending
    let pending = db
        .pending_disagreements(&run_id)
        .expect("pending_disagreements failed");
    assert_eq!(pending.len(), 1, "disagreement should remain pending");

    // Strategies are now implemented, so results reflect actual analysis
    let total = summary.proven + summary.disproven + summary.inconclusive;
    assert_eq!(total, 1, "exactly one result expected");
    assert_eq!(summary.results.len(), 1);
}

// ---------------------------------------------------------------------------
// max_cases limits the number of cases processed
// ---------------------------------------------------------------------------

#[test]
fn max_cases_limits_batch_size() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);
    insert_disagreement(&db, &run_id, "d-1", "case-1", 89);
    insert_disagreement(&db, &run_id, "d-2", "case-2", 79);
    insert_disagreement(&db, &run_id, "d-3", "case-3", 22);

    let config = ProveConfig {
        dry_run: true,
        max_cases: Some(2),
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending failed");
    assert_eq!(summary.total_cases, 2, "max_cases should limit to 2");
}

// ---------------------------------------------------------------------------
// No pending disagreements → empty summary
// ---------------------------------------------------------------------------

#[test]
fn no_pending_disagreements_produces_empty_summary() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);

    let config = ProveConfig {
        dry_run: true,
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending failed");
    assert_eq!(summary.total_cases, 0);
    assert_eq!(summary.proven, 0);
    assert_eq!(summary.disproven, 0);
    assert_eq!(summary.inconclusive, 0);
    assert!(summary.results.is_empty());
}

// ---------------------------------------------------------------------------
// score_evidence unit tests (deterministic scoring logic)
// ---------------------------------------------------------------------------

#[test]
fn score_evidence_empty_is_inconclusive() {
    let (score, verdict) = score_evidence(&[], &[]);
    assert_eq!(score, EvidenceScore::Insufficient);
    assert_eq!(verdict, PocVerdict::Inconclusive);
}

#[test]
fn score_evidence_disproof_wins() {
    let disproof = vec![Evidence {
        kind: EvidenceKind::Sanitizer,
        description: "Input sanitized".into(),
        location: "src/lib.rs:10".into(),
        tool_output: "found htmlspecialchars()".into(),
    }];
    let proof = vec![Evidence {
        kind: EvidenceKind::TaintPath,
        description: "taint from input to sink".into(),
        location: "src/lib.rs:20".into(),
        tool_output: "user_input -> query".into(),
    }];

    let (score, verdict) = score_evidence(&disproof, &proof);
    assert_eq!(score, EvidenceScore::Disproven);
    assert_eq!(verdict, PocVerdict::Disproven);
}

#[test]
fn score_evidence_strong_proof() {
    let proof = vec![
        Evidence {
            kind: EvidenceKind::TaintPath,
            description: "taint path".into(),
            location: "a.rs:1".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::DataFlowSource,
            description: "source".into(),
            location: "a.rs:2".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::PatternMatch,
            description: "pattern".into(),
            location: "a.rs:3".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::CallChain,
            description: "chain".into(),
            location: "a.rs:4".into(),
            tool_output: "".into(),
        },
    ];

    let (score, verdict) = score_evidence(&[], &proof);
    assert_eq!(score, EvidenceScore::Strong);
    assert_eq!(verdict, PocVerdict::Proven);
}

// ---------------------------------------------------------------------------
// FK gap: in_memory vs open — document the enforcement difference
// ---------------------------------------------------------------------------

/// C1 fix verified with in_memory DB — FK enforcement is active and
/// the fix correctly uses the real disagreement_id.
#[test]
fn c1_fixed_also_in_memory() {
    let db = HistoryDb::in_memory().expect("in_memory failed");
    let run_id = insert_run(&db);
    insert_disagreement(&db, &run_id, "d-inmem", "case-inmem", 89);

    let config = ProveConfig {
        dry_run: false,
        ..ProveConfig::default()
    };
    let result = prove_pending(&db, &run_id, &config);
    assert!(
        result.is_ok(),
        "C1 fix: should succeed with real disagreement_id in in_memory DB, got: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// H3: Validation failure paths — malformed and empty CWE data
// ---------------------------------------------------------------------------

#[test]
fn h3_malformed_cwe_json_fails() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);

    // Insert a disagreement with malformed detected_cwes JSON
    let record = DisagreementRecord {
        id: "disagree-malformed".to_string(),
        run_id: run_id.clone(),
        suite: "test-suite".to_string(),
        case_id: "case-malformed".to_string(),
        detected_cwes: "not-valid-json".to_string(),
        finding_id: "finding-001".to_string(),
        adjudication: None,
        adjudicated_at: None,
        adjudicated_by: None,
    };
    db.insert_disagreement(&record)
        .expect("insert_disagreement failed");

    let config = ProveConfig {
        dry_run: true,
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending should not abort");
    // The malformed case should fail (not crash the batch)
    assert_eq!(
        summary.failed, 1,
        "malformed CWE JSON should cause case failure"
    );
}

#[test]
fn h3_empty_cwe_list_fails() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);

    // Insert a disagreement with empty CWE list
    let record = DisagreementRecord {
        id: "disagree-empty-cwe".to_string(),
        run_id: run_id.clone(),
        suite: "test-suite".to_string(),
        case_id: "case-empty-cwe".to_string(),
        detected_cwes: "[]".to_string(),
        finding_id: "finding-001".to_string(),
        adjudication: None,
        adjudicated_at: None,
        adjudicated_by: None,
    };
    db.insert_disagreement(&record)
        .expect("insert_disagreement failed");

    let config = ProveConfig {
        dry_run: true,
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending should not abort");
    assert_eq!(
        summary.failed, 1,
        "empty CWE list should cause case failure"
    );
}

// ---------------------------------------------------------------------------
// M1: Evidence deduplication — duplicate evidence should not inflate score
// ---------------------------------------------------------------------------

#[test]
fn m1_duplicate_evidence_not_double_counted() {
    let dup_proof = vec![
        Evidence {
            kind: EvidenceKind::TaintPath,
            description: "same taint".into(),
            location: "a.rs:1".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::TaintPath,
            description: "same taint".into(),
            location: "a.rs:1".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::DataFlowSource,
            description: "same source".into(),
            location: "a.rs:2".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::DataFlowSource,
            description: "same source".into(),
            location: "a.rs:2".into(),
            tool_output: "".into(),
        },
    ];

    let (score, verdict) = score_evidence(&[], &dup_proof);
    // Only 2 unique evidence items → score=2 → Insufficient/Inconclusive
    assert_eq!(score, EvidenceScore::Insufficient);
    assert_eq!(verdict, PocVerdict::Inconclusive);
}

#[test]
fn m1_unique_evidence_still_scored() {
    let unique_proof = vec![
        Evidence {
            kind: EvidenceKind::TaintPath,
            description: "taint A".into(),
            location: "a.rs:1".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::TaintPath,
            description: "taint B".into(),
            location: "b.rs:1".into(),
            tool_output: "".into(),
        },
        Evidence {
            kind: EvidenceKind::DataFlowSource,
            description: "source".into(),
            location: "c.rs:1".into(),
            tool_output: "".into(),
        },
    ];

    let (score, verdict) = score_evidence(&[], &unique_proof);
    // 3 unique items → score=3 → Moderate/Proven
    assert_eq!(score, EvidenceScore::Moderate);
    assert_eq!(verdict, PocVerdict::Proven);
}

// ---------------------------------------------------------------------------
// M4: Timeout stops batch before all cases processed
// ---------------------------------------------------------------------------

#[test]
fn m4_timeout_stops_batch() {
    let (db, _tmp) = open_temp_db();
    let run_id = insert_run(&db);
    // Insert many cases
    for i in 0..10 {
        insert_disagreement(
            &db,
            &run_id,
            &format!("d-timeout-{i}"),
            &format!("case-timeout-{i}"),
            89,
        );
    }

    let config = ProveConfig {
        dry_run: true,
        timeout: Some(Duration::ZERO), // Immediate timeout
        ..ProveConfig::default()
    };

    let summary = prove_pending(&db, &run_id, &config).expect("prove_pending should not abort");
    // With zero timeout, no cases should be processed
    assert_eq!(
        summary.total_cases, 0,
        "zero timeout should process no cases"
    );
}
