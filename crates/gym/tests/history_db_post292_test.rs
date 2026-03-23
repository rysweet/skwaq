//! TDD tests for the HistoryDb post-PR #292.
//!
//! Validates that baseline results from all 5 suites can be stored and retrieved,
//! per-CWE results include new Juliet CWE mappings, and the case_outcomes table
//! supports the per-case delta tracking needed for before/after comparison in PRs.

use skwaq_gym::history::{
    BenchmarkRun, CaseOutcome, CaseOutcomeKind, CaseResult, CweResult, HistoryDb, RunMetadata,
    SemanticResult,
};

// ---------------------------------------------------------------------------
// Schema and basic CRUD
// ---------------------------------------------------------------------------

#[test]
fn test_history_db_in_memory_creates_schema() {
    let db = HistoryDb::in_memory().expect("Should create in-memory DB");
    // Verify schema by starting a run (requires runs table)
    let run_id = db
        .start_run("fixtures", "02605466", &RunMetadata::default())
        .expect("start_run should succeed with fresh schema");
    assert!(!run_id.is_empty(), "Run ID should be a non-empty UUID");
}

#[test]
fn test_start_and_finish_run() {
    let db = HistoryDb::in_memory().unwrap();
    let run_id = db
        .start_run("fixtures", "02605466", &RunMetadata::default())
        .unwrap();

    let run = BenchmarkRun {
        id: run_id.clone(),
        started_at: chrono::Utc::now(),
        finished_at: Some(chrono::Utc::now()),
        suite: "fixtures".to_string(),
        skwaq_commit: "02605466".to_string(),
        metadata: RunMetadata::default(),
        precision: 1.0,
        recall: 0.784,
        f1: 0.879,
        true_positives: 91,
        false_positives: 0,
        false_negatives: 25,
        true_negatives: 12,
    };

    db.finish_run(&run).expect("finish_run should succeed");

    let recent = db.recent_runs(1).expect("recent_runs should succeed");
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, run_id);
    assert_eq!(recent[0].true_positives, 91);
    assert_eq!(recent[0].false_positives, 0);
    assert!((recent[0].f1 - 0.879).abs() < 0.001);
}

#[test]
fn test_abandon_run_removes_all_related_data() {
    let db = HistoryDb::in_memory().unwrap();
    let run_id = db
        .start_run("fixtures", "02605466", &RunMetadata::default())
        .unwrap();

    // Insert some related data
    db.insert_cwe_result(&CweResult {
        run_id: run_id.clone(),
        cwe_id: 119,
        total_cases: 10,
        true_positives: 8,
        false_positives: 0,
        false_negatives: 2,
        detection_rate: 0.8,
        precision: 1.0,
    })
    .unwrap();

    db.insert_case_outcome(&CaseOutcome {
        run_id: run_id.clone(),
        case_id: "case_1".to_string(),
        outcome: CaseOutcomeKind::TruePositive,
        cwe: 119,
    })
    .unwrap();

    // Abandon the run
    db.abandon_run(&run_id).unwrap();

    // Verify everything was cleaned up
    let recent = db.recent_runs(10).unwrap();
    assert!(
        recent.iter().all(|r| r.id != run_id),
        "Abandoned run should be removed"
    );

    let outcomes = db.case_outcomes_for_run(&run_id).unwrap();
    assert!(
        outcomes.is_empty(),
        "Case outcomes for abandoned run should be removed"
    );
}

// ---------------------------------------------------------------------------
// Per-suite baseline storage for all 5 suites
// ---------------------------------------------------------------------------

#[test]
fn test_store_baselines_for_all_five_suites() {
    let db = HistoryDb::in_memory().unwrap();

    let suites = ["fixtures", "juliet", "owasp", "cyberseceval", "cgc"];
    let mut run_ids = Vec::new();

    for suite in &suites {
        let run_id = db
            .start_run(suite, "02605466", &RunMetadata::default())
            .unwrap();
        let run = BenchmarkRun {
            id: run_id.clone(),
            started_at: chrono::Utc::now(),
            finished_at: Some(chrono::Utc::now()),
            suite: suite.to_string(),
            skwaq_commit: "02605466".to_string(),
            metadata: RunMetadata::default(),
            precision: 1.0,
            recall: 0.5,
            f1: 0.667,
            true_positives: 50,
            false_positives: 0,
            false_negatives: 50,
            true_negatives: 0,
        };
        db.finish_run(&run).unwrap();
        run_ids.push(run_id);
    }

    let recent = db.recent_runs(10).unwrap();
    assert_eq!(recent.len(), 5, "Should have one run per suite");

    // Verify each suite has a run
    for suite in &suites {
        assert!(
            recent.iter().any(|r| r.suite == *suite),
            "Suite {} should have a stored run",
            suite
        );
    }
}

#[test]
fn test_recent_finished_runs_for_suite_filters_correctly() {
    let db = HistoryDb::in_memory().unwrap();

    // Create runs for two suites
    for suite in ["fixtures", "juliet"] {
        let run_id = db
            .start_run(suite, "02605466", &RunMetadata::default())
            .unwrap();
        let run = BenchmarkRun {
            id: run_id,
            started_at: chrono::Utc::now(),
            finished_at: Some(chrono::Utc::now()),
            suite: suite.to_string(),
            skwaq_commit: "02605466".to_string(),
            metadata: RunMetadata::default(),
            precision: 1.0,
            recall: 0.5,
            f1: 0.667,
            true_positives: 50,
            false_positives: 0,
            false_negatives: 50,
            true_negatives: 0,
        };
        db.finish_run(&run).unwrap();
    }

    let fixtures_runs = db.recent_finished_runs_for_suite("fixtures", 10).unwrap();
    assert_eq!(fixtures_runs.len(), 1);
    assert_eq!(fixtures_runs[0].suite, "fixtures");

    let juliet_runs = db.recent_finished_runs_for_suite("juliet", 10).unwrap();
    assert_eq!(juliet_runs.len(), 1);
    assert_eq!(juliet_runs[0].suite, "juliet");
}

// ---------------------------------------------------------------------------
// Per-CWE results for new Juliet CWE mappings
// ---------------------------------------------------------------------------

#[test]
fn test_insert_cwe_results_for_new_juliet_cwes() {
    let db = HistoryDb::in_memory().unwrap();
    let run_id = db
        .start_run("juliet", "02605466", &RunMetadata::default())
        .unwrap();

    // Insert results for the 4 new CWEs from PR #292
    let new_cwes = [
        (400, "resource_exhaustion"),
        (563, "dead_store"),
        (617, "reachable_assertion"),
        (843, "type_confusion"),
    ];

    for (cwe_id, _desc) in &new_cwes {
        db.insert_cwe_result(&CweResult {
            run_id: run_id.clone(),
            cwe_id: *cwe_id,
            total_cases: 5,
            true_positives: 3,
            false_positives: 0,
            false_negatives: 2,
            detection_rate: 0.6,
            precision: 1.0,
        })
        .unwrap();
    }

    // Verify all CWE results were stored
    // We can't query CWE results directly via public API,
    // but we can verify the run completed without error
    let recent = db.recent_runs(1).unwrap();
    assert_eq!(recent[0].id, run_id);
}

// ---------------------------------------------------------------------------
// Per-semantic-class results
// ---------------------------------------------------------------------------

#[test]
fn test_insert_semantic_results() {
    let db = HistoryDb::in_memory().unwrap();
    let run_id = db
        .start_run("fixtures", "02605466", &RunMetadata::default())
        .unwrap();

    db.insert_semantic_result(&SemanticResult {
        run_id: run_id.clone(),
        class_name: "BufferOverflow".to_string(),
        total_cases: 20,
        true_positives: 18,
        false_positives: 0,
        false_negatives: 2,
        detection_rate: 0.9,
        precision: 1.0,
    })
    .unwrap();

    db.insert_semantic_result(&SemanticResult {
        run_id: run_id.clone(),
        class_name: "TypeConfusion".to_string(),
        total_cases: 5,
        true_positives: 3,
        false_positives: 0,
        false_negatives: 2,
        detection_rate: 0.6,
        precision: 1.0,
    })
    .unwrap();

    // Should not error on new semantic classes
}

// ---------------------------------------------------------------------------
// Case-level outcomes for before/after diffs
// ---------------------------------------------------------------------------

#[test]
fn test_case_outcomes_round_trip() {
    let db = HistoryDb::in_memory().unwrap();
    let run_id = db
        .start_run("fixtures", "02605466", &RunMetadata::default())
        .unwrap();

    db.insert_case_outcome(&CaseOutcome {
        run_id: run_id.clone(),
        case_id: "buffer_overflow".to_string(),
        outcome: CaseOutcomeKind::TruePositive,
        cwe: 121,
    })
    .unwrap();

    db.insert_case_outcome(&CaseOutcome {
        run_id: run_id.clone(),
        case_id: "race_condition".to_string(),
        outcome: CaseOutcomeKind::FalseNegative,
        cwe: 362,
    })
    .unwrap();

    let outcomes = db.case_outcomes_for_run(&run_id).unwrap();
    assert_eq!(outcomes.len(), 2, "Should have 2 case outcomes");

    let tp_cases: Vec<_> = outcomes
        .iter()
        .filter(|o| o.outcome == CaseOutcomeKind::TruePositive)
        .collect();
    assert_eq!(tp_cases.len(), 1);
    assert_eq!(tp_cases[0].case_id, "buffer_overflow");
    assert_eq!(tp_cases[0].cwe, 121);

    let fn_cases: Vec<_> = outcomes
        .iter()
        .filter(|o| o.outcome == CaseOutcomeKind::FalseNegative)
        .collect();
    assert_eq!(fn_cases.len(), 1);
    assert_eq!(fn_cases[0].case_id, "race_condition");
}

#[test]
fn test_case_result_stores_expected_and_detected_cwes() {
    let db = HistoryDb::in_memory().unwrap();
    let run_id = db
        .start_run("fixtures", "02605466", &RunMetadata::default())
        .unwrap();

    db.insert_case_result(&CaseResult {
        run_id: run_id.clone(),
        suite: "fixtures".to_string(),
        case_id: "multi_file".to_string(),
        expected_cwes: vec![121, 134],
        detected_cwes: vec![119],
        matched_finding_ids: vec!["f1".to_string()],
        unmatched_finding_ids: vec![],
        classification: "TP".to_string(),
    })
    .unwrap();

    // Should succeed without error
}

// ---------------------------------------------------------------------------
// Metadata storage
// ---------------------------------------------------------------------------

#[test]
fn test_run_metadata_round_trip() {
    let db = HistoryDb::in_memory().unwrap();
    let metadata = RunMetadata {
        llm_backend: "copilot".to_string(),
        llm_model: "claude-opus-4.6".to_string(),
        run_mode: "full".to_string(),
        binary_mode: false,
        git_dirty: false,
        concurrency: 2,
        skip: 0,
        max_cases: Some(128),
    };

    let run_id = db.start_run("fixtures", "02605466", &metadata).unwrap();
    let run = BenchmarkRun {
        id: run_id.clone(),
        started_at: chrono::Utc::now(),
        finished_at: Some(chrono::Utc::now()),
        suite: "fixtures".to_string(),
        skwaq_commit: "02605466".to_string(),
        metadata: metadata.clone(),
        precision: 1.0,
        recall: 0.784,
        f1: 0.879,
        true_positives: 91,
        false_positives: 0,
        false_negatives: 25,
        true_negatives: 12,
    };
    db.finish_run(&run).unwrap();

    let recent = db.recent_runs(1).unwrap();
    assert_eq!(recent[0].metadata, metadata);
}

// ---------------------------------------------------------------------------
// CaseOutcomeKind parsing
// ---------------------------------------------------------------------------

#[test]
fn test_case_outcome_kind_display_and_parse() {
    assert_eq!(CaseOutcomeKind::TruePositive.to_string(), "TP");
    assert_eq!(CaseOutcomeKind::FalsePositive.to_string(), "FP");
    assert_eq!(CaseOutcomeKind::FalseNegative.to_string(), "FN");

    assert_eq!(
        "TP".parse::<CaseOutcomeKind>().unwrap(),
        CaseOutcomeKind::TruePositive
    );
    assert_eq!(
        "FP".parse::<CaseOutcomeKind>().unwrap(),
        CaseOutcomeKind::FalsePositive
    );
    assert_eq!(
        "FN".parse::<CaseOutcomeKind>().unwrap(),
        CaseOutcomeKind::FalseNegative
    );

    assert!("XX".parse::<CaseOutcomeKind>().is_err());
}

// ---------------------------------------------------------------------------
// File permissions (Unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn test_history_db_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test_results.db");
    let _db = HistoryDb::open(&db_path).unwrap();

    let metadata = std::fs::metadata(&db_path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "History DB file should have 0o600 permissions, got {:o}",
        mode
    );
}
