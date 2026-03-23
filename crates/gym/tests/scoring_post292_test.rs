//! TDD tests for scoring engine post-PR #292.
//!
//! Validates the new CWE family mappings (CWE-400, CWE-563, CWE-617, CWE-843),
//! interprocedural taint scoring, and negative-case calibration after the
//! precision restoration (0 FP) and Juliet CWE expansion changes.
//!
//! These tests define the contract. They should FAIL until implementation
//! satisfies all post-292 scoring requirements.

use skwaq_gym::adapters::DetectedFinding;
use skwaq_gym::scoring::{
    aggregate, cwe_family, cwe_regressions, precision_regression, score_case, AggregateScore,
    CaseOutcome, CweScore, NegativeCaseCalibration,
};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_case(
    id: &str,
    expected_cwes: Vec<u32>,
    is_negative: bool,
) -> skwaq_gym::ground_truth::TestCase {
    skwaq_gym::ground_truth::TestCase {
        id: id.to_string(),
        path: format!("{}.c", id),
        binary_path: None,
        expected_cwes,
        is_negative,
        language: "c".to_string(),
    }
}

fn make_finding(category: &str, cwes: Vec<u32>) -> DetectedFinding {
    DetectedFinding {
        id: uuid::Uuid::new_v4().to_string(),
        category: category.to_string(),
        severity: "high".to_string(),
        cwes,
        file: "test.c".to_string(),
        function: "main".to_string(),
        line: Some(10),
        title: "test finding".to_string(),
    }
}

fn make_critical_finding(category: &str, cwes: Vec<u32>) -> DetectedFinding {
    DetectedFinding {
        id: uuid::Uuid::new_v4().to_string(),
        category: category.to_string(),
        severity: "critical".to_string(),
        cwes,
        file: "test.c".to_string(),
        function: "main".to_string(),
        line: Some(10),
        title: "critical finding".to_string(),
    }
}

fn make_score_with_cwes(cwe_scores: Vec<(u32, f64, u32)>) -> AggregateScore {
    let mut per_cwe = HashMap::new();
    for (cwe_id, rate, total) in cwe_scores {
        per_cwe.insert(
            cwe_id,
            CweScore {
                cwe_id,
                total_cases: total,
                true_positives: (rate * total as f64) as u32,
                false_positives: 0,
                false_negatives: ((1.0 - rate) * total as f64) as u32,
                detection_rate: rate,
                precision: 1.0,
            },
        );
    }
    AggregateScore {
        per_cwe,
        per_semantic: HashMap::new(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// CWE family mappings for new Juliet CWEs (PR #292)
// ---------------------------------------------------------------------------

#[test]
fn test_cwe400_maps_to_resource_leak_family() {
    // CWE-400: Uncontrolled Resource Consumption → resource leak family (401)
    assert_eq!(
        cwe_family(400),
        401,
        "CWE-400 should map to resource leak family 401"
    );
}

#[test]
fn test_cwe563_maps_to_uninitialized_var_family() {
    // CWE-563: Assignment to Variable without Use (Dead Store) → uninitialized var family (457)
    assert_eq!(
        cwe_family(563),
        457,
        "CWE-563 should map to uninitialized var family 457"
    );
}

#[test]
fn test_cwe617_maps_to_dangerous_function_family() {
    // CWE-617: Reachable Assertion → dangerous function family (676)
    assert_eq!(
        cwe_family(617),
        676,
        "CWE-617 should map to dangerous function family 676"
    );
}

#[test]
fn test_cwe843_maps_to_memory_safety_family() {
    // CWE-843: Access of Resource Using Incompatible Type (Type Confusion) → buffer overflow family (119)
    assert_eq!(
        cwe_family(843),
        119,
        "CWE-843 should map to memory safety family 119"
    );
}

// Verify that existing family mappings are preserved after PR #292
#[test]
fn test_existing_family_mappings_preserved() {
    assert_eq!(cwe_family(121), 119, "CWE-121 stack overflow → 119");
    assert_eq!(cwe_family(122), 119, "CWE-122 heap overflow → 119");
    assert_eq!(cwe_family(78), 74, "CWE-78 OS command injection → 74");
    assert_eq!(cwe_family(416), 416, "CWE-416 use-after-free → self");
    assert_eq!(cwe_family(415), 416, "CWE-415 double-free → 416");
    assert_eq!(cwe_family(134), 134, "CWE-134 format string → self");
    assert_eq!(cwe_family(190), 190, "CWE-190 integer overflow → self");
    assert_eq!(cwe_family(476), 476, "CWE-476 null deref → self");
    assert_eq!(cwe_family(362), 362, "CWE-362 race condition → self");
    assert_eq!(cwe_family(590), 119, "CWE-590 free-of-non-heap → 119");
}

// ---------------------------------------------------------------------------
// Cross-function (interprocedural) CWE family matching
// ---------------------------------------------------------------------------

#[test]
fn test_score_case_interprocedural_taint_finding() {
    // A finding detected via interprocedural taint (cross-function boundary)
    // should still match expected CWEs via family grouping.
    let case = make_case("interprocedural_bof", vec![121], false);

    // Agent detected CWE-787 (out-of-bounds write) via interprocedural taint flow.
    // CWE-787 belongs to the same family as CWE-121 (both → family 119).
    let findings = vec![make_finding("memory", vec![787])];

    let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
    assert!(
        outcome.cwe_hits[&121],
        "CWE-787 (interprocedural) should satisfy CWE-121 via family 119"
    );
    assert_eq!(outcome.matched_finding_ids.len(), 1);
}

#[test]
fn test_score_case_cross_file_taint_type_confusion() {
    // Type confusion detected via cross-file call graph (new CWE-843 mapping)
    let case = make_case("type_confusion", vec![843], false);
    let findings = vec![make_finding("memory", vec![843])];

    let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
    assert!(
        outcome.cwe_hits[&843],
        "CWE-843 type confusion should be detected via cross-file taint"
    );
}

#[test]
fn test_score_case_resource_exhaustion_via_taint() {
    // CWE-400 resource exhaustion detected via interprocedural taint
    let case = make_case("resource_exhaustion", vec![400], false);
    let findings = vec![make_finding("resource_leak", vec![401])];

    let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
    assert!(
        outcome.cwe_hits[&400],
        "CWE-401 finding should satisfy CWE-400 via resource leak family"
    );
}

#[test]
fn test_score_case_dead_store_detection() {
    // CWE-563 dead store (new Juliet mapping)
    let case = make_case("dead_store", vec![563], false);
    let findings = vec![make_finding("uninitialized_var", vec![457])];

    let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
    assert!(
        outcome.cwe_hits[&563],
        "CWE-457 finding should satisfy CWE-563 via uninitialized var family"
    );
}

#[test]
fn test_score_case_reachable_assertion() {
    // CWE-617 reachable assertion (new Juliet mapping)
    let case = make_case("reachable_assertion", vec![617], false);
    let findings = vec![make_finding("unsafe_code", vec![676])];

    let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
    assert!(
        outcome.cwe_hits[&617],
        "CWE-676 finding should satisfy CWE-617 via dangerous function family"
    );
}

// ---------------------------------------------------------------------------
// Negative case calibration: 100% precision (0 FP) contract
// ---------------------------------------------------------------------------

#[test]
fn test_aggregate_zero_fp_on_negative_cases() {
    // Contract: after PR #292, the fixtures suite has 0 FP (100% precision).
    // Simulate the expected outcome: 12 negative cases, all true negatives.
    let mut outcomes = Vec::new();
    for i in 0..12 {
        outcomes.push(CaseOutcome {
            case_id: format!("safe_{}", i),
            suite: "fixtures".to_string(),
            expected_cwes: vec![],
            detected_cwes: vec![],
            matched_finding_ids: vec![],
            unmatched_finding_ids: vec![],
            cwe_hits: HashMap::new(),
        });
    }

    let score = aggregate(&outcomes);
    assert_eq!(score.negative_calibration.total_negative_cases, 12);
    assert_eq!(score.negative_calibration.true_negatives, 12);
    assert_eq!(score.negative_calibration.false_positives, 0);
    assert_eq!(score.negative_calibration.false_positive_rate, 0.0);
    assert_eq!(score.true_negatives, 12);
}

#[test]
fn test_negative_case_only_critical_findings_count_as_fp() {
    // High-severity findings on negative cases should NOT count as FP
    let case = make_case("safe_code", vec![], true);
    let high_findings = vec![make_finding("memory", vec![119])];

    let outcome = score_case(&case, &high_findings, &|f| f.cwes.clone());
    assert!(
        outcome.detected_cwes.is_empty(),
        "High severity findings should be filtered out on negative cases"
    );

    // Critical-severity findings WITH CWEs SHOULD count as FP
    let critical_findings = vec![make_critical_finding("memory", vec![119])];
    let outcome2 = score_case(&case, &critical_findings, &|f| f.cwes.clone());
    assert!(
        !outcome2.detected_cwes.is_empty(),
        "Critical severity findings with CWEs should count as FP on negative cases"
    );
}

// ---------------------------------------------------------------------------
// Aggregate with the current baseline: F1=87.9%, P=100%, R=78.4%
// ---------------------------------------------------------------------------

#[test]
fn test_aggregate_matches_baseline_metrics() {
    // Simulate the known baseline: 91 TP, 0 FP, 25 FN, 12 TN
    let mut outcomes = Vec::new();

    // 91 true positives
    for i in 0..91 {
        outcomes.push(CaseOutcome {
            case_id: format!("tp_{}", i),
            suite: "fixtures".to_string(),
            expected_cwes: vec![119],
            detected_cwes: vec![119],
            matched_finding_ids: vec![format!("f_{}", i)],
            unmatched_finding_ids: vec![],
            cwe_hits: [(119, true)].into_iter().collect(),
        });
    }

    // 25 false negatives
    for i in 0..25 {
        outcomes.push(CaseOutcome {
            case_id: format!("fn_{}", i),
            suite: "fixtures".to_string(),
            expected_cwes: vec![119],
            detected_cwes: vec![],
            matched_finding_ids: vec![],
            unmatched_finding_ids: vec![],
            cwe_hits: [(119, false)].into_iter().collect(),
        });
    }

    // 12 true negatives
    for i in 0..12 {
        outcomes.push(CaseOutcome {
            case_id: format!("tn_{}", i),
            suite: "fixtures".to_string(),
            expected_cwes: vec![],
            detected_cwes: vec![],
            matched_finding_ids: vec![],
            unmatched_finding_ids: vec![],
            cwe_hits: HashMap::new(),
        });
    }

    let score = aggregate(&outcomes);
    assert_eq!(score.true_positives, 91);
    assert_eq!(score.false_positives, 0);
    assert_eq!(score.false_negatives, 25);
    assert_eq!(score.true_negatives, 12);

    // Precision = TP / (TP + FP) = 91 / 91 = 1.0
    assert_eq!(score.precision, 1.0, "Precision should be 100%");

    // Recall = TP / (TP + FN) = 91 / 116 ≈ 0.784
    let expected_recall = 91.0 / 116.0;
    assert!(
        (score.recall - expected_recall).abs() < 0.01,
        "Recall should be ~78.4%, got {:.1}%",
        score.recall * 100.0
    );

    // F1 = 2 * P * R / (P + R)
    let expected_f1 = 2.0 * 1.0 * expected_recall / (1.0 + expected_recall);
    assert!(
        (score.f1 - expected_f1).abs() < 0.01,
        "F1 should be ~87.9%, got {:.1}%",
        score.f1 * 100.0
    );
}

// ---------------------------------------------------------------------------
// CWE regression detection for new mappings
// ---------------------------------------------------------------------------

#[test]
fn test_cwe_regression_on_new_cwe400_mapping() {
    // After adding CWE-400 mapping, a regression on that CWE should be caught
    let baseline = make_score_with_cwes(vec![(401, 0.80, 10)]); // resource leak family
    let regressed = make_score_with_cwes(vec![(401, 0.50, 10)]); // dropped 30%

    let regressions = cwe_regressions(&baseline, &regressed);
    assert!(
        !regressions.is_empty(),
        "30% drop in CWE-401 detection should be flagged as regression"
    );
    assert_eq!(regressions[0].cwe_id, 401);
}

#[test]
fn test_no_regression_when_new_cwes_absent_from_baseline() {
    // CWEs that are NEW (not in baseline) should not trigger regression
    let baseline = make_score_with_cwes(vec![(119, 0.80, 10)]);
    let new_with_extra = make_score_with_cwes(vec![(119, 0.80, 10), (401, 0.50, 5)]);

    let regressions = cwe_regressions(&baseline, &new_with_extra);
    assert!(
        regressions.is_empty(),
        "New CWEs not in baseline should not trigger regression"
    );
}

#[test]
fn test_precision_regression_catches_fp_introduction() {
    // Contract: any FP introduction from 0 FP baseline should be detected
    let baseline = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 12,
            true_negatives: 12,
            false_positives: 0,
            false_positive_rate: 0.0,
            per_semantic_fps: HashMap::new(),
        },
        ..Default::default()
    };

    let with_fp = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 12,
            true_negatives: 11,
            false_positives: 1,
            false_positive_rate: 1.0 / 12.0, // ~8.3%
            per_semantic_fps: HashMap::new(),
        },
        ..Default::default()
    };

    let regression = precision_regression(&baseline, &with_fp);
    assert!(
        regression.is_some(),
        "Any FP introduction from 0% should trigger precision regression"
    );
    let delta = regression.unwrap();
    assert_eq!(delta.previous_fp_rate, 0.0);
    assert!((delta.current_fp_rate - 1.0 / 12.0).abs() < 0.001);
}

// ---------------------------------------------------------------------------
// Deduplication across shards (interprocedural may produce duplicates)
// ---------------------------------------------------------------------------

#[test]
fn test_deduplicate_outcomes_merges_cross_shard_detections() {
    use skwaq_gym::scoring::deduplicate_outcomes;

    let outcomes = vec![
        CaseOutcome {
            case_id: "case_1".to_string(),
            suite: "fixtures".to_string(),
            expected_cwes: vec![121, 134],
            detected_cwes: vec![119],
            matched_finding_ids: vec!["f1".to_string()],
            unmatched_finding_ids: vec![],
            cwe_hits: [(121, true), (134, false)].into_iter().collect(),
        },
        CaseOutcome {
            case_id: "case_1".to_string(),
            suite: "fixtures".to_string(),
            expected_cwes: vec![121, 134],
            detected_cwes: vec![134],
            matched_finding_ids: vec!["f2".to_string()],
            unmatched_finding_ids: vec![],
            cwe_hits: [(121, false), (134, true)].into_iter().collect(),
        },
    ];

    let deduped = deduplicate_outcomes(outcomes);
    assert_eq!(deduped.len(), 1, "Should merge duplicates into one outcome");

    let merged = &deduped[0];
    assert!(
        merged.cwe_hits[&121],
        "CWE-121 hit in shard 1 should be preserved"
    );
    assert!(
        merged.cwe_hits[&134],
        "CWE-134 hit in shard 2 should be preserved"
    );
    assert!(merged.detected_cwes.contains(&119));
    assert!(merged.detected_cwes.contains(&134));
    assert_eq!(merged.matched_finding_ids.len(), 2);
}

// ---------------------------------------------------------------------------
// Semantic class mapping for new CWEs
// ---------------------------------------------------------------------------

#[test]
fn test_cwe_to_semantic_class_new_mappings() {
    use skwaq_gym::scoring::cwe_to_semantic_class;

    // CWE-843 → BufferOverflow (type confusion → memory safety)
    let class_843 = cwe_to_semantic_class(843);
    assert!(class_843.is_some(), "CWE-843 should have a semantic class");

    // CWE-617 → UnsafeApiUsage (reachable assertion)
    let class_617 = cwe_to_semantic_class(617);
    assert!(class_617.is_some(), "CWE-617 should have a semantic class");

    // CWE-563 → UninitializedVar (dead store)
    let class_563 = cwe_to_semantic_class(563);
    assert!(class_563.is_some(), "CWE-563 should have a semantic class");

    // CWE-400 → ResourceLeak (resource exhaustion)
    let class_400 = cwe_to_semantic_class(400);
    assert!(class_400.is_some(), "CWE-400 should have a semantic class");
}

// ---------------------------------------------------------------------------
// Inferred finding CWEs (semantic fallback path)
// ---------------------------------------------------------------------------

#[test]
fn test_inferred_finding_cwes_uses_explicit_cwes_first() {
    use skwaq_gym::scoring::inferred_finding_cwes;

    let finding = DetectedFinding {
        id: "test".to_string(),
        category: "memory".to_string(),
        severity: "high".to_string(),
        cwes: vec![121, 787],
        file: "test.c".to_string(),
        function: "vuln".to_string(),
        line: Some(5),
        title: "buffer overflow".to_string(),
    };

    let cwes = inferred_finding_cwes(&finding);
    assert!(
        cwes.contains(&121),
        "Explicit CWEs should be returned first"
    );
    assert!(
        cwes.contains(&787),
        "Explicit CWEs should be returned first"
    );
}

#[test]
fn test_inferred_finding_cwes_falls_back_to_category() {
    use skwaq_gym::scoring::inferred_finding_cwes;

    let finding = DetectedFinding {
        id: "test".to_string(),
        category: "memory".to_string(),
        severity: "high".to_string(),
        cwes: vec![],
        file: "test.c".to_string(),
        function: "vuln".to_string(),
        line: Some(5),
        title: "some issue".to_string(),
    };

    let cwes = inferred_finding_cwes(&finding);
    assert!(
        !cwes.is_empty(),
        "Category fallback should produce CWEs for 'memory'"
    );
}
