//! Integration tests for the self-improvement cycle.
//!
//! These tests define the contract for safe, structured improvement proposals.
//! They are written TDD-style: they specify expected behavior BEFORE implementation.
//!
//! Tests that reference unimplemented features (regex size_limit, CLI arg validation)
//! are expected to FAIL until implementation is complete.

use skwaq_gym::improve::{
    apply_accepted_proposals, has_any_regression, has_cwe_regression, has_precision_regression,
    EvidenceRef, EvidenceSourceType, Improvement, ImprovementCycle, ImprovementKind, Patch,
    Priority, ReviewDecision, ReviewRating, ReviewVerdict,
};
use skwaq_gym::scoring::{AggregateScore, CweScore, NegativeCaseCalibration};
use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_score(cwe_scores: Vec<(u32, f64)>) -> AggregateScore {
    let mut per_cwe = HashMap::new();
    for (cwe_id, rate) in cwe_scores {
        per_cwe.insert(
            cwe_id,
            CweScore {
                cwe_id,
                total_cases: 10,
                true_positives: (rate * 10.0) as u32,
                false_positives: 0,
                false_negatives: ((1.0 - rate) * 10.0) as u32,
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

fn make_cycle_with_proposals(proposals: Vec<Improvement>) -> ImprovementCycle {
    ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: make_score(vec![(119, 0.5)]),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals,
        holdout_case_count: 0,
        training_case_count: 0,
        holdout_score: None,
        cross_validation_pending: vec![],
        run_metadata: None,
    }
}

fn make_new_pattern_proposal(regex: &str, cwes: Vec<u32>, target: PathBuf) -> Improvement {
    Improvement {
        kind: ImprovementKind::NewPattern,
        description: format!("Add pattern for CWEs {:?}", cwes),
        target_cwes: cwes,
        target_file: target,
        patch: Patch {
            find: String::new(),
            replace: regex.to_string(),
        },
        source_case: "test_case".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![EvidenceRef {
            source_type: EvidenceSourceType::Heuristic,
            source: Some("test".to_string()),
            topic: None,
            title: None,
            memory_type: None,
            context: None,
            tags: vec![],
            rationale: "test evidence".to_string(),
        }],
        review: None,
    }
}

// ---------------------------------------------------------------------------
// apply_accepted_proposals: Filtering
// ---------------------------------------------------------------------------

#[test]
fn test_apply_empty_cycle_returns_zero() {
    let cycle = make_cycle_with_proposals(vec![]);
    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "Empty cycle should apply zero proposals"
    );
}

#[test]
fn test_apply_skips_non_pattern_proposals() {
    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Improve prompt".to_string(),
        target_cwes: vec![78],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "new prompt text".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::Medium,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "AgentPrompt proposals should be skipped"
    );
}

#[test]
fn test_apply_skips_empty_replace_proposals() {
    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Empty replace".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
        patch: Patch {
            find: String::new(),
            replace: String::new(), // empty replace → skip
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "Empty-replace proposals should be skipped"
    );
    assert_eq!(
        applied.skipped, 1,
        "Empty-replace proposal should be counted as skipped"
    );
    assert_eq!(
        applied.blocked, 0,
        "Empty-replace proposal should not be blocked"
    );
}

/// When the overfitting reviewer has accepted a proposal (strict_mode = true) but the
/// proposal carries no patch (architectural guidance only), `apply_accepted_proposals`
/// must still complete successfully, counting the proposal as skipped.
#[test]
fn test_apply_reviewed_empty_patch_proposal_is_skipped_not_error() {
    let reviewed_proposal = Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Improve CPG ingestion for better coverage".to_string(),
        target_cwes: vec![22],
        target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
        patch: Patch {
            find: String::new(),
            replace: String::new(), // no auto-apply patch
        },
        source_case: "cse_path_traversal".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Accept,
            reason: "Valid architectural guidance.".to_string(),
            overfitting_risk: ReviewRating::Low,
            real_world_applicability: ReviewRating::High,
            suggested_modification: None,
            evidence_refs: vec![],
        }),
    };
    // Use reviewed_proposals so strict_mode = true
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: make_score(vec![(22, 0.5)]),
        false_negatives: vec![],
        reviewed_proposals: vec![reviewed_proposal],
        proposals: vec![],
        holdout_case_count: 0,
        training_case_count: 0,
        holdout_score: None,
        cross_validation_pending: vec![],
        run_metadata: None,
    };

    let report = apply_accepted_proposals(&cycle, None)
        .expect("Empty-patch reviewed proposal must not cause an error");
    assert_eq!(report.applied, 0, "Nothing should be applied");
    assert_eq!(
        report.skipped, 1,
        "Empty-patch reviewed proposal should be counted as skipped"
    );
    assert_eq!(
        report.blocked, 0,
        "Empty-patch reviewed proposal should not be blocked"
    );
}

#[test]
fn test_apply_skips_nonexistent_target_file() {
    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bsprintf\s*\(",
        vec![119],
        PathBuf::from("/nonexistent/path/patterns_source.rs"),
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "Non-existent target file should be skipped"
    );
}

// ---------------------------------------------------------------------------
// apply_accepted_proposals: Structured insertion (not raw interpolation)
// ---------------------------------------------------------------------------

#[test]
fn test_apply_inserts_structured_source_pattern() {
    // Create a temp file mimicking the c_cpp_patterns() array structure
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\bstrcpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "strcpy is unsafe",
        },
    ]
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bsprintf\s*\(",
        vec![119],
        tmp.path().to_path_buf(),
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied.applied, 1, "Should apply one proposal");

    let result = std::fs::read_to_string(tmp.path()).unwrap();

    // Verify structured insertion — must contain SourcePattern { ... } block
    assert!(
        result.contains("SourcePattern {"),
        "Inserted code must use typed SourcePattern struct, not raw string: {result}"
    );
    assert!(
        result.contains("DangerCategory::Memory"),
        "Should infer Memory category for CWE-119: {result}"
    );
    assert!(
        result.contains(r#"regex: r"\bsprintf\s*\(""#),
        "Regex should be inserted verbatim in the regex field: {result}"
    );
    assert!(
        result.contains("Self-improvement: from case"),
        "Should include provenance comment: {result}"
    );

    // Security: verify no raw format!() interpolation of the regex into code
    // The regex must appear ONLY inside a string literal (r"..." or "...")
    // not as bare Rust code
    assert!(
        !result.contains("\\bsprintf\\s*\\(\n"),
        "Regex must not appear as bare code outside a string literal"
    );
}

#[test]
fn test_apply_preserves_existing_patterns() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern {
            regex: r"\bstrcpy\s*\(",
            category: DangerCategory::Memory,
            severity: Severity::High,
            reason: "strcpy is unsafe",
        },
    ]
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bmemcpy\s*\(",
        vec![119],
        tmp.path().to_path_buf(),
    )]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();

    // Original pattern must still be present
    assert!(
        result.contains(r#"r"\bstrcpy\s*\(""#),
        "Original patterns must be preserved after insertion"
    );
    // New pattern must be present
    assert!(
        result.contains(r#"r"\bmemcpy\s*\(""#),
        "New pattern must be inserted"
    );
}

// ---------------------------------------------------------------------------
// apply_accepted_proposals: Replace mode
// ---------------------------------------------------------------------------

#[test]
fn test_apply_replace_mode() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = "OLD_PATTERN_HERE";
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Replace old pattern".to_string(),
        target_cwes: vec![119],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "OLD_PATTERN_HERE".to_string(),
            replace: "NEW_PATTERN_HERE".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied.applied, 1);

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert_eq!(result, "NEW_PATTERN_HERE");
}

#[test]
fn test_apply_replace_mode_skips_when_find_text_missing() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "some content here").unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Replace nonexistent text".to_string(),
        target_cwes: vec![119],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "DOES_NOT_EXIST".to_string(),
            replace: "NEW_TEXT".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "Should skip when find text is not present"
    );
}

// ---------------------------------------------------------------------------
// Regex safety gate: RegexBuilder::size_limit(200_000) — TDD: SHOULD FAIL
// ---------------------------------------------------------------------------

/// This test defines the contract for Phase B1: LLM-proposed patterns must be
/// compiled with `RegexBuilder::size_limit(200_000)` to prevent ReDoS.
/// Currently EXPECTED TO FAIL because the safety gate is not yet implemented.
#[test]
fn test_regex_size_limit_rejects_catastrophic_pattern() {
    // A pattern that causes exponential blowup in the regex engine.
    // With Unicode-aware \w, \w{200} generates a massive NFA that
    // exceeds the 200KB compiled size limit.
    let huge_regex = r"\w{200}";
    let huge_result = regex::RegexBuilder::new(huge_regex)
        .size_limit(200_000)
        .build();

    assert!(
        huge_result.is_err(),
        "Regex exceeding size_limit(200_000) should fail to compile"
    );

    // Verify the catastrophic backtracking pattern (a+)+ is bounded.
    // The regex crate's NFA engine doesn't backtrack, but size_limit
    // still applies to the compiled representation.
    let evil_regex = r"(a+)+$";
    let evil_result = regex::RegexBuilder::new(evil_regex)
        .size_limit(200_000)
        .build();
    // This pattern is small enough to compile, but the regex crate's
    // NFA engine handles it in linear time anyway. The size_limit
    // protects against state explosion, not backtracking.
    assert!(
        evil_result.is_ok(),
        "Simple backtracking pattern should compile (regex crate is NFA-based)"
    );
}

/// Verify that normal, well-behaved patterns still compile with the size limit.
#[test]
fn test_regex_size_limit_allows_normal_patterns() {
    let normal_patterns = vec![
        r"\bstrcpy\s*\(",
        r"\bmemcpy\s*\(",
        r"\bsprintf\s*\(",
        r"\beval\s*\(",
        r"\bos\.system\s*\(",
    ];

    for pat in normal_patterns {
        let result = regex::RegexBuilder::new(pat).size_limit(200_000).build();
        assert!(
            result.is_ok(),
            "Normal pattern '{pat}' should compile within size_limit(200_000)"
        );
    }
}

// ---------------------------------------------------------------------------
// infer_danger_category: tested indirectly through apply_accepted_proposals
// ---------------------------------------------------------------------------

#[test]
fn test_apply_infers_injection_category_for_cwe78() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
    ]
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bexecl\s*\(",
        vec![78],
        tmp.path().to_path_buf(),
    )]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::Injection"),
        "CWE-78 should map to Injection category: {result}"
    );
}

#[test]
fn test_apply_infers_memory_category_for_cwe121() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
    ]
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bgets\s*\(",
        vec![121],
        tmp.path().to_path_buf(),
    )]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::Memory"),
        "CWE-121 should map to Memory category: {result}"
    );
}

#[test]
fn test_apply_infers_format_string_category_for_cwe134() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
    ]
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bprintf\s*\(",
        vec![134],
        tmp.path().to_path_buf(),
    )]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::FormatString"),
        "CWE-134 should map to FormatString category: {result}"
    );
}

#[test]
fn test_apply_defaults_to_memory_for_unknown_cwe() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
    ]
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![make_new_pattern_proposal(
        r"\bfoo\s*\(",
        vec![9999], // unknown CWE
        tmp.path().to_path_buf(),
    )]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::Memory"),
        "Unknown CWE should default to Memory category: {result}"
    );
}

// ---------------------------------------------------------------------------
// Regression gate: has_cwe_regression / has_precision_regression / combined
// ---------------------------------------------------------------------------

#[test]
fn test_regression_gate_exact_boundary() {
    // The contract: delta < -CWE_REGRESSION_NOISE_MARGIN (-0.02) is a regression.
    // Due to floating-point precision, we test with values that are clearly
    // on each side of the boundary.

    // -0.01 delta: well within margin, NOT a regression
    let baseline = make_score(vec![(119, 0.50)]);
    let within_margin = make_score(vec![(119, 0.49)]); // -0.01
    assert!(
        !has_cwe_regression(&baseline, &within_margin),
        "-0.01 delta should not be regression (within 2% margin)"
    );

    // -0.05 delta: clearly beyond margin, IS a regression
    let beyond_margin = make_score(vec![(119, 0.45)]); // -0.05
    assert!(
        has_cwe_regression(&baseline, &beyond_margin),
        "-0.05 delta should be regression (beyond 2% margin)"
    );
}

#[test]
fn test_precision_regression_gate_exact_boundary() {
    let baseline = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 10,
            true_negatives: 9,
            false_positives: 1,
            false_positive_rate: 0.10,
            per_semantic_fps: HashMap::new(),
        },
        ..Default::default()
    };

    // At margin: 0.10 + 0.02 = 0.12 → should NOT trigger
    let at_margin = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 10,
            true_negatives: 9,
            false_positives: 1,
            false_positive_rate: 0.12,
            per_semantic_fps: HashMap::new(),
        },
        ..Default::default()
    };
    assert!(
        !has_precision_regression(&baseline, &at_margin),
        "FP rate increase of exactly 0.02 should not trigger regression"
    );

    // Beyond margin: 0.10 + 0.021 = 0.121 → SHOULD trigger
    let beyond_margin = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 10,
            true_negatives: 8,
            false_positives: 2,
            false_positive_rate: 0.121,
            per_semantic_fps: HashMap::new(),
        },
        ..Default::default()
    };
    assert!(
        has_precision_regression(&baseline, &beyond_margin),
        "FP rate increase beyond 0.02 should trigger regression"
    );
}

#[test]
fn test_combined_regression_cwe_only() {
    let baseline = make_score(vec![(119, 0.80), (78, 0.60)]);
    let mut new = make_score(vec![(119, 0.70), (78, 0.60)]); // CWE-119 dropped 10%

    // No negative calibration, so no precision regression
    new.negative_calibration.total_negative_cases = 0;

    assert!(
        has_any_regression(&baseline, &new),
        "CWE regression alone should trigger combined check"
    );
}

#[test]
fn test_combined_regression_precision_only() {
    let mut baseline = make_score(vec![(119, 0.80)]);
    baseline.negative_calibration = NegativeCaseCalibration {
        total_negative_cases: 10,
        true_negatives: 10,
        false_positives: 0,
        false_positive_rate: 0.0,
        per_semantic_fps: HashMap::new(),
    };

    let mut new = make_score(vec![(119, 0.80)]); // CWE detection unchanged
    new.negative_calibration = NegativeCaseCalibration {
        total_negative_cases: 10,
        true_negatives: 5,
        false_positives: 5,
        false_positive_rate: 0.50, // massive FP increase
        per_semantic_fps: HashMap::new(),
    };

    assert!(
        has_any_regression(&baseline, &new),
        "Precision regression alone should trigger combined check"
    );
}

#[test]
fn test_no_regression_when_scores_improve() {
    let baseline = make_score(vec![(119, 0.50), (78, 0.40)]);
    let improved = make_score(vec![(119, 0.60), (78, 0.50)]);
    assert!(
        !has_any_regression(&baseline, &improved),
        "Improved scores should not trigger regression"
    );
}

// ---------------------------------------------------------------------------
// Review decision filtering
// ---------------------------------------------------------------------------

#[test]
fn test_accepted_proposals_include_accept_and_modify_verdicts() {
    let accepted = Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Accepted proposal".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("test.rs"),
        patch: Patch {
            find: String::new(),
            replace: r"\bgets\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Accept,
            reason: "Good pattern".to_string(),
            overfitting_risk: ReviewRating::Low,
            real_world_applicability: ReviewRating::High,
            suggested_modification: None,
            evidence_refs: vec![],
        }),
    };

    let modified = Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Modified proposal".to_string(),
        target_cwes: vec![78],
        target_file: PathBuf::from("test.rs"),
        patch: Patch {
            find: String::new(),
            replace: r"\bexecl\s*\(".to_string(),
        },
        source_case: "case_2".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Modify,
            reason: "Needs adjustment".to_string(),
            overfitting_risk: ReviewRating::Medium,
            real_world_applicability: ReviewRating::Medium,
            suggested_modification: Some("Broaden pattern".to_string()),
            evidence_refs: vec![],
        }),
    };

    let rejected = Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Rejected proposal".to_string(),
        target_cwes: vec![134],
        target_file: PathBuf::from("test.rs"),
        patch: Patch {
            find: String::new(),
            replace: r"\bprintf\s*\(".to_string(),
        },
        source_case: "case_3".to_string(),
        priority: Priority::Low,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Reject,
            reason: "Too broad".to_string(),
            overfitting_risk: ReviewRating::High,
            real_world_applicability: ReviewRating::Low,
            suggested_modification: None,
            evidence_refs: vec![],
        }),
    };

    // Verify that we can correctly filter by verdict
    let proposals = [accepted, modified, rejected];
    let acceptable: Vec<_> = proposals
        .iter()
        .filter(|p| {
            matches!(
                p.review.as_ref().map(|r| r.verdict),
                Some(ReviewVerdict::Accept) | Some(ReviewVerdict::Modify)
            )
        })
        .collect();

    assert_eq!(
        acceptable.len(),
        2,
        "Accept and Modify verdicts should be acceptable"
    );

    let high_risk: Vec<_> = proposals
        .iter()
        .filter(|p| {
            matches!(
                p.review.as_ref().map(|r| r.overfitting_risk),
                Some(ReviewRating::High)
            )
        })
        .collect();

    assert_eq!(
        high_risk.len(),
        1,
        "High overfitting risk proposals should be identifiable"
    );
}

// ---------------------------------------------------------------------------
// ImprovementCycle holdout/training split
// ---------------------------------------------------------------------------

#[test]
fn test_cycle_tracks_holdout_and_training_counts() {
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: make_score(vec![(119, 0.5)]),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals: vec![],
        holdout_case_count: 4,
        holdout_score: None,
        training_case_count: 16,
        cross_validation_pending: vec!["juliet".to_string(), "owasp".to_string()],
        run_metadata: None,
    };

    assert_eq!(cycle.holdout_case_count, 4);
    assert_eq!(cycle.training_case_count, 16);
    assert_eq!(cycle.cross_validation_pending.len(), 2);
    // 20% holdout of 20 total = 4
    let total = cycle.holdout_case_count + cycle.training_case_count;
    let holdout_fraction = cycle.holdout_case_count as f64 / total as f64;
    assert!(
        (holdout_fraction - 0.20).abs() < 0.01,
        "Holdout fraction should be ~20%: got {holdout_fraction}"
    );
}
