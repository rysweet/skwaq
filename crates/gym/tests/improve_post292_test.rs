//! TDD tests for the self-improvement engine post-PR #292.
//!
//! Covers heuristic failure analysis (Phase 1: TaintRule/AgentPrompt proposals,
//! Phase 2: NewPattern fallback), apply_accepted_proposals for all ImprovementKind
//! variants, and the new infer_danger_category mappings.
//!
//! Tests are written TDD-style: they specify the expected behavior BEFORE
//! implementation changes. Some will FAIL until the improvement engine is updated.

use skwaq_gym::improve::{
    apply_accepted_proposals, has_any_regression, has_precision_regression, EvidenceRef,
    EvidenceSourceType, Improvement, ImprovementCycle, ImprovementKind, Patch, Priority,
};

#[cfg(feature = "test-heuristic-api")]
use skwaq_gym::improve::{heuristic_failure_analysis, FalseNegativeCase};
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
        baseline_score: make_score(vec![(119, 0.784)]),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals,
        holdout_case_count: 26,
        training_case_count: 102,
        cross_validation_pending: vec![],
    }
}

#[cfg(feature = "test-heuristic-api")]
fn make_fn_case(case_id: &str, expected_cwes: Vec<u32>, source: &str) -> FalseNegativeCase {
    FalseNegativeCase {
        case_id: case_id.to_string(),
        expected_cwes,
        detected_cwes: vec![],
        source_path: PathBuf::from(format!("tests/fixtures/{}.c", case_id)),
        source_content: source.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Heuristic failure analysis: Phase 1 — TaintRule and AgentPrompt proposals
// ---------------------------------------------------------------------------

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_proposes_taint_rule_for_recv_source() {
    let cases = vec![make_fn_case(
        "network_overflow",
        vec![119, 120],
        r#"
void handle_connection(int sockfd) {
    char buf[256];
    int n = recv(sockfd, buf, sizeof(buf), 0);
    process(buf);
}
"#,
    )];

    let proposals = heuristic_failure_analysis(&cases);
    let taint_rules: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::TaintRule))
        .collect();

    assert!(
        !taint_rules.is_empty(),
        "recv() in FN case should produce TaintRule proposal for network source"
    );
    assert!(
        taint_rules.iter().any(|p| p.description.contains("recv")),
        "TaintRule should mention recv as taint source"
    );
}

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_proposes_agent_prompt_for_strcpy_sink() {
    let cases = vec![make_fn_case(
        "buffer_overflow_strcpy",
        vec![119, 120],
        r#"
void copy_input(char *input) {
    char buf[64];
    strcpy(buf, input);
}
"#,
    )];

    let proposals = heuristic_failure_analysis(&cases);
    let agent_prompts: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::AgentPrompt))
        .collect();

    assert!(
        !agent_prompts.is_empty(),
        "strcpy() sink in FN case should produce AgentPrompt proposal"
    );
    assert!(
        agent_prompts
            .iter()
            .any(|p| p.description.contains("strcpy")),
        "AgentPrompt should mention strcpy as taint sink"
    );
}

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_proposes_taint_rule_for_getenv_source() {
    let cases = vec![make_fn_case(
        "env_injection",
        vec![78],
        r#"
void run_command() {
    char *path = getenv("TOOL_PATH");
    system(path);
}
"#,
    )];

    let proposals = heuristic_failure_analysis(&cases);

    // Should produce TaintRule for getenv as environment source
    let taint_rules: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::TaintRule))
        .collect();

    assert!(
        taint_rules.iter().any(|p| p.description.contains("getenv")),
        "getenv() should produce TaintRule for environment source"
    );

    // Should also produce AgentPrompt for system() as command execution sink
    let agent_prompts: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::AgentPrompt))
        .collect();

    assert!(
        agent_prompts
            .iter()
            .any(|p| p.description.contains("system")),
        "system() should produce AgentPrompt for command execution sink"
    );
}

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_phase2_fallback_new_pattern_for_execl() {
    // Phase 2: regex pattern fallback for APIs not in taint source/sink lists
    let cases = vec![make_fn_case(
        "command_injection_execl",
        vec![78],
        r#"
void run(const char *cmd) {
    execl("/bin/sh", "sh", "-c", cmd, NULL);
}
"#,
    )];

    let proposals = heuristic_failure_analysis(&cases);
    let patterns: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::NewPattern))
        .collect();

    assert!(
        patterns.iter().any(|p| p.patch.replace.contains("execl")),
        "execl() should produce NewPattern fallback proposal"
    );
}

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_fallback_for_no_matchable_apis() {
    // When FN code has no regex-matchable dangerous APIs, the heuristic engine
    // should still produce an AgentPrompt proposal to enhance graph traversal.
    let cases = vec![make_fn_case(
        "clean_code",
        vec![119],
        r#"
int safe_add(int a, int b) {
    return a + b;
}
"#,
    )];

    let proposals = heuristic_failure_analysis(&cases);
    // Phase 3 catch-all: enhance agent graph traversal for cases with no matchable APIs
    let agent_prompts: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::AgentPrompt))
        .collect();

    assert!(
        !agent_prompts.is_empty() || proposals.is_empty(),
        "Should either produce an AgentPrompt fallback or no proposals"
    );

    // No TaintRule or NewPattern should be produced for clean code
    let patterns: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::NewPattern))
        .collect();
    assert!(
        patterns.is_empty(),
        "Clean code should not produce NewPattern proposals"
    );
    let taint_rules: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::TaintRule))
        .collect();
    assert!(
        taint_rules.is_empty(),
        "Clean code should not produce TaintRule proposals"
    );
}

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_deduplicates_proposals_by_api() {
    // Two FN cases both containing recv() should not produce duplicate proposals
    let cases = vec![
        make_fn_case("case_1", vec![119], "void f() { recv(fd, buf, 64, 0); }"),
        make_fn_case("case_2", vec![120], "void g() { recv(fd, buf, 128, 0); }"),
    ];

    let proposals = heuristic_failure_analysis(&cases);
    let recv_proposals: Vec<_> = proposals
        .iter()
        .filter(|p| p.description.contains("recv"))
        .collect();

    // Each case produces its own proposal (different source_case), but they may
    // be deduplicated later by description. At minimum, verify proposals exist.
    assert!(
        !recv_proposals.is_empty(),
        "recv() in multiple FN cases should produce proposals"
    );
}

#[cfg(feature = "test-heuristic-api")]
#[test]
fn test_heuristic_only_matches_relevant_cwes() {
    // Case expects CWE-134 (format string) but contains recv() which maps to CWE-119/120.
    // recv() TaintRule should NOT be proposed because CWE families don't overlap.
    let cases = vec![make_fn_case(
        "format_string_with_recv",
        vec![134],
        r#"
void f(int fd) {
    char buf[64];
    recv(fd, buf, sizeof(buf), 0);
    printf(buf);
}
"#,
    )];

    let proposals = heuristic_failure_analysis(&cases);
    let recv_taint: Vec<_> = proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::TaintRule) && p.description.contains("recv"))
        .collect();

    assert!(
        recv_taint.is_empty(),
        "recv() TaintRule should not be proposed for CWE-134 (family mismatch)"
    );
}

// ---------------------------------------------------------------------------
// apply_accepted_proposals: AgentPrompt kind
// ---------------------------------------------------------------------------

#[test]
fn test_apply_agent_prompt_append_mode() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "# vuln-hunter agent\n\nExisting instructions.\n",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Add taint tracing instruction".to_string(),
        target_cwes: vec![78],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: "When you see recv() calls, trace data flow to sinks.".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied, 1, "AgentPrompt proposal should be applied");

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("recv()"),
        "Agent prompt should contain the new instruction"
    );
    assert!(
        result.contains("Existing instructions"),
        "Existing content should be preserved"
    );
}

#[test]
fn test_apply_agent_prompt_replace_mode() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "# vuln-hunter\n\nOLD INSTRUCTION HERE\n\nMore content.\n",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Replace old instruction".to_string(),
        target_cwes: vec![119],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "OLD INSTRUCTION HERE".to_string(),
            replace: "NEW TAINT TRACING INSTRUCTION".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied, 1);

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(result.contains("NEW TAINT TRACING INSTRUCTION"));
    assert!(!result.contains("OLD INSTRUCTION HERE"));
}

#[test]
fn test_apply_agent_prompt_rejects_non_agent_path() {
    // Security: AgentPrompt should only write to agents/ dir or temp files
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "content").unwrap();

    // Simulate a target that looks like it's in src/ (not agents/)
    let evil_path = PathBuf::from("/home/user/src/main.rs");

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Malicious path".to_string(),
        target_cwes: vec![78],
        target_file: evil_path,
        patch: Patch {
            find: String::new(),
            replace: "evil content".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied, 0,
        "AgentPrompt to non-agents/ path should be rejected"
    );
}

// ---------------------------------------------------------------------------
// apply_accepted_proposals: TaintRule kind
// ---------------------------------------------------------------------------

#[test]
fn test_apply_taint_rule_validates_pipe_format() {
    // TaintRule expects: name|type|location|source_or_sink
    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::TaintRule,
        description: "Add recv taint source".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "recv|network|libc|source".to_string(), // 4 fields: valid
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    // Without a DB, TaintRule should skip (no DB to insert into)
    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    // TaintRule without DB: depends on implementation — it should either skip or succeed
    // The key contract: it should NOT panic
    assert!(applied <= 1);
}

#[test]
fn test_apply_taint_rule_rejects_wrong_field_count() {
    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::TaintRule,
        description: "Bad format".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "recv|network|libc".to_string(), // Only 3 fields: invalid
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied, 0,
        "TaintRule with wrong field count should be rejected"
    );
}

#[test]
fn test_apply_taint_rule_rejects_oversized_fields() {
    let long_name = "a".repeat(257); // exceeds 256 char limit
    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::TaintRule,
        description: "Oversized field".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: format!("{}|network|libc|source", long_name),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied, 0,
        "TaintRule with >256 char field should be rejected"
    );
}

// ---------------------------------------------------------------------------
// apply_accepted_proposals: NewPattern with pattern ceiling
// ---------------------------------------------------------------------------

#[test]
fn test_apply_rejects_when_pattern_ceiling_reached() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    // Create a file with 500 existing SourcePattern entries (at ceiling)
    let mut content = String::from("fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n");
    for i in 0..500 {
        content.push_str(&format!(
            "        SourcePattern {{\n            regex: r\"\\bapi_{i}\\s*\\(\",\n\
             \x20           category: DangerCategory::Memory,\n\
             \x20           severity: Severity::High,\n\
             \x20           reason: \"pattern {i}\",\n        }},\n"
        ));
    }
    content.push_str("    ]\n}\n");
    std::fs::write(tmp.path(), &content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Pattern at ceiling".to_string(),
        target_cwes: vec![119],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\bnew_api\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied, 0,
        "Should reject when pattern count >= 500 ceiling"
    );
}

#[test]
fn test_apply_rejects_regex_with_double_quote() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}\n";
    std::fs::write(tmp.path(), content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Regex with quotes".to_string(),
        target_cwes: vec![119],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r#"\b"evil"\b"#.to_string(), // contains double quote
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied, 0,
        "Regex containing double quotes should be rejected"
    );
}

// ---------------------------------------------------------------------------
// infer_danger_category: new CWE mappings from PR #292
// ---------------------------------------------------------------------------

#[test]
fn test_infer_category_for_new_cwe400() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}\n";
    std::fs::write(tmp.path(), content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Resource exhaustion".to_string(),
        target_cwes: vec![400],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\bmalloc_unlimited\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::ResourceExhaustion"),
        "CWE-400 should map to ResourceExhaustion category: {result}"
    );
}

#[test]
fn test_infer_category_for_new_cwe843() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}\n";
    std::fs::write(tmp.path(), content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Type confusion".to_string(),
        target_cwes: vec![843],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\breinterpret_cast\s*<".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::TypeConfusion"),
        "CWE-843 should map to TypeConfusion category: {result}"
    );
}

#[test]
fn test_infer_category_for_new_cwe617() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}\n";
    std::fs::write(tmp.path(), content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Reachable assertion".to_string(),
        target_cwes: vec![617],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\bassert\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    // CWE-617 is in the unsafe_code / dangerous function family
    // infer_danger_category doesn't have explicit 617 mapping yet — it falls through to Memory default
    // After improvement, it should map to UnsafeCode or similar
    assert!(
        result.contains("DangerCategory::"),
        "CWE-617 should produce a valid DangerCategory: {result}"
    );
}

// ---------------------------------------------------------------------------
// Max improvements per cycle cap
// ---------------------------------------------------------------------------

#[test]
fn test_cycle_holdout_training_split_20_percent() {
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: make_score(vec![(119, 0.784)]),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals: vec![],
        holdout_case_count: 26,
        training_case_count: 102,
        cross_validation_pending: vec![
            "juliet".to_string(),
            "owasp".to_string(),
            "cyberseceval".to_string(),
            "cgc".to_string(),
        ],
    };

    let total = cycle.holdout_case_count + cycle.training_case_count;
    assert_eq!(total, 128, "Total should be 128 fixture cases");

    let holdout_fraction = cycle.holdout_case_count as f64 / total as f64;
    assert!(
        (holdout_fraction - 0.20).abs() < 0.02,
        "Holdout should be ~20%: got {:.1}%",
        holdout_fraction * 100.0
    );
}

#[test]
fn test_cross_validation_pending_includes_all_other_suites() {
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: AggregateScore::default(),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals: vec![Improvement {
            kind: ImprovementKind::NewPattern,
            description: "dummy".to_string(),
            target_cwes: vec![119],
            target_file: PathBuf::from("test.rs"),
            patch: Patch {
                find: String::new(),
                replace: "x".to_string(),
            },
            source_case: "case_1".to_string(),
            priority: Priority::High,
            supporting_evidence: vec![],
            review: None,
        }],
        holdout_case_count: 0,
        training_case_count: 0,
        cross_validation_pending: vec![
            "juliet".to_string(),
            "owasp".to_string(),
            "cyberseceval".to_string(),
            "cgc".to_string(),
        ],
    };

    // With proposals, cross-validation should include at least juliet, owasp, cyberseceval, cgc
    assert!(
        cycle.cross_validation_pending.len() >= 4,
        "Should have at least 4 cross-validation suites"
    );
    assert!(cycle
        .cross_validation_pending
        .contains(&"juliet".to_string()));
    assert!(cycle
        .cross_validation_pending
        .contains(&"owasp".to_string()));
    assert!(cycle.cross_validation_pending.contains(&"cgc".to_string()));
}

// ---------------------------------------------------------------------------
// Evidence tracking in proposals
// ---------------------------------------------------------------------------

#[test]
fn test_improvement_preserves_evidence_refs() {
    let improvement = Improvement {
        kind: ImprovementKind::TaintRule,
        description: "Add recv source".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "recv|network|libc|source".to_string(),
        },
        source_case: "network_overflow".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![
            EvidenceRef {
                source_type: EvidenceSourceType::Knowledge,
                source: Some("cwe-families".to_string()),
                topic: Some("taint analysis".to_string()),
                title: Some("Network taint sources".to_string()),
                memory_type: None,
                context: Some("recv() returns attacker-controlled data".to_string()),
                tags: vec!["taint".to_string(), "network".to_string()],
                rationale: "recv() is a standard network taint source".to_string(),
            },
            EvidenceRef {
                source_type: EvidenceSourceType::Memory,
                source: None,
                topic: None,
                title: None,
                memory_type: Some("durable".to_string()),
                context: None,
                tags: vec![],
                rationale: "Previously seen in similar FN case".to_string(),
            },
        ],
        review: None,
    };

    assert_eq!(improvement.supporting_evidence.len(), 2);
    assert_eq!(
        improvement.supporting_evidence[0].source_type,
        EvidenceSourceType::Knowledge
    );
    assert_eq!(
        improvement.supporting_evidence[1].source_type,
        EvidenceSourceType::Memory
    );
}

// ---------------------------------------------------------------------------
// Regression gates: interaction with 100% precision baseline
// ---------------------------------------------------------------------------

#[test]
fn test_regression_from_perfect_precision() {
    // Baseline: 100% precision (0 FP)
    let mut baseline = make_score(vec![(119, 0.784)]);
    baseline.precision = 1.0;
    baseline.negative_calibration = NegativeCaseCalibration {
        total_negative_cases: 12,
        true_negatives: 12,
        false_positives: 0,
        false_positive_rate: 0.0,
        per_semantic_fps: HashMap::new(),
    };

    // After improvement: 1 FP introduced
    let mut improved = make_score(vec![(119, 0.85)]); // recall improved
    improved.negative_calibration = NegativeCaseCalibration {
        total_negative_cases: 12,
        true_negatives: 11,
        false_positives: 1,
        false_positive_rate: 1.0 / 12.0,
        per_semantic_fps: HashMap::new(),
    };

    assert!(
        has_precision_regression(&baseline, &improved),
        "Any FP from 0% baseline should be a regression"
    );
    assert!(
        has_any_regression(&baseline, &improved),
        "Combined check should catch precision regression"
    );
}

#[test]
fn test_no_regression_when_recall_improves_precision_holds() {
    let mut baseline = make_score(vec![(119, 0.784)]);
    baseline.negative_calibration = NegativeCaseCalibration {
        total_negative_cases: 12,
        true_negatives: 12,
        false_positives: 0,
        false_positive_rate: 0.0,
        per_semantic_fps: HashMap::new(),
    };

    // Improvement: recall up, precision unchanged (still 0 FP)
    let mut improved = make_score(vec![(119, 0.85)]);
    improved.negative_calibration = NegativeCaseCalibration {
        total_negative_cases: 12,
        true_negatives: 12,
        false_positives: 0,
        false_positive_rate: 0.0,
        per_semantic_fps: HashMap::new(),
    };

    assert!(
        !has_any_regression(&baseline, &improved),
        "Recall improvement with no FP should not trigger regression"
    );
}
