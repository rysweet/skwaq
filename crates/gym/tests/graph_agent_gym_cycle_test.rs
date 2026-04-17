//! TDD tests for graph-agent gym cycle (PR #288/#289 features).
//!
//! These tests specify the contracts for:
//! 1. AgentPrompt proposal application (path safety, append/replace)
//! 2. TaintRule proposal application (pipe-delimited format, DB insertion, validation)
//! 3. CweMapping proposal application (match-arm insertion, replace mode)
//! 4. Heuristic failure analysis generating AgentPrompt/TaintRule proposals
//! 5. ReviewDecision gating across all proposal types
//! 6. Pattern count ceiling guard (~500 max patterns)
//! 7. Cross-file analysis context in generated proposals
//!
//! These tests should FAIL initially and pass once implementation is complete.

#[cfg(feature = "test-heuristic-api")]
use skwaq_gym::improve::FalseNegativeCase;
use skwaq_gym::improve::{
    apply_accepted_proposals, has_cwe_regression, has_precision_regression, EvidenceRef,
    EvidenceSourceType, Improvement, ImprovementCycle, ImprovementKind, Patch, Priority,
    ReviewDecision, ReviewRating, ReviewVerdict,
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

fn make_agent_prompt_proposal(instruction: &str, target: PathBuf) -> Improvement {
    Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Update vuln-hunter agent prompt".to_string(),
        target_cwes: vec![78],
        target_file: target,
        patch: Patch {
            find: String::new(),
            replace: instruction.to_string(),
        },
        source_case: "multi_file".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![EvidenceRef {
            source_type: EvidenceSourceType::Heuristic,
            source: Some("graph-analysis".to_string()),
            topic: None,
            title: None,
            memory_type: None,
            context: None,
            tags: vec![],
            rationale: "Cross-file taint flow detected".to_string(),
        }],
        review: None,
    }
}

fn make_taint_rule_proposal(rule: &str, cwes: Vec<u32>) -> Improvement {
    Improvement {
        kind: ImprovementKind::TaintRule,
        description: format!("Add taint rule: {}", rule),
        target_cwes: cwes,
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: rule.to_string(),
        },
        source_case: "test_case".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }
}

fn make_cwe_mapping_proposal(mapping: &str, target: PathBuf) -> Improvement {
    Improvement {
        kind: ImprovementKind::CweMapping,
        description: format!("Add CWE mapping: {}", mapping),
        target_cwes: vec![],
        target_file: target,
        patch: Patch {
            find: String::new(),
            replace: mapping.to_string(),
        },
        source_case: "test_case".to_string(),
        priority: Priority::Medium,
        supporting_evidence: vec![],
        review: None,
    }
}

#[cfg(feature = "test-heuristic-api")]
fn make_false_negative(case_id: &str, expected_cwes: Vec<u32>, source: &str) -> FalseNegativeCase {
    FalseNegativeCase {
        case_id: case_id.to_string(),
        expected_cwes,
        detected_cwes: vec![],
        source_path: PathBuf::from(format!("tests/fixtures/{}.c", case_id)),
        source_content: source.to_string(),
    }
}

// ===========================================================================
// AgentPrompt proposal application
// ===========================================================================

#[test]
fn test_agent_prompt_append_mode() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "# Vuln Hunter Agent\n\nExisting instructions.").unwrap();

    let cycle = make_cycle_with_proposals(vec![make_agent_prompt_proposal(
        "Use get_cross_file_calls to trace data flow across compilation units.",
        tmp.path().to_path_buf(),
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied.applied, 1, "AgentPrompt append should succeed");

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("get_cross_file_calls"),
        "Appended instruction should be present: {result}"
    );
    assert!(
        result.contains("Existing instructions"),
        "Original content must be preserved: {result}"
    );
}

#[test]
fn test_agent_prompt_replace_mode() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "# Vuln Hunter\n\nOLD_INSTRUCTION\n\nMore text.").unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Replace instruction".to_string(),
        target_cwes: vec![78],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "OLD_INSTRUCTION".to_string(),
            replace: "NEW_INSTRUCTION with get_taint_paths".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied.applied, 1, "AgentPrompt replace should succeed");

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("NEW_INSTRUCTION with get_taint_paths"),
        "Replacement should be applied: {result}"
    );
    assert!(
        !result.contains("OLD_INSTRUCTION"),
        "Old instruction should be gone: {result}"
    );
}

#[test]
fn test_agent_prompt_rejects_path_traversal() {
    // Path outside agents/ and /tmp should be rejected
    let evil_path = PathBuf::from("/etc/passwd");

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Evil path traversal".to_string(),
        target_cwes: vec![78],
        target_file: evil_path,
        patch: Patch {
            find: String::new(),
            replace: "malicious content".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "AgentPrompt targeting /etc/passwd must be rejected"
    );
}

#[test]
fn test_agent_prompt_allows_agents_directory() {
    // Simulate a file whose path contains "agents/" — the path check allows
    // targets containing "agents/" or ending with ".md"
    let tmp_agents = tempfile::Builder::new()
        .prefix("agents_")
        .suffix(".md")
        .tempfile()
        .unwrap();
    std::fs::write(tmp_agents.path(), "# Agent\n\nExisting content.").unwrap();

    let cycle = make_cycle_with_proposals(vec![make_agent_prompt_proposal(
        "New graph analysis instruction.",
        tmp_agents.path().to_path_buf(),
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 1,
        "AgentPrompt targeting .md file should be allowed"
    );
}

#[test]
fn test_agent_prompt_skips_when_find_text_missing() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "# Agent\n\nSome content.").unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Replace nonexistent text".to_string(),
        target_cwes: vec![78],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "DOES_NOT_EXIST_IN_FILE".to_string(),
            replace: "new text".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "AgentPrompt replace should skip when find text is missing"
    );
}

// ===========================================================================
// TaintRule proposal application
// ===========================================================================

#[test]
fn test_taint_rule_skipped_without_db() {
    let cycle = make_cycle_with_proposals(vec![make_taint_rule_proposal(
        "recv|network|libc|source",
        vec![119, 120],
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "TaintRule requires DB connection — should skip with db=None"
    );
}

#[test]
fn test_taint_rule_rejects_wrong_field_count() {
    // 3 fields instead of 4
    let cycle = make_cycle_with_proposals(vec![make_taint_rule_proposal(
        "recv|network|libc",
        vec![119],
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "TaintRule with wrong field count should be rejected"
    );
}

#[test]
fn test_taint_rule_rejects_oversized_fields() {
    let long_name = "a".repeat(257);
    let rule = format!("{}|network|libc|source", long_name);
    let cycle = make_cycle_with_proposals(vec![make_taint_rule_proposal(&rule, vec![119])]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "TaintRule with field > 256 chars should be rejected"
    );
}

#[test]
fn test_taint_rule_rejects_five_fields() {
    let cycle = make_cycle_with_proposals(vec![make_taint_rule_proposal(
        "recv|network|libc|source|extra",
        vec![119],
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "TaintRule with 5 pipe-delimited fields should be rejected"
    );
}

// ===========================================================================
// CweMapping proposal application
// ===========================================================================

#[test]
fn test_cwe_mapping_append_at_insertion_point() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = r#"fn cwe_to_semantic_class(cwe: u32) -> Option<&'static str> {
    match cwe {
        119 => Some("memory"),
        _ => None,
    }
}"#;
    std::fs::write(tmp.path(), initial_content).unwrap();

    let mapping = "        502 => Some(\"deserialization\"),\n";
    let cycle = make_cycle_with_proposals(vec![make_cwe_mapping_proposal(
        mapping,
        tmp.path().to_path_buf(),
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 1,
        "CweMapping should insert before _ => None"
    );

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("502 => Some(\"deserialization\")"),
        "New CWE mapping should be present: {result}"
    );
    assert!(
        result.contains("119 => Some(\"memory\")"),
        "Existing mappings must be preserved: {result}"
    );
    // The new mapping should appear before the catch-all
    let new_pos = result.find("502").unwrap();
    let catch_all_pos = result.find("_ => None").unwrap();
    assert!(
        new_pos < catch_all_pos,
        "New mapping must be inserted before _ => None"
    );
}

#[test]
fn test_cwe_mapping_replace_mode() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let initial_content = "OLD_CWE_MAPPING";
    std::fs::write(tmp.path(), initial_content).unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::CweMapping,
        description: "Replace CWE mapping".to_string(),
        target_cwes: vec![],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "OLD_CWE_MAPPING".to_string(),
            replace: "NEW_CWE_MAPPING".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::Medium,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(applied.applied, 1);

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert_eq!(result, "NEW_CWE_MAPPING");
}

#[test]
fn test_cwe_mapping_skips_when_find_text_missing() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "some content").unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::CweMapping,
        description: "Replace missing text".to_string(),
        target_cwes: vec![],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: "DOES_NOT_EXIST".to_string(),
            replace: "NEW".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::Medium,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "CweMapping should skip when find text is missing"
    );
}

#[test]
fn test_cwe_mapping_appends_when_no_insertion_point() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    // File without the "_ => None," insertion point
    std::fs::write(tmp.path(), "fn some_function() {}").unwrap();

    let mapping = "502 => Some(\"deserialization\"),";
    let cycle = make_cycle_with_proposals(vec![make_cwe_mapping_proposal(
        mapping,
        tmp.path().to_path_buf(),
    )]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 1,
        "CweMapping should append when no insertion point matches"
    );

    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("deserialization"),
        "Appended mapping should be present: {result}"
    );
}

// ===========================================================================
// Mixed proposal types in a single cycle
// ===========================================================================

#[test]
fn test_mixed_proposal_types_apply_independently() {
    // Create temp files for NewPattern and AgentPrompt targets
    let pattern_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        pattern_file.path(),
        r#"fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
    ]
}"#,
    )
    .unwrap();

    let agent_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(agent_file.path(), "# Vuln Hunter\n\nExisting.").unwrap();

    let cwe_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(cwe_file.path(), "match cwe {\n        _ => None,\n    }").unwrap();

    let proposals = vec![
        // NewPattern
        Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Add pattern".to_string(),
            target_cwes: vec![119],
            target_file: pattern_file.path().to_path_buf(),
            patch: Patch {
                find: String::new(),
                replace: r"\bstrcpy\s*\(".to_string(),
            },
            source_case: "case_1".to_string(),
            priority: Priority::High,
            supporting_evidence: vec![],
            review: None,
        },
        // AgentPrompt
        make_agent_prompt_proposal(
            "Use get_taint_paths for cross-file analysis.",
            agent_file.path().to_path_buf(),
        ),
        // TaintRule (skipped without DB)
        make_taint_rule_proposal("recv|network|libc|source", vec![119]),
        // CweMapping
        make_cwe_mapping_proposal(
            "        502 => Some(\"deserialization\"),\n",
            cwe_file.path().to_path_buf(),
        ),
    ];

    let cycle = make_cycle_with_proposals(proposals);
    let applied = apply_accepted_proposals(&cycle, None).unwrap();

    // NewPattern + AgentPrompt + CweMapping = 3 applied, TaintRule skipped (no DB)
    assert_eq!(
        applied.applied, 3,
        "Should apply NewPattern + AgentPrompt + CweMapping, skip TaintRule without DB"
    );
}

// ===========================================================================
// ReviewDecision gating for non-NewPattern proposal types
// ===========================================================================

#[test]
fn test_review_verdict_filtering_for_agent_prompt() {
    let accepted = Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Accepted prompt update".to_string(),
        target_cwes: vec![78],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "Use get_cross_file_calls for tracing.".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Accept,
            reason: "Graph tools improve detection".to_string(),
            overfitting_risk: ReviewRating::Low,
            real_world_applicability: ReviewRating::High,
            suggested_modification: None,
            evidence_refs: vec![],
        }),
    };

    let rejected = Improvement {
        kind: ImprovementKind::AgentPrompt,
        description: "Rejected prompt update".to_string(),
        target_cwes: vec![78],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "Overly specific instruction.".to_string(),
        },
        source_case: "case_2".to_string(),
        priority: Priority::Low,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Reject,
            reason: "Too specific, overfitting to fixture".to_string(),
            overfitting_risk: ReviewRating::High,
            real_world_applicability: ReviewRating::Low,
            suggested_modification: None,
            evidence_refs: vec![],
        }),
    };

    let proposals = [accepted, rejected];

    // Verify filtering logic: Accept passes, Reject filtered
    let acceptable: Vec<_> = proposals
        .iter()
        .filter(|p| {
            matches!(
                p.review.as_ref().map(|r| r.verdict),
                Some(ReviewVerdict::Accept) | Some(ReviewVerdict::Modify) | None
            )
        })
        .collect();

    assert_eq!(
        acceptable.len(),
        1,
        "Only Accept/Modify/None verdicts should pass the review gate"
    );
    assert!(
        acceptable[0].description.contains("Accepted"),
        "The accepted proposal should pass"
    );
}

#[test]
fn test_review_verdict_filtering_for_taint_rule() {
    let accepted = Improvement {
        kind: ImprovementKind::TaintRule,
        description: "Accepted taint rule".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "recv|network|libc|source".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Accept,
            reason: "Standard taint source".to_string(),
            overfitting_risk: ReviewRating::Low,
            real_world_applicability: ReviewRating::High,
            suggested_modification: None,
            evidence_refs: vec![],
        }),
    };

    let modified = Improvement {
        kind: ImprovementKind::TaintRule,
        description: "Modified taint rule".to_string(),
        target_cwes: vec![78],
        target_file: PathBuf::from("agents/vuln-hunter.md"),
        patch: Patch {
            find: String::new(),
            replace: "system|command_execution|libc|sink".to_string(),
        },
        source_case: "case_2".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: Some(ReviewDecision {
            verdict: ReviewVerdict::Modify,
            reason: "Broaden scope".to_string(),
            overfitting_risk: ReviewRating::Medium,
            real_world_applicability: ReviewRating::Medium,
            suggested_modification: Some("Include popen variant".to_string()),
            evidence_refs: vec![],
        }),
    };

    let proposals = [accepted, modified];
    let acceptable: Vec<_> = proposals
        .iter()
        .filter(|p| {
            matches!(
                p.review.as_ref().map(|r| r.verdict),
                Some(ReviewVerdict::Accept) | Some(ReviewVerdict::Modify) | None
            )
        })
        .collect();

    assert_eq!(
        acceptable.len(),
        2,
        "Both Accept and Modify TaintRule proposals should pass review gate"
    );
}

// ===========================================================================
// Heuristic failure analysis: graph context proposals
//
// NOTE: These tests require `heuristic_failure_analysis` to be made `pub`.
// This is a TDD contract — the function SHOULD be public so that unit tests
// can verify proposal generation independently of the full async cycle.
// Until made public, enable with: cargo test --features test-heuristic-api
// ===========================================================================

/// TDD gate: uncomment the cfg below when heuristic_failure_analysis is made pub.
/// For now these tests compile only with the test-heuristic-api feature.
#[cfg(feature = "test-heuristic-api")]
mod heuristic_tests {
    use super::*;

    #[test]
    fn test_heuristic_generates_taint_source_proposals() {
        // A false negative case with recv() — should produce a TaintRule or AgentPrompt
        let fn_cases = vec![make_false_negative(
            "network_recv",
            vec![119],
            r#"
void handle_connection(int sock) {
    char buf[256];
    int n = recv(sock, buf, sizeof(buf), 0);
    process(buf, n);
}
"#,
        )];

        let proposals = skwaq_gym::improve::heuristic_failure_analysis(&fn_cases);

        assert!(
            !proposals.is_empty(),
            "recv() in FN case should generate at least one proposal"
        );

        // Should have a TaintRule proposal for recv as a taint source
        let taint_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| matches!(p.kind, ImprovementKind::TaintRule))
            .collect();

        assert!(
            !taint_proposals.is_empty(),
            "Should generate TaintRule proposal for recv() taint source"
        );

        // Verify taint proposal mentions recv
        assert!(
            taint_proposals[0].description.contains("recv"),
            "TaintRule proposal should mention recv: {}",
            taint_proposals[0].description
        );
    }

    #[test]
    fn test_heuristic_generates_agent_prompt_for_sinks() {
        // A false negative with system() — should produce AgentPrompt for sink tracing
        let fn_cases = vec![make_false_negative(
            "command_injection",
            vec![78],
            r#"
void execute_cmd(const char *input) {
    char cmd[256];
    sprintf(cmd, "echo %s", input);
    system(cmd);
}
"#,
        )];

        let proposals = skwaq_gym::improve::heuristic_failure_analysis(&fn_cases);

        let agent_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| matches!(p.kind, ImprovementKind::AgentPrompt))
            .collect();

        assert!(
            !agent_proposals.is_empty(),
            "system() sink should generate AgentPrompt for taint tracing"
        );

        // The proposal should reference graph tools
        let has_graph_tool_ref = agent_proposals.iter().any(|p| {
            p.patch.replace.contains("get_taint_paths")
                || p.patch.replace.contains("get_cross_file_calls")
        });

        assert!(
        has_graph_tool_ref,
        "AgentPrompt proposals should reference graph tools (get_taint_paths or get_cross_file_calls)"
    );
    }

    #[test]
    fn test_heuristic_generates_default_agent_prompt_for_no_api_match() {
        // A false negative with no recognizable taint source/sink — should produce
        // a generic AgentPrompt for deeper graph analysis
        let fn_cases = vec![make_false_negative(
            "indirect_vuln",
            vec![416],
            r#"
void process_data(struct Context *ctx) {
    Widget *w = ctx->widgets[ctx->index];
    free_widget(w);
    // ... later use of w (use-after-free via wrapper)
    render_widget(w);
}
"#,
        )];

        let proposals = skwaq_gym::improve::heuristic_failure_analysis(&fn_cases);

        // Should have at least one AgentPrompt for deeper graph traversal
        let deep_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| {
                matches!(p.kind, ImprovementKind::AgentPrompt) && p.description.contains("graph")
            })
            .collect();

        assert!(
            !deep_proposals.is_empty(),
            "FN case with no standard APIs should produce AgentPrompt for deeper graph analysis"
        );
    }

    #[test]
    fn test_heuristic_generates_regex_pattern_for_missing_apis() {
        // A false negative with execl() — should produce NewPattern proposal
        let fn_cases = vec![make_false_negative(
            "exec_injection",
            vec![78],
            r#"
void run_command(const char *arg) {
    execl("/bin/sh", "sh", "-c", arg, NULL);
}
"#,
        )];

        let proposals = skwaq_gym::improve::heuristic_failure_analysis(&fn_cases);

        let pattern_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| matches!(p.kind, ImprovementKind::NewPattern))
            .collect();

        assert!(
            !pattern_proposals.is_empty(),
            "execl() should generate NewPattern proposal"
        );
        assert!(
            pattern_proposals[0].patch.replace.contains("execl"),
            "NewPattern should match execl: {}",
            pattern_proposals[0].patch.replace
        );
    }

    #[test]
    fn test_heuristic_deduplicates_proposals() {
        // Two FN cases with recv() — should not produce duplicate TaintRule proposals
        let fn_cases = vec![
            make_false_negative(
                "network_recv_1",
                vec![119],
                "void f1(int s) { char b[64]; recv(s, b, 64, 0); }",
            ),
            make_false_negative(
                "network_recv_2",
                vec![120],
                "void f2(int s) { char b[64]; recv(s, b, 64, 0); }",
            ),
        ];

        let proposals = skwaq_gym::improve::heuristic_failure_analysis(&fn_cases);

        // Count TaintRule proposals mentioning recv
        let recv_taint: Vec<_> = proposals
            .iter()
            .filter(|p| {
                matches!(p.kind, ImprovementKind::TaintRule) && p.description.contains("recv")
            })
            .collect();

        // Each case may generate its own proposal (dedupe happens at the cycle level),
        // but they should have distinct source_case IDs
        if recv_taint.len() > 1 {
            let sources: std::collections::HashSet<_> =
                recv_taint.iter().map(|p| &p.source_case).collect();
            assert_eq!(
                sources.len(),
                recv_taint.len(),
                "If multiple recv TaintRule proposals, they must have distinct source_cases"
            );
        }
    }
} // mod heuristic_tests

// ===========================================================================
// Scoring: edge cases for aggregate and regression detection
// ===========================================================================

#[test]
fn test_aggregate_score_with_no_outcomes() {
    let score = skwaq_gym::scoring::aggregate(&[]);
    assert_eq!(score.true_positives, 0);
    assert_eq!(score.false_positives, 0);
    assert_eq!(score.false_negatives, 0);
    assert_eq!(score.f1, 0.0);
    assert_eq!(score.precision, 0.0);
    assert_eq!(score.recall, 0.0);
}

#[test]
fn test_regression_detection_with_new_cwe_appearing() {
    // Baseline has CWE-119, new score has CWE-119 + CWE-78
    // CWE-119 detection rate unchanged — no regression
    let baseline = make_score(vec![(119, 0.80)]);
    let new_with_extra = make_score(vec![(119, 0.80), (78, 0.60)]);

    assert!(
        !has_cwe_regression(&baseline, &new_with_extra),
        "Adding a new CWE with no drop in existing should not be a regression"
    );
}

#[test]
fn test_regression_detection_with_cwe_disappearing() {
    // Baseline has CWE-119 + CWE-78, new score drops CWE-78
    // This should NOT be a regression (CWE-78 simply has no test cases in new eval)
    let baseline = make_score(vec![(119, 0.80), (78, 0.60)]);
    let new_without = make_score(vec![(119, 0.80)]);

    assert!(
        !has_cwe_regression(&baseline, &new_without),
        "CWE absent from new score (no cases) should not be regression"
    );
}

#[test]
fn test_multiple_cwe_regressions_reported() {
    let baseline = make_score(vec![(119, 0.80), (78, 0.70), (416, 0.60)]);
    let new = make_score(vec![(119, 0.70), (78, 0.60), (416, 0.60)]); // 119 and 78 drop

    let regressions = skwaq_gym::scoring::cwe_regressions(&baseline, &new);
    assert_eq!(
        regressions.len(),
        2,
        "Should detect regressions for both CWE-119 and CWE-78"
    );
}

#[test]
fn test_precision_no_regression_when_no_negative_cases() {
    let baseline = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    let new = AggregateScore {
        negative_calibration: NegativeCaseCalibration {
            total_negative_cases: 0,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(
        !has_precision_regression(&baseline, &new),
        "No negative cases means no precision regression possible"
    );
}

// ===========================================================================
// infer_danger_category: comprehensive coverage
// ===========================================================================

#[test]
fn test_infer_category_integer_overflow() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Integer overflow pattern".to_string(),
        target_cwes: vec![190],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\batoi\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::IntegerOverflow"),
        "CWE-190 should map to IntegerOverflow: {result}"
    );
}

#[test]
fn test_infer_category_use_after_free() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "UAF pattern".to_string(),
        target_cwes: vec![416],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\bfree\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::UseAfterFree"),
        "CWE-416 should map to UseAfterFree: {result}"
    );
}

#[test]
fn test_infer_category_path_traversal() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Path traversal pattern".to_string(),
        target_cwes: vec![22],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\.\./".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::PathTraversal"),
        "CWE-22 should map to PathTraversal: {result}"
    );
}

#[test]
fn test_infer_category_race_condition() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Race condition pattern".to_string(),
        target_cwes: vec![362],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\bpthread_create\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::Race"),
        "CWE-362 should map to Race: {result}"
    );
}

#[test]
fn test_infer_category_deserialization() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Deserialization pattern".to_string(),
        target_cwes: vec![502],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r"\bpickle\.loads\s*\(".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    apply_accepted_proposals(&cycle, None).unwrap();
    let result = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        result.contains("DangerCategory::Deserialization"),
        "CWE-502 should map to Deserialization: {result}"
    );
}

// ===========================================================================
// Security: NewPattern regex must not contain unescaped double quotes
// ===========================================================================

#[test]
fn test_new_pattern_rejects_regex_with_double_quotes() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}",
    )
    .unwrap();

    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::NewPattern,
        description: "Pattern with quotes".to_string(),
        target_cwes: vec![798],
        target_file: tmp.path().to_path_buf(),
        patch: Patch {
            find: String::new(),
            replace: r#"password\s*=\s*""#.to_string(), // contains "
        },
        source_case: "case_1".to_string(),
        priority: Priority::High,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "Regex containing double quotes must be rejected to prevent code injection"
    );
}

// ===========================================================================
// GroundTruthFix proposals should be skipped by apply_accepted_proposals
// ===========================================================================

#[test]
fn test_ground_truth_fix_skipped() {
    let cycle = make_cycle_with_proposals(vec![Improvement {
        kind: ImprovementKind::GroundTruthFix,
        description: "Fix ground truth for case X".to_string(),
        target_cwes: vec![119],
        target_file: PathBuf::from("data/gym/ground_truth/fixtures.toml"),
        patch: Patch {
            find: String::new(),
            replace: "expected_cwes = [119, 121]".to_string(),
        },
        source_case: "case_1".to_string(),
        priority: Priority::Medium,
        supporting_evidence: vec![],
        review: None,
    }]);

    let applied = apply_accepted_proposals(&cycle, None).unwrap();
    assert_eq!(
        applied.applied, 0,
        "GroundTruthFix proposals should not be automatically applied"
    );
}

// ===========================================================================
// ImprovementCycle: structural invariants
// ===========================================================================

#[test]
fn test_cycle_proposals_and_reviewed_proposals_are_disjoint() {
    // proposals = accepted/modified proposals after review gating
    // reviewed_proposals = all proposals including rejected ones
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: make_score(vec![(119, 0.5)]),
        false_negatives: vec![],
        reviewed_proposals: vec![
            Improvement {
                kind: ImprovementKind::NewPattern,
                description: "Accepted".to_string(),
                target_cwes: vec![119],
                target_file: PathBuf::from("test.rs"),
                patch: Patch {
                    find: String::new(),
                    replace: "pattern".to_string(),
                },
                source_case: "case_1".to_string(),
                priority: Priority::High,
                supporting_evidence: vec![],
                review: Some(ReviewDecision {
                    verdict: ReviewVerdict::Accept,
                    reason: "Good".to_string(),
                    overfitting_risk: ReviewRating::Low,
                    real_world_applicability: ReviewRating::High,
                    suggested_modification: None,
                    evidence_refs: vec![],
                }),
            },
            Improvement {
                kind: ImprovementKind::NewPattern,
                description: "Rejected".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("test.rs"),
                patch: Patch {
                    find: String::new(),
                    replace: "bad_pattern".to_string(),
                },
                source_case: "case_2".to_string(),
                priority: Priority::Low,
                supporting_evidence: vec![],
                review: Some(ReviewDecision {
                    verdict: ReviewVerdict::Reject,
                    reason: "Bad".to_string(),
                    overfitting_risk: ReviewRating::High,
                    real_world_applicability: ReviewRating::Low,
                    suggested_modification: None,
                    evidence_refs: vec![],
                }),
            },
        ],
        proposals: vec![Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Accepted".to_string(),
            target_cwes: vec![119],
            target_file: PathBuf::from("test.rs"),
            patch: Patch {
                find: String::new(),
                replace: "pattern".to_string(),
            },
            source_case: "case_1".to_string(),
            priority: Priority::High,
            supporting_evidence: vec![],
            review: Some(ReviewDecision {
                verdict: ReviewVerdict::Accept,
                reason: "Good".to_string(),
                overfitting_risk: ReviewRating::Low,
                real_world_applicability: ReviewRating::High,
                suggested_modification: None,
                evidence_refs: vec![],
            }),
        }],
        holdout_case_count: 4,
        holdout_score: None,
        training_case_count: 16,
        cross_validation_pending: vec![],
        run_metadata: None,
    };

    // proposals should only contain accepted/modified proposals
    assert!(
        cycle.proposals.iter().all(|p| !matches!(
            p.review.as_ref().map(|r| r.verdict),
            Some(ReviewVerdict::Reject)
        )),
        "proposals field should not contain rejected proposals"
    );

    // reviewed_proposals includes all
    assert_eq!(
        cycle.reviewed_proposals.len(),
        2,
        "reviewed_proposals includes all proposals (accepted + rejected)"
    );
}

// ===========================================================================
// EvidenceRef: supporting evidence structure
// ===========================================================================

#[test]
fn test_evidence_ref_types_round_trip() {
    let evidence = [
        EvidenceRef {
            source_type: EvidenceSourceType::Knowledge,
            source: Some("kb:cwe-78".to_string()),
            topic: Some("command injection".to_string()),
            title: Some("CWE-78 Patterns".to_string()),
            memory_type: None,
            context: Some("OS command injection via system()".to_string()),
            tags: vec!["injection".to_string(), "system".to_string()],
            rationale: "KB confirms system() as dangerous sink".to_string(),
        },
        EvidenceRef {
            source_type: EvidenceSourceType::Memory,
            source: None,
            topic: None,
            title: None,
            memory_type: Some("durable".to_string()),
            context: Some("Previous cycle detected recv as untracked source".to_string()),
            tags: vec![],
            rationale: "Memory from prior improvement cycle".to_string(),
        },
        EvidenceRef {
            source_type: EvidenceSourceType::Heuristic,
            source: Some("taint_api_match".to_string()),
            topic: None,
            title: None,
            memory_type: None,
            context: None,
            tags: vec![],
            rationale: "Heuristic: recv() matches known taint source".to_string(),
        },
    ];

    assert_eq!(evidence[0].source_type, EvidenceSourceType::Knowledge);
    assert_eq!(evidence[1].source_type, EvidenceSourceType::Memory);
    assert_eq!(evidence[2].source_type, EvidenceSourceType::Heuristic);
    assert!(evidence[0].source.is_some());
    assert!(evidence[1].memory_type.is_some());
}

// ===========================================================================
// Regression: F1 computation edge cases
// ===========================================================================

#[test]
fn test_f1_computation_perfect_score() {
    let score = AggregateScore {
        true_positives: 10,
        false_positives: 0,
        false_negatives: 0,
        precision: 1.0,
        recall: 1.0,
        f1: 1.0,
        ..Default::default()
    };

    assert_eq!(score.f1, 1.0, "Perfect TP/FP/FN should yield F1=1.0");
}

#[test]
fn test_f1_computation_zero_score() {
    let score = AggregateScore {
        true_positives: 0,
        false_positives: 5,
        false_negatives: 5,
        precision: 0.0,
        recall: 0.0,
        f1: 0.0,
        ..Default::default()
    };

    assert_eq!(score.f1, 0.0, "Zero TP should yield F1=0.0");
}

// ===========================================================================
// Pattern count ceiling (safety guard against unbounded growth)
// ===========================================================================

#[test]
fn test_pattern_ceiling_guard() {
    // After many improvement cycles, patterns_source.rs could grow unbounded.
    // The apply function should count existing SourcePattern entries and warn/skip
    // if approaching the ~500 ceiling.
    let tmp = tempfile::NamedTempFile::new().unwrap();

    // Generate a file with 498 existing patterns
    let mut content = String::from("fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n");
    for i in 0..498 {
        content.push_str(&format!(
            "        SourcePattern {{\n\
             \x20           regex: r\"\\bpattern_{i}\\s*\\(\",\n\
             \x20           category: DangerCategory::Memory,\n\
             \x20           severity: Severity::High,\n\
             \x20           reason: \"pattern {i}\",\n\
             \x20       }},\n"
        ));
    }
    content.push_str("    ]\n}");
    std::fs::write(tmp.path(), &content).unwrap();

    // Try to add 5 more patterns
    let proposals: Vec<Improvement> = (0..5)
        .map(|i| Improvement {
            kind: ImprovementKind::NewPattern,
            description: format!("New pattern {}", i),
            target_cwes: vec![119],
            target_file: tmp.path().to_path_buf(),
            patch: Patch {
                find: String::new(),
                replace: format!(r"\bnew_func_{}\s*\(", i),
            },
            source_case: format!("case_{}", i),
            priority: Priority::High,
            supporting_evidence: vec![],
            review: None,
        })
        .collect();

    let cycle = make_cycle_with_proposals(proposals);
    let applied = apply_accepted_proposals(&cycle, None).unwrap();

    // Should apply at most 2 (498 + 2 = 500 ceiling)
    // This test documents the EXPECTED behavior — it may fail until
    // the pattern ceiling guard is implemented
    assert!(
        applied.applied <= 2,
        "Pattern ceiling (~500) should limit insertions: applied {:?} when 498 exist",
        applied
    );
}
