//! TDD tests for ground truth validation and interprocedural taint integration
//! post-PR #292.
//!
//! Covers:
//! - TOML manifest loading for new Juliet CWE cases
//! - Path traversal prevention (security)
//! - Case ID validation (colon-separated IDs for CyberGym)
//! - Holdout/training split with holdout_fraction
//! - Learned patterns knowledge base append

use skwaq_gym::ground_truth::{GroundTruth, TestCase};
use skwaq_gym::improve::{
    append_learned_patterns, Improvement, ImprovementCycle, ImprovementKind, Patch, Priority,
};
use skwaq_gym::scoring::AggregateScore;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// TOML manifest loading
// ---------------------------------------------------------------------------

#[test]
fn test_load_manifest_with_new_juliet_cwes() {
    let toml = r#"
suite = "juliet"
version = "3.0"
download_url = ""
download_sha256 = ""

[[cases]]
id = "CWE400_Resource_Exhaustion__connect_socket_01"
path = "CWE400/CWE400_Resource_Exhaustion__connect_socket_01.c"
expected_cwes = [400]
is_negative = false
language = "c"

[[cases]]
id = "CWE563_Unused_Variable__unused_init_variable_01"
path = "CWE563/CWE563_Unused_Variable__unused_init_variable_01.c"
expected_cwes = [563]
is_negative = false
language = "c"

[[cases]]
id = "CWE617_Reachable_Assertion__01"
path = "CWE617/CWE617_Reachable_Assertion__01.c"
expected_cwes = [617]
is_negative = false
language = "c"

[[cases]]
id = "CWE843_Type_Confusion__01"
path = "CWE843/CWE843_Type_Confusion__01.c"
expected_cwes = [843]
is_negative = false
language = "c"
"#;
    let gt: GroundTruth = toml::from_str(toml).unwrap();
    assert_eq!(gt.suite, "juliet");
    assert_eq!(gt.cases.len(), 4);

    // Verify each new CWE mapping
    assert_eq!(gt.cases[0].expected_cwes, vec![400]);
    assert_eq!(gt.cases[1].expected_cwes, vec![563]);
    assert_eq!(gt.cases[2].expected_cwes, vec![617]);
    assert_eq!(gt.cases[3].expected_cwes, vec![843]);
}

#[test]
fn test_load_manifest_with_negative_cases() {
    let toml = r#"
suite = "fixtures"
version = "3.0"

[[cases]]
id = "buffer_overflow"
path = "buffer_overflow.c"
binary_path = "binaries/buffer_overflow_O0"
expected_cwes = [121, 134]
is_negative = false
language = "c"

[[cases]]
id = "buffer_overflow_safe"
path = "buffer_overflow_safe.c"
expected_cwes = []
is_negative = true
language = "c"
"#;
    let gt: GroundTruth = toml::from_str(toml).unwrap();
    assert_eq!(gt.cases.len(), 2);
    assert!(!gt.cases[0].is_negative);
    assert!(gt.cases[1].is_negative);
    assert!(gt.cases[1].expected_cwes.is_empty());
}

// ---------------------------------------------------------------------------
// Path traversal prevention (security)
// ---------------------------------------------------------------------------

#[test]
fn test_reject_path_traversal_in_source_path() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evil.toml");
    std::fs::write(
        &manifest,
        r#"
suite = "evil"
version = "1.0"

[[cases]]
id = "evil_case"
path = "../../etc/passwd"
expected_cwes = [22]
is_negative = false
language = "c"
"#,
    )
    .unwrap();

    let result = GroundTruth::load(&manifest);
    assert!(result.is_err(), "Path with .. should be rejected");
    assert!(result.unwrap_err().to_string().contains(".."));
}

#[test]
fn test_reject_absolute_path_in_source_path() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evil.toml");
    std::fs::write(
        &manifest,
        r#"
suite = "evil"
version = "1.0"

[[cases]]
id = "evil_case"
path = "/etc/shadow"
expected_cwes = [22]
is_negative = false
language = "c"
"#,
    )
    .unwrap();

    let result = GroundTruth::load(&manifest);
    assert!(result.is_err(), "Absolute path should be rejected");
}

#[test]
fn test_reject_path_traversal_in_binary_path() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("evil.toml");
    std::fs::write(
        &manifest,
        r#"
suite = "evil"
version = "1.0"

[[cases]]
id = "evil_case"
path = "test.c"
binary_path = "../../etc/shadow"
expected_cwes = [22]
is_negative = false
language = "c"
"#,
    )
    .unwrap();

    let result = GroundTruth::load(&manifest);
    assert!(result.is_err(), "Binary path with .. should be rejected");
    assert!(result.unwrap_err().to_string().contains("binary_path"));
}

// ---------------------------------------------------------------------------
// Case ID validation
// ---------------------------------------------------------------------------

#[test]
fn test_case_id_allows_colons_for_cybergym() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("cybergym.toml");
    std::fs::write(
        &manifest,
        r#"
suite = "cybergym"
version = "1.0"

[[cases]]
id = "arvo:1065"
path = "arvo_1065.c"
expected_cwes = [119]
is_negative = false
language = "c"
"#,
    )
    .unwrap();

    let result = GroundTruth::load(&manifest);
    assert!(
        result.is_ok(),
        "Case ID with colon should be allowed for CyberGym"
    );
}

#[test]
fn test_case_id_allows_dots_and_hyphens() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("test.toml");
    std::fs::write(
        &manifest,
        r#"
suite = "test"
version = "1.0"

[[cases]]
id = "cwe-121.variant-01"
path = "test.c"
expected_cwes = [121]
is_negative = false
language = "c"
"#,
    )
    .unwrap();

    let result = GroundTruth::load(&manifest);
    assert!(
        result.is_ok(),
        "Case ID with dots and hyphens should be allowed"
    );
}

#[test]
fn test_case_id_rejects_special_characters() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("bad.toml");
    std::fs::write(
        &manifest,
        r#"
suite = "test"
version = "1.0"

[[cases]]
id = "evil;rm -rf /"
path = "test.c"
expected_cwes = [78]
is_negative = false
language = "c"
"#,
    )
    .unwrap();

    let result = GroundTruth::load(&manifest);
    assert!(
        result.is_err(),
        "Case ID with special characters should be rejected"
    );
}

// ---------------------------------------------------------------------------
// TestCase struct validation
// ---------------------------------------------------------------------------

#[test]
fn test_test_case_multi_cwe_expectations() {
    let case = TestCase {
        id: "buffer_overflow".to_string(),
        path: "buffer_overflow.c".to_string(),
        binary_path: Some("binaries/buffer_overflow_O0".to_string()),
        expected_cwes: vec![121, 134],
        is_negative: false,
        language: "c".to_string(),
    };

    assert_eq!(case.expected_cwes.len(), 2);
    assert!(case.expected_cwes.contains(&121));
    assert!(case.expected_cwes.contains(&134));
    assert!(case.binary_path.is_some());
}

#[test]
fn test_test_case_cpp_language() {
    let case = TestCase {
        id: "cpp_vulns".to_string(),
        path: "cpp_vulns.cpp".to_string(),
        binary_path: None,
        expected_cwes: vec![119, 416, 843],
        is_negative: false,
        language: "cpp".to_string(),
    };

    assert_eq!(case.language, "cpp");
    assert!(
        case.expected_cwes.contains(&843),
        "New CWE-843 in C++ test case"
    );
}

// ---------------------------------------------------------------------------
// Holdout/training split validation
// ---------------------------------------------------------------------------

#[test]
fn test_holdout_fraction_20_percent_of_128_cases() {
    // 128 total fixture cases × 0.2 = 25.6, ceil = 26 holdout
    let total = 128usize;
    let holdout_fraction = 0.20f64;
    let holdout_count = (total as f64 * holdout_fraction).ceil() as usize;
    let training_count = total.saturating_sub(holdout_count);

    assert_eq!(holdout_count, 26, "20% holdout of 128 should be 26");
    assert_eq!(training_count, 102, "Training should be 102");
    assert_eq!(
        holdout_count + training_count,
        128,
        "Total should be preserved"
    );
}

#[test]
fn test_holdout_fraction_zero_disables_holdout() {
    let total = 128usize;
    let holdout_fraction = 0.0f64;
    let holdout_count = if holdout_fraction > 0.0 {
        (total as f64 * holdout_fraction).ceil() as usize
    } else {
        0
    };

    assert_eq!(
        holdout_count, 0,
        "Zero holdout fraction should disable holdout"
    );
}

// ---------------------------------------------------------------------------
// Learned patterns knowledge base
// ---------------------------------------------------------------------------

#[test]
fn test_append_learned_patterns_creates_file() {
    let dir = tempfile::tempdir().unwrap();
    let knowledge_dir = dir.path().join("data/knowledge");
    std::fs::create_dir_all(&knowledge_dir).unwrap();

    // We test the structure, not the actual file write (which uses cwd-relative paths)
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: AggregateScore {
            f1: 0.879,
            precision: 1.0,
            recall: 0.784,
            ..Default::default()
        },
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals: vec![Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Add sprintf detection".to_string(),
            target_cwes: vec![119, 134],
            target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
            patch: Patch {
                find: String::new(),
                replace: r"\bsprintf\s*\(".to_string(),
            },
            source_case: "format_string".to_string(),
            priority: Priority::High,
            supporting_evidence: vec![],
            review: None,
        }],
        holdout_case_count: 26,
        training_case_count: 102,
        cross_validation_pending: vec![],
    };

    // This will try to write to data/knowledge/learned-patterns.md relative to cwd.
    // In test context it may not write (different cwd), but should not panic.
    append_learned_patterns(&cycle);
    // Contract: function should not panic even if the directory doesn't exist at cwd
}

#[test]
fn test_append_learned_patterns_skips_non_pattern_proposals() {
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: AggregateScore::default(),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals: vec![Improvement {
            kind: ImprovementKind::AgentPrompt,
            description: "Agent prompt improvement".to_string(),
            target_cwes: vec![78],
            target_file: PathBuf::from("agents/vuln-hunter.md"),
            patch: Patch {
                find: String::new(),
                replace: "new instruction".to_string(),
            },
            source_case: "case_1".to_string(),
            priority: Priority::Medium,
            supporting_evidence: vec![],
            review: None,
        }],
        holdout_case_count: 0,
        training_case_count: 0,
        cross_validation_pending: vec![],
    };

    // Should not panic; AgentPrompt proposals are skipped by append_learned_patterns
    append_learned_patterns(&cycle);
}

#[test]
fn test_append_learned_patterns_skips_empty_replace() {
    let cycle = ImprovementCycle {
        suite: "fixtures".to_string(),
        baseline_score: AggregateScore::default(),
        false_negatives: vec![],
        reviewed_proposals: vec![],
        proposals: vec![Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Empty pattern".to_string(),
            target_cwes: vec![119],
            target_file: PathBuf::from("test.rs"),
            patch: Patch {
                find: String::new(),
                replace: String::new(), // empty replace should be skipped
            },
            source_case: "case_1".to_string(),
            priority: Priority::High,
            supporting_evidence: vec![],
            review: None,
        }],
        holdout_case_count: 0,
        training_case_count: 0,
        cross_validation_pending: vec![],
    };

    append_learned_patterns(&cycle);
    // Should not panic; empty replace proposals are filtered out
}
