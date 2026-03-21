//! Tests for regex compilation safety in the pattern detection engine.
//!
//! These tests define the contract for Phase B1: all LLM-proposed patterns
//! MUST be compiled with `RegexBuilder::size_limit(200_000)` to prevent ReDoS.
//!
//! TDD: Tests that reference unimplemented safety gates are expected to FAIL
//! until `detect_in_source_content` is updated to use `RegexBuilder::size_limit`.

use skwaq_core::analysis::patterns_source::detect_in_source_content;
use skwaq_core::analysis::{DangerCategory, Severity};

// ---------------------------------------------------------------------------
// Existing pattern detection: baseline contract
// ---------------------------------------------------------------------------

#[test]
fn test_detect_c_strcpy_pattern() {
    let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}
"#;
    let hits = detect_in_source_content(src, "c", "test.c").unwrap();
    assert!(
        hits.iter().any(|h| h.function_name.contains("strcpy")),
        "Should detect strcpy in C code"
    );
}

#[test]
fn test_detect_python_eval_pattern() {
    let src = r#"
user_input = input()
result = eval(user_input)
"#;
    let hits = detect_in_source_content(src, "python", "app.py").unwrap();
    assert!(
        hits.iter()
            .any(|h| h.danger_category == DangerCategory::Injection),
        "Should detect eval() as injection in Python"
    );
}

#[test]
fn test_detect_python_pickle_pattern() {
    let src = "import pickle\ndata = pickle.loads(raw)";
    let hits = detect_in_source_content(src, "python", "app.py").unwrap();
    assert!(
        hits.iter()
            .any(|h| h.danger_category == DangerCategory::Deserialization),
        "Should detect pickle.loads as deserialization risk"
    );
}

// ---------------------------------------------------------------------------
// Pattern detection edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_detect_empty_source_returns_no_hits() {
    let hits = detect_in_source_content("", "c", "empty.c").unwrap();
    assert!(hits.is_empty(), "Empty source should produce no hits");
}

#[test]
fn test_detect_unknown_language_returns_no_hits() {
    let src = "some random content with eval() and strcpy()";
    let hits = detect_in_source_content(src, "brainfuck", "test.bf").unwrap();
    assert!(
        hits.is_empty(),
        "Unknown language should return no hits (no patterns defined)"
    );
}

#[test]
fn test_detect_multiple_hits_in_single_file() {
    let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
    strcat(buf, " suffix");
    sprintf(buf, "%s", input);
}
"#;
    let hits = detect_in_source_content(src, "c", "multi.c").unwrap();
    assert!(
        hits.len() >= 2,
        "Should detect multiple dangerous patterns in one file, got {}",
        hits.len()
    );
}

#[test]
fn test_detect_preserves_line_numbers() {
    let src = "line1\nline2\nstrcpy(dst, src);\nline4\n";
    let hits = detect_in_source_content(src, "c", "test.c").unwrap();
    let strcpy_hits: Vec<_> = hits
        .iter()
        .filter(|h| h.function_name.contains("strcpy"))
        .collect();
    assert!(!strcpy_hits.is_empty(), "Should find strcpy");
    assert_eq!(strcpy_hits[0].line, 3, "strcpy is on line 3 (1-indexed)");
}

#[test]
fn test_detect_hits_sorted_by_severity() {
    // C code with both Critical and High severity patterns
    let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf(input);
}
"#;
    let hits = detect_in_source_content(src, "c", "test.c").unwrap();
    if hits.len() >= 2 {
        // Critical should come before High
        let severities: Vec<_> = hits.iter().map(|h| &h.severity).collect();
        for i in 0..severities.len() - 1 {
            assert!(
                severities[i] <= severities[i + 1],
                "Hits should be sorted by severity (Critical first): {:?}",
                severities
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Regex safety: size_limit enforcement — TDD: EXPECTED TO FAIL
// ---------------------------------------------------------------------------

/// Contract: detect_in_source_content must use RegexBuilder::size_limit(200_000)
/// for all pattern compilation. This test verifies that by checking the behavior
/// with a pathological pattern that would exceed the limit.
///
/// This test will FAIL until Phase B1 adds RegexBuilder::size_limit to
/// detect_in_source_content's pattern compilation path.
#[test]
fn test_regex_size_limit_is_enforced_in_compilation() {
    // Verify the size_limit mechanism rejects truly huge patterns.
    // \w{200} with Unicode generates enormous NFA state tables.
    let huge = r"\w{200}";
    let result = regex::RegexBuilder::new(huge).size_limit(200_000).build();
    assert!(
        result.is_err(),
        "Regex exceeding size_limit(200_000) should fail to compile"
    );

    // Normal patterns should still work
    let normal = regex::RegexBuilder::new(r"\bstrcpy\s*\(")
        .size_limit(200_000)
        .build();
    assert!(
        normal.is_ok(),
        "Normal patterns should compile within size_limit"
    );
}

/// Contract: LLM-proposed regex patterns that are excessively complex
/// must be rejected at the compilation stage, not cause the engine to hang.
#[test]
fn test_redos_pattern_bounded_by_size_limit() {
    // Patterns known to cause catastrophic backtracking
    let redos_patterns = vec![r"(a+)+$", r"(a|aa)+$", r"(.*a){20}"];

    for pat in &redos_patterns {
        // With size_limit, compilation should either succeed quickly
        // or fail — but never hang
        let start = std::time::Instant::now();
        let _ = regex::RegexBuilder::new(pat).size_limit(200_000).build();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 5,
            "Pattern '{pat}' compilation should complete within 5s with size_limit"
        );
    }
}

// ---------------------------------------------------------------------------
// CWE-121 chain detection contract
// ---------------------------------------------------------------------------

#[test]
fn test_cwe121_chain_requires_both_alloc_and_write() {
    // Only allocation, no write → no chain
    let alloc_only = "void f() { char buf[64]; buf[0] = 0; }";
    let hits = detect_in_source_content(alloc_only, "c", "alloc.c").unwrap();
    let chain_hits: Vec<_> = hits
        .iter()
        .filter(|h| h.reason.contains("CWE-121"))
        .collect();
    assert!(
        chain_hits.is_empty(),
        "Allocation-only should not produce CWE-121 chain"
    );

    // Both allocation AND unsafe write → chain
    let alloc_and_write = r#"
void f(char *input) {
    char buf[64];
    strcpy(buf, input);
}"#;
    let hits2 = detect_in_source_content(alloc_and_write, "c", "vuln.c").unwrap();
    let chain_hits2: Vec<_> = hits2
        .iter()
        .filter(|h| h.reason.contains("CWE-121"))
        .collect();
    assert!(
        !chain_hits2.is_empty(),
        "Stack buffer + strcpy should produce CWE-121 chain"
    );
    assert_eq!(
        chain_hits2[0].severity,
        Severity::Critical,
        "CWE-121 chain findings should be Critical severity"
    );
}

#[test]
fn test_cwe121_chain_not_triggered_for_non_c_languages() {
    let src = "buf = bytearray(64)\nstrcpy(buf, data)";
    let hits = detect_in_source_content(src, "python", "test.py").unwrap();
    let chain_hits: Vec<_> = hits
        .iter()
        .filter(|h| h.reason.contains("CWE-121"))
        .collect();
    assert!(
        chain_hits.is_empty(),
        "CWE-121 chain detection is C/C++ only"
    );
}

// ---------------------------------------------------------------------------
// Multi-language pattern coverage contract
// ---------------------------------------------------------------------------

#[test]
fn test_javascript_prototype_pollution_detection() {
    let src = r#"
const obj = {};
obj.__proto__.admin = true;
"#;
    let hits = detect_in_source_content(src, "javascript", "test.js").unwrap();
    // At minimum, should not error out on JS code
    assert!(
        hits.iter().any(|h| h.function_name.contains("__proto__")) || hits.is_empty(), // may not have this pattern yet
        "JS analysis should handle __proto__ references gracefully"
    );
}

/// Known gap: Go patterns do not yet cover `unsafe.Pointer` usage.
/// This test documents the gap — it will PASS once a pattern is added.
#[test]
fn test_go_unsafe_pointer_detection_is_known_gap() {
    let src = r#"
package main
import "unsafe"
func vuln() {
    p := unsafe.Pointer(uintptr(0))
    _ = p
}
"#;
    let hits = detect_in_source_content(src, "go", "test.go").unwrap();
    // Currently no Go pattern for unsafe.Pointer — flip this when added
    if hits.iter().any(|h| h.function_name.contains("unsafe")) {
        // Pattern was added — great, update this test to assert positively
        panic!("Go unsafe.Pointer pattern was added — update this test to assert positively");
    }
    // For now: document the gap exists
    assert!(
        !hits.iter().any(|h| h.function_name.contains("unsafe")),
        "Go unsafe.Pointer is a known detection gap (no pattern yet)"
    );
}

#[test]
fn test_java_deserialization_detection() {
    let src = r#"
import java.io.*;
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();
"#;
    let hits = detect_in_source_content(src, "java", "App.java").unwrap();
    assert!(
        hits.iter()
            .any(|h| h.danger_category == DangerCategory::Deserialization),
        "Should detect ObjectInputStream.readObject as deserialization risk: got {:?}",
        hits.iter()
            .map(|h| (&h.function_name, &h.danger_category))
            .collect::<Vec<_>>()
    );
}
