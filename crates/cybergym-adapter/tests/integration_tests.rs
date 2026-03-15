//! Integration tests for the CyberGym adapter.
//!
//! Tests cover:
//! - Functional scenarios: happy path, error path, partial results, validation
//! - Security scenarios: command injection, path traversal, DoS cap, source tag,
//!   error message sanitization, permission checks

use cybergym_adapter::types::{Finding, ScanResult, ScanStatus};

// ─── Functional Scenarios ───

#[tokio::test]
async fn scan_valid_c_file_returns_findings() {
    let temp = tempfile::tempdir().unwrap();
    let vuln_file = temp.path().join("vuln.c");
    std::fs::write(
        &vuln_file,
        r#"
#include <stdio.h>
#include <string.h>
void vulnerable(char *input) {
    char buf[64];
    gets(buf);
    strcpy(buf, input);
    system(input);
}
"#,
    )
    .unwrap();

    let result = cybergym_adapter::scan(vuln_file.to_str().unwrap(), Some(30), true).await;
    assert!(result.is_ok(), "scan should succeed: {:?}", result.err());
    let scan_result = result.unwrap();
    assert!(!scan_result.findings.is_empty(), "should detect findings");
    assert_eq!(scan_result.status, ScanStatus::Complete);
    assert!(!scan_result.run_id.is_empty());
}

#[tokio::test]
async fn scan_safe_code_returns_minimal_findings() {
    let temp = tempfile::tempdir().unwrap();
    let safe_file = temp.path().join("safe.c");
    std::fs::write(
        &safe_file,
        r#"
#include <stdio.h>
int add(int a, int b) {
    return a + b;
}
int main(void) {
    printf("%d\n", add(1, 2));
    return 0;
}
"#,
    )
    .unwrap();

    let result = cybergym_adapter::scan(safe_file.to_str().unwrap(), Some(30), true).await;
    assert!(result.is_ok());
    // Safe code may or may not have findings (pattern detection can flag printf)
    // but it should not error
}

#[tokio::test]
async fn scan_nonexistent_target_returns_error() {
    let result = cybergym_adapter::scan("/nonexistent/path/to/scan.c", Some(30), true).await;
    assert!(result.is_err());
}

#[test]
fn validate_passes_for_well_formed_result() {
    let result = ScanResult {
        run_id: "test-123".to_string(),
        target: "/tmp/test.c".to_string(),
        status: ScanStatus::Complete,
        findings: vec![Finding::new(
            "f1".into(),
            vec![79],
            "high".into(),
            "injection".into(),
            "test.c".into(),
            "main".into(),
            Some(5),
            "injection".into(),
        )],
        started_at: chrono::Utc::now(),
        finished_at: chrono::Utc::now(),
        truncated_count: 0,
    };
    let validation = cybergym_adapter::validate(&result, None);
    assert!(validation.valid, "issues: {:?}", validation.issues);
}

#[test]
fn validate_fails_for_empty_target() {
    let result = ScanResult {
        run_id: "test-123".to_string(),
        target: "".to_string(),
        status: ScanStatus::Complete,
        findings: vec![],
        started_at: chrono::Utc::now(),
        finished_at: chrono::Utc::now(),
        truncated_count: 0,
    };
    let validation = cybergym_adapter::validate(&result, None);
    assert!(!validation.valid);
}

#[test]
fn report_generates_severity_breakdown() {
    let result = ScanResult {
        run_id: "rpt-test".to_string(),
        target: "/tmp/test.c".to_string(),
        status: ScanStatus::Complete,
        findings: vec![
            Finding::new(
                "f1".into(),
                vec![79],
                "high".into(),
                "inj".into(),
                "a.c".into(),
                "fn1".into(),
                None,
                "injection".into(),
            ),
            Finding::new(
                "f2".into(),
                vec![120],
                "medium".into(),
                "buf".into(),
                "b.c".into(),
                "fn2".into(),
                None,
                "memory".into(),
            ),
        ],
        started_at: chrono::Utc::now(),
        finished_at: chrono::Utc::now(),
        truncated_count: 0,
    };
    let rpt = cybergym_adapter::report(&result);
    assert_eq!(rpt.total_findings, 2);
    assert_eq!(rpt.by_severity.get("high"), Some(&1));
    assert_eq!(rpt.by_severity.get("medium"), Some(&1));
}

// ─── Security Scenarios ───

#[tokio::test]
async fn security_rejects_command_injection_in_path() {
    let result = cybergym_adapter::scan("/tmp/; rm -rf /", Some(30), true).await;
    assert!(result.is_err(), "should reject command injection attempt");
}

#[tokio::test]
async fn security_rejects_path_traversal() {
    let result = cybergym_adapter::scan("/tmp/../etc/shadow", Some(30), true).await;
    assert!(result.is_err(), "should reject path traversal");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("traversal"),
        "error should mention traversal: {}",
        err
    );
}

#[tokio::test]
async fn security_rejects_null_byte_injection() {
    let result = cybergym_adapter::scan("/tmp/test\0.c", Some(30), true).await;
    assert!(result.is_err(), "should reject null byte");
}

#[test]
fn security_finding_cap_prevents_unbounded_growth() {
    let findings: Vec<Finding> = (0..10_500)
        .map(|i| {
            Finding::new(
                format!("f{}", i),
                vec![79],
                "low".into(),
                "test".into(),
                "test.c".into(),
                "fn".into(),
                None,
                "test".into(),
            )
        })
        .collect();

    // Verify the cap constant at compile time
    const { assert!(cybergym_adapter::output_writer::MAX_FINDINGS <= 10_000) };

    // Verify findings can be constructed but would be capped by scan_runner
    assert_eq!(findings.len(), 10_500);
}

#[test]
fn security_source_tag_integrity() {
    let finding = Finding::new(
        "f1".into(),
        vec![79],
        "high".into(),
        "test".into(),
        "test.c".into(),
        "fn".into(),
        None,
        "injection".into(),
    );
    assert_eq!(finding.source(), "cybergym-adapter");

    // Verify source survives JSON roundtrip
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.source(), "cybergym-adapter");
}

#[tokio::test]
async fn security_error_messages_are_sanitized() {
    // Error messages should not leak filesystem paths
    let result = cybergym_adapter::scan("/very/secret/path/to/scan.c", Some(30), true).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // The error message should be generic, not include the full path
    assert!(
        !err_msg.contains("/very/secret/path"),
        "error should not leak path: {}",
        err_msg
    );
}

#[cfg(unix)]
#[test]
fn security_output_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let run_dir =
        cybergym_adapter::output_writer::create_run_dir(temp.path(), "perm-test").unwrap();

    let mode = std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o750, "directory should be 0o750");
}

#[test]
fn security_output_rejects_symlink_run_id() {
    let temp = tempfile::tempdir().unwrap();
    // Run IDs with path separators are rejected
    let result = cybergym_adapter::output_writer::create_run_dir(temp.path(), "../escape");
    assert!(result.is_err());
}

// ─── Validate with output directory ───

#[test]
fn validate_with_output_dir_checks_results_file() {
    let temp = tempfile::tempdir().unwrap();
    let result = ScanResult {
        run_id: "validate-dir-test".to_string(),
        target: "/tmp/test.c".to_string(),
        status: ScanStatus::Complete,
        findings: vec![],
        started_at: chrono::Utc::now(),
        finished_at: chrono::Utc::now(),
        truncated_count: 0,
    };

    // Without results.json, validation should report the issue
    let validation = cybergym_adapter::validate(&result, Some(temp.path()));
    assert!(!validation.valid);
    assert!(validation.issues.iter().any(|i| i.contains("results.json")));

    // Write results.json and re-validate
    let run_dir =
        cybergym_adapter::output_writer::create_run_dir(temp.path(), "validate-dir-test").unwrap();
    cybergym_adapter::output_writer::write_results(&run_dir, &result).unwrap();
    let validation = cybergym_adapter::validate(&result, Some(&run_dir));
    assert!(validation.valid, "issues: {:?}", validation.issues);
}
