//! CyberGym Adapter: External integration layer for skwaq's vulnerability detection.
//!
//! Provides a high-level API (`scan`, `report`, `validate`) for running skwaq's
//! multi-agent analysis pipeline against arbitrary targets. All outputs are tagged
//! with source "cybergym-adapter" for metric isolation.
//!
//! # Security
//!
//! - All inputs are validated before agent execution (path traversal, length caps)
//! - No shell execution — all analysis goes through the skwaq API
//! - Output directories use restricted permissions (0o750/0o640)
//! - Finding cap (10K) prevents unbounded memory allocation
//! - 30-minute timeout prevents infinite hangs

pub mod input_validator;
pub mod output_writer;
pub mod scan_runner;
pub mod types;

use std::path::Path;
use types::{AdapterError, Report, ScanResult, ValidationResult};

/// Run a vulnerability scan against the given target.
///
/// The target can be a file or directory path. All inputs are validated
/// before any analysis begins. Returns findings tagged with source
/// "cybergym-adapter".
///
/// # Arguments
///
/// * `target` - Path to the file or directory to scan
/// * `timeout_secs` - Optional timeout in seconds (default: 1800, max: 1800)
/// * `quick_only` - If true, use pattern detection only (no LLM agents)
pub async fn scan(
    target: &str,
    timeout_secs: Option<u64>,
    quick_only: bool,
) -> Result<ScanResult, AdapterError> {
    // Validate inputs at the trust boundary
    let canonical_target = input_validator::validate_target(target)?;
    if let Some(t) = timeout_secs {
        input_validator::validate_timeout(t)?;
    }

    tracing::info!("starting scan of {}", canonical_target.display());
    scan_runner::run_scan(&canonical_target, timeout_secs, quick_only).await
}

/// Generate a report from scan results.
///
/// Aggregates findings by severity and CWE, producing a structured report
/// suitable for external consumption.
pub fn report(scan_result: &ScanResult) -> Report {
    let mut by_severity: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut by_cwe: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();

    for finding in &scan_result.findings {
        *by_severity
            .entry(finding.severity.clone())
            .or_insert(0) += 1;
        for &cwe in &finding.cwes {
            *by_cwe.entry(cwe).or_insert(0) += 1;
        }
    }

    Report {
        total_findings: scan_result.findings.len(),
        by_severity,
        by_cwe,
        scan_result: scan_result.clone(),
    }
}

/// Validate scan results for integrity and metric isolation.
///
/// Three-layer validation:
/// 1. Type-level: all findings must have source "cybergym-adapter"
/// 2. Output isolation: if output_dir is provided, verify directory structure
/// 3. Consistency: finding count matches, no empty required fields
pub fn validate(scan_result: &ScanResult, output_dir: Option<&Path>) -> ValidationResult {
    let mut issues = Vec::new();

    // Layer 1: Source tag integrity
    for (i, finding) in scan_result.findings.iter().enumerate() {
        if finding.source() != "cybergym-adapter" {
            issues.push(format!(
                "finding {} has incorrect source tag: {}",
                i,
                finding.source()
            ));
        }
    }

    // Layer 2: Output directory isolation
    if let Some(dir) = output_dir {
        if !dir.exists() {
            issues.push("output directory does not exist".to_string());
        } else if !dir.is_dir() {
            issues.push("output path is not a directory".to_string());
        } else {
            let results_file = dir.join("results.json");
            if !results_file.exists() {
                issues.push("results.json not found in output directory".to_string());
            }
        }
    }

    // Layer 3: Consistency checks
    if scan_result.run_id.is_empty() {
        issues.push("run_id is empty".to_string());
    }
    if scan_result.target.is_empty() {
        issues.push("target is empty".to_string());
    }
    for (i, finding) in scan_result.findings.iter().enumerate() {
        if finding.id.is_empty() {
            issues.push(format!("finding {} has empty id", i));
        }
        if finding.file.is_empty() {
            issues.push(format!("finding {} has empty file", i));
        }
    }

    ValidationResult {
        valid: issues.is_empty(),
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Finding, ScanStatus};

    fn make_scan_result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            run_id: "test-run".to_string(),
            target: "/tmp/test.c".to_string(),
            status: ScanStatus::Complete,
            findings,
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            truncated_count: 0,
        }
    }

    #[test]
    fn report_aggregates_by_severity() {
        let findings = vec![
            Finding::new(
                "f1".into(), vec![79], "high".into(), "inj".into(),
                "a.c".into(), "fn".into(), None, "injection".into(),
            ),
            Finding::new(
                "f2".into(), vec![120], "high".into(), "buf".into(),
                "b.c".into(), "fn".into(), None, "memory".into(),
            ),
            Finding::new(
                "f3".into(), vec![22], "low".into(), "path".into(),
                "c.c".into(), "fn".into(), None, "path".into(),
            ),
        ];
        let result = make_scan_result(findings);
        let rpt = report(&result);
        assert_eq!(rpt.total_findings, 3);
        assert_eq!(rpt.by_severity["high"], 2);
        assert_eq!(rpt.by_severity["low"], 1);
    }

    #[test]
    fn report_aggregates_by_cwe() {
        let findings = vec![
            Finding::new(
                "f1".into(), vec![79, 89], "high".into(), "multi".into(),
                "a.c".into(), "fn".into(), None, "injection".into(),
            ),
        ];
        let result = make_scan_result(findings);
        let rpt = report(&result);
        assert_eq!(rpt.by_cwe[&79], 1);
        assert_eq!(rpt.by_cwe[&89], 1);
    }

    #[test]
    fn validate_passes_for_valid_result() {
        let findings = vec![Finding::new(
            "f1".into(), vec![79], "high".into(), "test".into(),
            "a.c".into(), "fn".into(), None, "injection".into(),
        )];
        let result = make_scan_result(findings);
        let validation = validate(&result, None);
        assert!(validation.valid);
        assert!(validation.issues.is_empty());
    }

    #[test]
    fn validate_catches_empty_run_id() {
        let mut result = make_scan_result(vec![]);
        result.run_id = String::new();
        let validation = validate(&result, None);
        assert!(!validation.valid);
        assert!(validation.issues.iter().any(|i| i.contains("run_id")));
    }

    #[test]
    fn validate_catches_empty_finding_id() {
        let findings = vec![Finding::new(
            "".into(), vec![], "low".into(), "test".into(),
            "a.c".into(), "fn".into(), None, "test".into(),
        )];
        let result = make_scan_result(findings);
        let validation = validate(&result, None);
        assert!(!validation.valid);
        assert!(validation.issues.iter().any(|i| i.contains("empty id")));
    }

    #[test]
    fn validate_checks_output_directory() {
        let result = make_scan_result(vec![]);
        let validation = validate(&result, Some(Path::new("/nonexistent")));
        assert!(!validation.valid);
        assert!(
            validation
                .issues
                .iter()
                .any(|i| i.contains("does not exist"))
        );
    }

    #[tokio::test]
    async fn scan_rejects_invalid_target() {
        let result = scan("", None, true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn scan_rejects_path_traversal() {
        let result = scan("/tmp/../etc/passwd", None, true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn scan_rejects_invalid_timeout() {
        let result = scan("/tmp", Some(0), true).await;
        assert!(result.is_err());
    }
}
