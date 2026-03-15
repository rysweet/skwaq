//! Domain types for the CyberGym adapter.
//!
//! All types use serde for JSON serialization. The `Finding.source` field
//! is private and hardcoded to "cybergym-adapter" — it cannot be overridden.

use serde::{Deserialize, Serialize};

/// Status of a completed scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// All agents completed successfully.
    Complete,
    /// Some agents failed or timed out; partial results returned.
    Partial,
    /// Scan could not produce any results.
    Failed,
}

/// A single vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding identifier.
    pub id: String,
    /// CWE identifiers associated with this finding.
    pub cwes: Vec<u32>,
    /// Severity level (e.g., "high", "medium", "low").
    pub severity: String,
    /// Short description of the finding.
    pub title: String,
    /// File where the finding was detected.
    pub file: String,
    /// Function where the finding was detected.
    pub function: String,
    /// Line number, if available.
    pub line: Option<u32>,
    /// Category of vulnerability.
    pub category: String,
    /// Source of this finding — always "cybergym-adapter".
    /// Private field; set at construction only.
    source: String,
}

impl Finding {
    /// Create a new finding. The `source` field is always "cybergym-adapter".
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        cwes: Vec<u32>,
        severity: String,
        title: String,
        file: String,
        function: String,
        line: Option<u32>,
        category: String,
    ) -> Self {
        Self {
            id,
            cwes,
            severity,
            title,
            file,
            function,
            line,
            category,
            source: "cybergym-adapter".to_string(),
        }
    }

    /// Returns the source tag (always "cybergym-adapter").
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Result of a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique run identifier.
    pub run_id: String,
    /// Target that was scanned.
    pub target: String,
    /// Status of the scan.
    pub status: ScanStatus,
    /// Findings detected during the scan.
    pub findings: Vec<Finding>,
    /// When the scan started.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// When the scan finished.
    pub finished_at: chrono::DateTime<chrono::Utc>,
    /// Number of findings truncated due to cap enforcement.
    pub truncated_count: usize,
}

/// A formatted report from scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// The scan result this report is based on.
    pub scan_result: ScanResult,
    /// Summary statistics.
    pub total_findings: usize,
    /// Findings grouped by severity.
    pub by_severity: std::collections::HashMap<String, usize>,
    /// Findings grouped by CWE.
    pub by_cwe: std::collections::HashMap<u32, usize>,
}

/// Result of a validation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether validation passed.
    pub valid: bool,
    /// Issues found during validation.
    pub issues: Vec<String>,
}

/// Adapter-specific errors.
///
/// Public messages are sanitized — no paths, no finding content.
/// Full details are logged at debug level only.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("input validation failed: {message}")]
    InputValidation { message: String },

    #[error("scan failed: {message}")]
    ScanFailed { message: String },

    #[error("output write failed: {message}")]
    OutputFailed { message: String },

    #[error("timeout after {seconds}s")]
    Timeout { seconds: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_source_is_always_cybergym_adapter() {
        let f = Finding::new(
            "f1".into(),
            vec![79],
            "high".into(),
            "test".into(),
            "main.c".into(),
            "foo".into(),
            Some(10),
            "injection".into(),
        );
        assert_eq!(f.source(), "cybergym-adapter");
    }

    #[test]
    fn finding_source_preserved_in_json_roundtrip() {
        let f = Finding::new(
            "f1".into(),
            vec![79],
            "high".into(),
            "test".into(),
            "main.c".into(),
            "foo".into(),
            None,
            "injection".into(),
        );
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"source\":\"cybergym-adapter\""));
        let deserialized: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source(), "cybergym-adapter");
    }

    #[test]
    fn scan_status_serializes_as_snake_case() {
        let json = serde_json::to_string(&ScanStatus::Complete).unwrap();
        assert_eq!(json, "\"complete\"");
        let json = serde_json::to_string(&ScanStatus::Partial).unwrap();
        assert_eq!(json, "\"partial\"");
    }
}
