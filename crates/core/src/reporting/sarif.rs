//! SARIF (Static Analysis Results Interchange Format) output.
//!
//! Generates SARIF v2.1.0 JSON for integration with GitHub Code Scanning,
//! Azure DevOps, and other SARIF-compatible tools.

use serde_json::Value;

/// Generate a SARIF v2.1.0 JSON document from analysis results.
pub fn generate_sarif(_findings: &[Value]) -> anyhow::Result<String> {
    todo!("SARIF generation not yet implemented")
}
