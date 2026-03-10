//! JSON output for analysis results.
//!
//! Provides a structured JSON export of vulnerability findings for
//! programmatic consumption by downstream tools and dashboards.

use serde_json::Value;

/// Generate a JSON report from analysis results.
pub fn generate_json(_findings: &[Value]) -> anyhow::Result<String> {
    todo!("JSON report generation not yet implemented")
}
