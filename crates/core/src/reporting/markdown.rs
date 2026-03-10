//! Markdown report generation.
//!
//! Produces a human-readable Markdown vulnerability assessment report
//! suitable for code review or documentation.

use serde_json::Value;

/// Generate a Markdown report from analysis results.
pub fn generate_markdown(_findings: &[Value]) -> anyhow::Result<String> {
    todo!("Markdown report generation not yet implemented")
}
