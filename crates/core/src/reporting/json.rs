//! JSON output for analysis results.
//!
//! Provides a structured JSON export of vulnerability findings for
//! programmatic consumption by downstream tools and dashboards.

use crate::graph::GraphDb;
use serde::Serialize;
use serde_json::Value;

/// A finding record suitable for JSON serialization.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub evidence: String,
    pub agent: String,
    pub timestamp: String,
    pub investigation_id: String,
}

/// A vulnerability record suitable for JSON serialization.
#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss: f64,
    pub cwe_id: String,
    pub function_id: String,
    pub evidence: String,
    pub confidence: f64,
    pub investigation_id: String,
}

/// Full JSON report structure.
#[derive(Debug, Clone, Serialize)]
pub struct JsonReport {
    pub investigation_id: String,
    pub investigation_name: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub findings: Vec<Finding>,
}

/// Generate a JSON report from analysis results stored in the value array.
pub fn generate_json(_findings: &[Value]) -> anyhow::Result<String> {
    serde_json::to_string_pretty(_findings).map_err(Into::into)
}

/// Generate a full JSON report for a given investigation from the graph DB.
pub fn generate_report_for_investigation(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<String> {
    // Get investigation name
    let inv_name: String = db
        .conn()
        .query_row(
            "SELECT name FROM investigations WHERE id = ?1",
            [investigation_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "unknown".to_string());

    // Query vulnerabilities
    let mut vuln_stmt = db.conn().prepare(
        "SELECT id, title, description, severity, cvss, cwe_id, \
         function_id, evidence, confidence, investigation_id \
         FROM vulnerabilities WHERE investigation_id = ?1 \
         ORDER BY cvss DESC",
    )?;
    let vulns: Vec<Vulnerability> = vuln_stmt
        .query_map([investigation_id], |row| {
            Ok(Vulnerability {
                id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                severity: row.get(3)?,
                cvss: row.get(4)?,
                cwe_id: row.get(5)?,
                function_id: row.get(6)?,
                evidence: row.get(7)?,
                confidence: row.get(8)?,
                investigation_id: row.get(9)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    // Query findings
    let mut find_stmt = db.conn().prepare(
        "SELECT id, title, evidence, agent, timestamp, investigation_id \
         FROM findings WHERE investigation_id = ?1 \
         ORDER BY timestamp DESC",
    )?;
    let findings: Vec<Finding> = find_stmt
        .query_map([investigation_id], |row| {
            Ok(Finding {
                id: row.get(0)?,
                title: row.get(1)?,
                evidence: row.get(2)?,
                agent: row.get(3)?,
                timestamp: row.get(4)?,
                investigation_id: row.get(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    let report = JsonReport {
        investigation_id: investigation_id.to_string(),
        investigation_name: inv_name,
        vulnerabilities: vulns,
        findings,
    };

    serde_json::to_string_pretty(&report).map_err(Into::into)
}
