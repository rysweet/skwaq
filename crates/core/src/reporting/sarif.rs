//! SARIF (Static Analysis Results Interchange Format) output.
//!
//! Generates SARIF v2.1.0 JSON for integration with GitHub Code Scanning,
//! Azure DevOps, and other SARIF-compatible tools.

use serde::Serialize;
use serde_json::Value;

use crate::graph::GraphDb;

/// Top-level SARIF v2.1.0 document.
#[derive(Serialize)]
struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "helpUri")]
    help_uri: String,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<SarifMessage>,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u64,
}

#[derive(Serialize)]
struct SarifResultProperties {
    severity: String,
    confidence: f64,
}

/// Map vulnerability severity to SARIF level.
fn severity_to_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "warning",
    }
}

/// Build a CWE help URI.
fn cwe_help_uri(cwe_id: &str) -> String {
    let numeric = cwe_id
        .strip_prefix("CWE-")
        .unwrap_or(cwe_id);
    format!("https://cwe.mitre.org/data/definitions/{numeric}.html")
}

/// Generate a SARIF v2.1.0 JSON document from a flat value array.
///
/// Each value should have fields: `title`, `severity`, `description`,
/// `cwe_id`, `function_id`, `confidence`.
pub fn generate_sarif(findings: &[Value]) -> anyhow::Result<String> {
    let mut rules: Vec<SarifRule> = Vec::new();
    let mut results: Vec<SarifResult> = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for finding in findings {
        let title = finding
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown finding");
        let severity = finding
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium");
        let description = finding
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cwe_id = finding
            .get("cwe_id")
            .and_then(|v| v.as_str())
            .unwrap_or("CWE-0");
        let function_id = finding
            .get("function_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let confidence = finding
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let rule_id = if cwe_id.is_empty() || cwe_id == "CWE-0" {
            title.replace(' ', "-").to_lowercase()
        } else {
            cwe_id.to_string()
        };

        if !seen_rules.contains(&rule_id) {
            rules.push(SarifRule {
                id: rule_id.clone(),
                name: title.to_string(),
                short_description: SarifMessage {
                    text: if description.is_empty() {
                        title.to_string()
                    } else {
                        description.chars().take(200).collect()
                    },
                },
                help_uri: cwe_help_uri(&rule_id),
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), severity.to_string()],
                },
            });
            seen_rules.insert(rule_id.clone());
        }

        results.push(SarifResult {
            rule_id: rule_id.clone(),
            level: severity_to_level(severity).into(),
            message: SarifMessage {
                text: if description.is_empty() {
                    title.to_string()
                } else {
                    description.to_string()
                },
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: function_id.to_string(),
                        description: Some(SarifMessage {
                            text: format!("Function: {function_id}"),
                        }),
                    },
                    region: None,
                },
            }],
            properties: SarifResultProperties {
                severity: severity.to_string(),
                confidence,
            },
        });
    }

    let doc = SarifDocument {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "skwaq".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    information_uri: "https://github.com/rysweet/skwaq".into(),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&doc).map_err(Into::into)
}

/// Generate a SARIF report for a given investigation from the graph DB.
pub fn generate_sarif_for_investigation(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<String> {
    let mut stmt = db.conn().prepare(
        "SELECT id, title, description, severity, cvss, cwe_id, \
         function_id, evidence, confidence, investigation_id \
         FROM vulnerabilities WHERE investigation_id = ?1 \
         ORDER BY cvss DESC",
    )?;

    let vulns: Vec<Value> = stmt
        .query_map([investigation_id], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "title": row.get::<_, String>(1)?,
                "description": row.get::<_, String>(2)?,
                "severity": row.get::<_, String>(3)?,
                "cvss": row.get::<_, f64>(4)?,
                "cwe_id": row.get::<_, String>(5)?,
                "function_id": row.get::<_, String>(6)?,
                "evidence": row.get::<_, String>(7)?,
                "confidence": row.get::<_, f64>(8)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();

    generate_sarif(&vulns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sarif_empty() {
        let result = generate_sarif(&[]).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(doc["version"], "2.1.0");
        assert!(doc["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_generate_sarif_single_finding() {
        let findings = vec![serde_json::json!({
            "title": "Buffer overflow in parse_header",
            "severity": "critical",
            "description": "Unchecked memcpy allows heap overflow",
            "cwe_id": "CWE-122",
            "function_id": "parse_header",
            "confidence": 0.92
        })];

        let result = generate_sarif(&findings).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result).unwrap();

        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "CWE-122");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["properties"]["severity"], "critical");

        let rules = doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "CWE-122");
    }

    #[test]
    fn test_generate_sarif_multiple_findings() {
        let findings = vec![
            serde_json::json!({
                "title": "Buffer overflow",
                "severity": "high",
                "description": "Stack buffer overflow",
                "cwe_id": "CWE-121",
                "function_id": "func_a",
                "confidence": 0.85
            }),
            serde_json::json!({
                "title": "Format string",
                "severity": "medium",
                "description": "User-controlled format string",
                "cwe_id": "CWE-134",
                "function_id": "func_b",
                "confidence": 0.70
            }),
            serde_json::json!({
                "title": "Info leak",
                "severity": "low",
                "description": "Memory disclosure",
                "cwe_id": "CWE-200",
                "function_id": "func_c",
                "confidence": 0.50
            }),
        ];

        let result = generate_sarif(&findings).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result).unwrap();

        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
    }

    #[test]
    fn test_severity_to_level() {
        assert_eq!(severity_to_level("critical"), "error");
        assert_eq!(severity_to_level("high"), "error");
        assert_eq!(severity_to_level("medium"), "warning");
        assert_eq!(severity_to_level("low"), "note");
        assert_eq!(severity_to_level("info"), "note");
        assert_eq!(severity_to_level("unknown"), "warning");
    }

    #[test]
    fn test_cwe_help_uri() {
        assert_eq!(
            cwe_help_uri("CWE-122"),
            "https://cwe.mitre.org/data/definitions/122.html"
        );
    }

    #[test]
    fn test_sarif_from_investigation() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, status, created_at) VALUES (?1, ?2, ?3, ?4)",
            &[&"inv1", &"Test Investigation", &"active", &"2026-03-10"],
        )
        .unwrap();

        db.execute(
            "INSERT INTO vulnerabilities (id, title, description, severity, cvss, cwe_id, function_id, evidence, confidence, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                &"v1" as &dyn rusqlite::types::ToSql,
                &"Buffer overflow",
                &"Heap overflow in parse_header",
                &"critical",
                &9.8_f64 as &dyn rusqlite::types::ToSql,
                &"CWE-122",
                &"parse_header",
                &"memcpy without bounds check",
                &0.95_f64 as &dyn rusqlite::types::ToSql,
                &"inv1",
            ],
        )
        .unwrap();

        let result = generate_sarif_for_investigation(&db, "inv1").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "CWE-122");
    }
}
