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
    let numeric = cwe_id.strip_prefix("CWE-").unwrap_or(cwe_id);
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
            title_to_rule_id(title)
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

/// Parse a severity string from finding evidence text.
///
/// Looks for patterns like "severity=critical" or "severity=high" in the
/// evidence string. Falls back to "medium" if no severity is found.
fn parse_severity_from_evidence(evidence: &str) -> &str {
    let lower = evidence.to_lowercase();
    if lower.contains("severity=critical") || lower.contains("critical") {
        "critical"
    } else if lower.contains("severity=high") || lower.contains("high") {
        "high"
    } else if lower.contains("severity=low") || lower.contains("low") {
        "low"
    } else if lower.contains("severity=info") || lower.contains("informational") {
        "info"
    } else {
        "medium"
    }
}

/// Convert a finding title to a SARIF-style rule ID (e.g. "Dangerous API - system" -> "dangerous-api-system").
fn title_to_rule_id(title: &str) -> String {
    title
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
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
        .collect::<Result<Vec<_>, _>>()?;

    // Also query the findings table (populated by `analyze --quick`)
    let mut find_stmt = db.conn().prepare(
        "SELECT id, title, evidence, agent, timestamp \
         FROM findings WHERE investigation_id = ?1 \
         ORDER BY timestamp DESC",
    )?;

    let findings_as_values: Vec<Value> = find_stmt
        .query_map([investigation_id], |row| {
            let title: String = row.get(1)?;
            let evidence: String = row.get(2)?;
            let agent: String = row.get(3)?;
            let severity = parse_severity_from_evidence(&evidence);
            let rule_id = title_to_rule_id(&title);
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "title": title,
                "description": evidence,
                "severity": severity,
                "cvss": 0.0,
                "cwe_id": "",
                "function_id": agent,
                "evidence": evidence,
                "confidence": 0.5,
                "rule_id": rule_id,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Combine vulnerabilities and findings
    let mut all: Vec<Value> = vulns;
    all.extend(findings_as_values);

    generate_sarif(&all)
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

        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
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

    #[test]
    fn test_sarif_includes_findings_table() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, status, created_at) VALUES (?1, ?2, ?3, ?4)",
            &[&"inv2", &"Quick Analysis", &"active", &"2026-03-10"],
        )
        .unwrap();

        // Insert a finding (from analyze --quick)
        db.execute(
            "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                &"f1",
                &"Dangerous API - system",
                &"Call to system() with user input; severity=critical",
                &"quick-analyzer",
                &"2026-03-10T12:00:00Z",
                &"inv2",
            ],
        )
        .unwrap();

        let result = generate_sarif_for_investigation(&db, "inv2").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "dangerous-api-system");
        assert_eq!(results[0]["level"], "error"); // critical -> error
    }

    #[test]
    fn test_sarif_combines_vulns_and_findings() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, status, created_at) VALUES (?1, ?2, ?3, ?4)",
            &[&"inv3", &"Combined", &"active", &"2026-03-10"],
        )
        .unwrap();

        db.execute(
            "INSERT INTO vulnerabilities (id, title, description, severity, cvss, cwe_id, function_id, evidence, confidence, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                &"v1" as &dyn rusqlite::types::ToSql,
                &"Buffer overflow",
                &"Heap overflow",
                &"high",
                &8.0_f64 as &dyn rusqlite::types::ToSql,
                &"CWE-122",
                &"parse_header",
                &"evidence",
                &0.9_f64 as &dyn rusqlite::types::ToSql,
                &"inv3",
            ],
        )
        .unwrap();

        db.execute(
            "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                &"f1",
                &"Format string bug",
                &"printf with user input; severity=high",
                &"quick-analyzer",
                &"2026-03-10T12:00:00Z",
                &"inv3",
            ],
        )
        .unwrap();

        let result = generate_sarif_for_investigation(&db, "inv3").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result).unwrap();
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_title_to_rule_id() {
        assert_eq!(
            title_to_rule_id("Dangerous API - system"),
            "dangerous-api-system"
        );
        assert_eq!(title_to_rule_id("Buffer Overflow"), "buffer-overflow");
        assert_eq!(title_to_rule_id("simple"), "simple");
    }

    #[test]
    fn test_parse_severity_from_evidence() {
        assert_eq!(
            parse_severity_from_evidence("severity=critical something"),
            "critical"
        );
        assert_eq!(parse_severity_from_evidence("severity=high"), "high");
        assert_eq!(parse_severity_from_evidence("severity=low minor"), "low");
        assert_eq!(parse_severity_from_evidence("no severity marker"), "medium");
    }
}
