//! Markdown report generation.
//!
//! Produces a human-readable Markdown vulnerability assessment report
//! suitable for code review or documentation.

use serde_json::Value;

use crate::graph::GraphDb;

/// Generate a Markdown report from a flat value array of findings.
///
/// Each value should have fields: `title`, `severity`, `description`,
/// `cwe_id`, `function_id`, `evidence`, `confidence`, `cvss`.
pub fn generate_markdown(findings: &[Value]) -> anyhow::Result<String> {
    let mut md = String::new();

    md.push_str("# Vulnerability Assessment Report\n\n");
    md.push_str(&format!(
        "**Generated**: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Summary
    md.push_str("## Summary\n\n");
    let total = findings.len();
    let critical = count_severity(findings, "critical");
    let high = count_severity(findings, "high");
    let medium = count_severity(findings, "medium");
    let low = count_severity(findings, "low");

    md.push_str("| Metric | Value |\n");
    md.push_str("| --- | --- |\n");
    md.push_str(&format!("| Total findings | {total} |\n"));
    md.push_str(&format!("| Critical | {critical} |\n"));
    md.push_str(&format!("| High | {high} |\n"));
    md.push_str(&format!("| Medium | {medium} |\n"));
    md.push_str(&format!("| Low | {low} |\n\n"));

    if findings.is_empty() {
        md.push_str("No vulnerabilities found.\n");
        return Ok(md);
    }

    // Findings table sorted by severity
    md.push_str("## Findings\n\n");
    md.push_str("| # | Severity | Title | CWE | Function | Confidence |\n");
    md.push_str("| --- | --- | --- | --- | --- | --- |\n");

    let mut sorted: Vec<&Value> = findings.iter().collect();
    sorted.sort_by_key(|a| severity_rank(a));

    for (i, finding) in sorted.iter().enumerate() {
        let title = finding.get("title").and_then(|v| v.as_str()).unwrap_or("—");
        let severity = finding
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let cwe_id = finding
            .get("cwe_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let function = finding
            .get("function_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let confidence = finding
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        md.push_str(&format!(
            "| {idx} | {sev} | {title} | {cwe} | `{func}` | {conf:.0}% |\n",
            idx = i + 1,
            sev = severity_badge(severity),
            title = title,
            cwe = cwe_link(cwe_id),
            func = function,
            conf = confidence * 100.0,
        ));
    }
    md.push('\n');

    // Detailed findings
    md.push_str("## Details\n\n");
    for (i, finding) in sorted.iter().enumerate() {
        let title = finding.get("title").and_then(|v| v.as_str()).unwrap_or("—");
        let severity = finding
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let description = finding
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("No description.");
        let cwe_id = finding
            .get("cwe_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let function = finding
            .get("function_id")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let evidence = finding
            .get("evidence")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cvss = finding.get("cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);

        md.push_str(&format!(
            "### {}. {} {}\n\n",
            i + 1,
            severity_badge(severity),
            title
        ));
        md.push_str(&format!("- **Severity**: {severity}\n"));
        if cvss > 0.0 {
            md.push_str(&format!("- **CVSS**: {cvss:.1}\n"));
        }
        md.push_str(&format!("- **CWE**: {}\n", cwe_link(cwe_id)));
        md.push_str(&format!("- **Function**: `{function}`\n\n"));
        md.push_str(&format!("{description}\n\n"));

        if !evidence.is_empty() {
            md.push_str("**Evidence**:\n\n");
            md.push_str(&format!("```\n{evidence}\n```\n\n"));
        }

        md.push_str("---\n\n");
    }

    Ok(md)
}

/// Generate a full Markdown report for a given investigation from the graph DB.
pub fn generate_markdown_for_investigation(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<String> {
    // Get investigation info
    let (inv_name, inv_target, inv_date): (String, String, String) = db
        .conn()
        .query_row(
            "SELECT name, target, created_at FROM investigations WHERE id = ?1",
            [investigation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|_| ("Unknown".into(), "Unknown".into(), "Unknown".into()));

    // Get hardening info (from functions table metadata)
    let func_count: i64 = db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM functions WHERE investigation_id = ?1",
            [investigation_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Get vulnerabilities
    let mut stmt = db.conn().prepare(
        "SELECT id, title, description, severity, cvss, cwe_id, \
         function_id, evidence, confidence \
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

    let mut md = String::new();
    md.push_str("# Vulnerability Assessment Report\n\n");
    md.push_str("## Investigation\n\n");
    md.push_str("| Field | Value |\n");
    md.push_str("| --- | --- |\n");
    md.push_str(&format!("| Name | {inv_name} |\n"));
    md.push_str(&format!("| Target | `{inv_target}` |\n"));
    md.push_str(&format!("| Date | {inv_date} |\n"));
    md.push_str(&format!("| Functions analyzed | {func_count} |\n"));
    md.push_str(&format!("| Investigation ID | `{investigation_id}` |\n\n"));

    // Query the findings table (populated by `analyze --quick`)
    let mut find_stmt = db.conn().prepare(
        "SELECT id, title, evidence, agent, timestamp \
         FROM findings WHERE investigation_id = ?1 \
         ORDER BY timestamp DESC",
    )?;

    struct FindingRow {
        id: String,
        title: String,
        evidence: String,
        agent: String,
        timestamp: String,
    }

    let findings_rows: Vec<FindingRow> = find_stmt
        .query_map([investigation_id], |row| {
            Ok(FindingRow {
                id: row.get(0)?,
                title: row.get(1)?,
                evidence: row.get(2)?,
                agent: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Append the generic vulnerability report content
    let findings_report = generate_markdown(&vulns)?;
    // Skip the title line from the generic report since we already have one
    if let Some(pos) = findings_report.find("## Summary") {
        md.push_str(&findings_report[pos..]);
    } else {
        md.push_str(&findings_report);
    }

    // Append findings section if there are any
    if !findings_rows.is_empty() {
        md.push_str("## Quick Analysis Findings\n\n");
        md.push_str(&format!(
            "The quick analysis produced **{}** finding(s).\n\n",
            findings_rows.len()
        ));
        md.push_str("| # | Title | Agent | Timestamp |\n");
        md.push_str("| --- | --- | --- | --- |\n");

        for (i, f) in findings_rows.iter().enumerate() {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                i + 1,
                f.title,
                f.agent,
                f.timestamp,
            ));
        }
        md.push('\n');

        // Detailed findings
        md.push_str("### Finding Details\n\n");
        for (i, f) in findings_rows.iter().enumerate() {
            md.push_str(&format!("#### {}. {}\n\n", i + 1, f.title));
            md.push_str(&format!("- **Agent**: {}\n", f.agent));
            md.push_str(&format!("- **Timestamp**: {}\n", f.timestamp));
            md.push_str(&format!("- **ID**: `{}`\n\n", f.id));
            if !f.evidence.is_empty() {
                md.push_str("**Evidence**:\n\n");
                md.push_str(&format!("```\n{}\n```\n\n", f.evidence));
            }
            md.push_str("---\n\n");
        }
    }

    Ok(md)
}

fn count_severity(findings: &[Value], severity: &str) -> usize {
    findings
        .iter()
        .filter(|f| {
            f.get("severity")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(severity))
                .unwrap_or(false)
        })
        .count()
}

fn severity_rank(finding: &Value) -> u8 {
    match finding
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn severity_badge(severity: &str) -> &str {
    match severity.to_lowercase().as_str() {
        "critical" => "**CRITICAL**",
        "high" => "**HIGH**",
        "medium" => "MEDIUM",
        "low" => "LOW",
        _ => severity,
    }
}

fn cwe_link(cwe_id: &str) -> String {
    if cwe_id == "—" || cwe_id.is_empty() || cwe_id == "CWE-0" {
        return "—".into();
    }
    let numeric = cwe_id.strip_prefix("CWE-").unwrap_or(cwe_id);
    format!("[{cwe_id}](https://cwe.mitre.org/data/definitions/{numeric}.html)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_markdown_empty() {
        let md = generate_markdown(&[]).unwrap();
        assert!(md.contains("# Vulnerability Assessment Report"));
        assert!(md.contains("Total findings | 0"));
        assert!(md.contains("No vulnerabilities found."));
    }

    #[test]
    fn test_generate_markdown_single_finding() {
        let findings = vec![serde_json::json!({
            "title": "Buffer overflow in parse_header",
            "severity": "critical",
            "description": "Unchecked memcpy allows heap overflow",
            "cwe_id": "CWE-122",
            "function_id": "parse_header",
            "evidence": "memcpy(buf, input, len) with no bounds check",
            "cvss": 9.8,
            "confidence": 0.92
        })];

        let md = generate_markdown(&findings).unwrap();
        assert!(md.contains("Critical | 1"));
        assert!(md.contains("Buffer overflow in parse_header"));
        assert!(md.contains("CWE-122"));
        assert!(md.contains("`parse_header`"));
        assert!(md.contains("memcpy(buf, input, len)"));
    }

    #[test]
    fn test_findings_sorted_by_severity() {
        let findings = vec![
            serde_json::json!({
                "title": "Low finding",
                "severity": "low",
                "description": "Minor issue",
                "cwe_id": "CWE-200",
                "function_id": "func_c",
                "confidence": 0.5
            }),
            serde_json::json!({
                "title": "Critical finding",
                "severity": "critical",
                "description": "Major issue",
                "cwe_id": "CWE-122",
                "function_id": "func_a",
                "confidence": 0.9
            }),
        ];

        let md = generate_markdown(&findings).unwrap();
        // Critical should appear before low in the table
        let crit_pos = md.find("Critical finding").unwrap();
        let low_pos = md.find("Low finding").unwrap();
        assert!(crit_pos < low_pos);
    }

    #[test]
    fn test_cwe_link() {
        assert_eq!(
            cwe_link("CWE-122"),
            "[CWE-122](https://cwe.mitre.org/data/definitions/122.html)"
        );
        assert_eq!(cwe_link("—"), "—");
        assert_eq!(cwe_link(""), "—");
    }

    #[test]
    fn test_markdown_from_investigation() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[&"inv1", &"Test", &"/usr/bin/test", &"active", &"2026-03-10"],
        )
        .unwrap();

        db.execute(
            "INSERT INTO vulnerabilities (id, title, description, severity, cvss, cwe_id, function_id, evidence, confidence, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                &"v1" as &dyn rusqlite::types::ToSql,
                &"Test vuln",
                &"A test vulnerability",
                &"high",
                &7.5_f64 as &dyn rusqlite::types::ToSql,
                &"CWE-787",
                &"main",
                &"evidence here",
                &0.80_f64 as &dyn rusqlite::types::ToSql,
                &"inv1",
            ],
        )
        .unwrap();

        let md = generate_markdown_for_investigation(&db, "inv1").unwrap();
        assert!(md.contains("Test"));
        assert!(md.contains("`/usr/bin/test`"));
        assert!(md.contains("Test vuln"));
    }

    #[test]
    fn test_markdown_includes_findings_table() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &"inv2",
                &"Quick Test",
                &"/usr/bin/quick",
                &"active",
                &"2026-03-10",
            ],
        )
        .unwrap();

        db.execute(
            "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                &"f1",
                &"Dangerous API - system",
                &"Call to system() with user input",
                &"quick-analyzer",
                &"2026-03-10T12:00:00Z",
                &"inv2",
            ],
        )
        .unwrap();

        let md = generate_markdown_for_investigation(&db, "inv2").unwrap();
        assert!(md.contains("Quick Analysis Findings"));
        assert!(md.contains("Dangerous API - system"));
        assert!(md.contains("quick-analyzer"));
        assert!(md.contains("Call to system() with user input"));
    }

    #[test]
    fn test_markdown_combines_vulns_and_findings() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &"inv3",
                &"Combined",
                &"/usr/bin/combo",
                &"active",
                &"2026-03-10",
            ],
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
                &"CWE-787",
                &"main",
                &"evidence",
                &0.80_f64 as &dyn rusqlite::types::ToSql,
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
                &"printf with user input",
                &"quick-analyzer",
                &"2026-03-10T12:00:00Z",
                &"inv3",
            ],
        )
        .unwrap();

        let md = generate_markdown_for_investigation(&db, "inv3").unwrap();
        // Should contain both vulnerability and finding
        assert!(md.contains("Buffer overflow"));
        assert!(md.contains("Format string bug"));
        assert!(md.contains("Quick Analysis Findings"));
    }
}
