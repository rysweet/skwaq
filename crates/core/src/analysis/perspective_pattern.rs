//! Pattern perspective: fast, broad pattern matching for dangerous APIs.

use crate::analysis::findings::{Finding, FindingLocation, FindingStatus};
use crate::graph::GraphDb;
use uuid::Uuid;

/// First perspective: pattern matching (fast, broad).
///
/// Scans the graph for dangerous API usage by checking function names,
/// imports, and data sinks against a known-dangerous list.
pub fn pattern_perspective(db: &GraphDb, inv_id: &str, cycle: u32) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Check functions for dangerous API names
    if let Ok(mut stmt) = db
        .conn()
        .prepare("SELECT f.name, f.address FROM functions f WHERE f.investigation_id = ?1")
    {
        if let Ok(rows) = stmt.query_map([inv_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
            ))
        }) {
            for row in rows.flatten() {
                let (name, address) = row;
                let base = name.split('@').next().unwrap_or(&name);
                if let Some((cat, sev, reason)) = dangerous_api_info(base) {
                    if seen.insert(base.to_string()) {
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            title: format!("Dangerous API: {}", base),
                            description: reason.to_string(),
                            severity: sev.to_string(),
                            category: cat.to_string(),
                            location: FindingLocation {
                                file: String::new(),
                                function: name.clone(),
                                line: None,
                                address: if address.is_empty() {
                                    None
                                } else {
                                    Some(address)
                                },
                            },
                            evidence: vec![format!(
                                "Function '{}' is a known dangerous API: {}",
                                base, reason
                            )],
                            status: FindingStatus::New,
                            cycle_discovered: cycle,
                            cycle_last_updated: cycle,
                        });
                    }
                }
            }
        }
    }

    // Check imports in symbols table
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT s.name FROM symbols s WHERE s.symbol_type = 'import' AND s.investigation_id = ?1",
    ) {
        if let Ok(rows) = stmt.query_map([inv_id], |row| row.get::<_, String>(0)) {
            for row in rows.flatten() {
                let base = row.split('@').next().unwrap_or(&row);
                if let Some((cat, sev, reason)) = dangerous_api_info(base) {
                    if seen.insert(base.to_string()) {
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            title: format!("Dangerous API: {}", base),
                            description: reason.to_string(),
                            severity: sev.to_string(),
                            category: cat.to_string(),
                            location: FindingLocation {
                                file: String::new(),
                                function: row.clone(),
                                line: None,
                                address: None,
                            },
                            evidence: vec![format!(
                                "Import '{}' is a known dangerous API: {}",
                                base, reason
                            )],
                            status: FindingStatus::New,
                            cycle_discovered: cycle,
                            cycle_last_updated: cycle,
                        });
                    }
                }
            }
        }
    }

    // Check data sinks
    if let Ok(mut stmt) = db
        .conn()
        .prepare("SELECT s.name, s.danger_level FROM data_sinks s WHERE s.investigation_id = ?1")
    {
        if let Ok(rows) = stmt.query_map([inv_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                let (name, danger) = row;
                let base = name.split('@').next().unwrap_or(&name);
                if let Some((cat, _sev, reason)) = dangerous_api_info(base) {
                    if seen.insert(format!("sink:{}", base)) {
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            title: format!("Dangerous sink: {}", base),
                            description: reason.to_string(),
                            severity: danger.clone(),
                            category: cat.to_string(),
                            location: FindingLocation {
                                file: String::new(),
                                function: name.clone(),
                                line: None,
                                address: None,
                            },
                            evidence: vec![format!(
                                "Data sink '{}' (danger_level={}): {}",
                                base, danger, reason
                            )],
                            status: FindingStatus::New,
                            cycle_discovered: cycle,
                            cycle_last_updated: cycle,
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Look up danger info for a function name. Returns (category, severity, reason).
pub(crate) fn dangerous_api_info(name: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match name {
        "strcpy" => Some((
            "memory",
            "critical",
            "unbounded copy; use strncpy or strlcpy",
        )),
        "strcat" => Some((
            "memory",
            "critical",
            "unbounded concatenation; use strncat or strlcat",
        )),
        "gets" => Some(("memory", "critical", "no bounds checking; use fgets")),
        "memcpy" => Some((
            "memory",
            "medium",
            "no bounds checking; verify size parameter",
        )),
        "memmove" => Some((
            "memory",
            "medium",
            "no bounds checking; verify size parameter",
        )),
        "strncpy" => Some(("memory", "low", "may not null-terminate; prefer strlcpy")),
        "strncat" => Some((
            "memory",
            "low",
            "size semantics are error-prone; prefer strlcat",
        )),
        "sprintf" => Some((
            "format_string",
            "high",
            "unbounded format output; use snprintf",
        )),
        "vsprintf" => Some((
            "format_string",
            "high",
            "unbounded format output; use vsnprintf",
        )),
        "scanf" => Some((
            "format_string",
            "high",
            "unbounded input; use width specifiers or fgets",
        )),
        "fscanf" => Some((
            "format_string",
            "high",
            "unbounded input; use width specifiers",
        )),
        "sscanf" => Some((
            "format_string",
            "medium",
            "potential buffer overflow with %s",
        )),
        "printf" | "fprintf" | "vprintf" | "vfprintf" => Some((
            "format_string",
            "high",
            "format string vulnerability if format is user-controlled",
        )),
        "snprintf" | "vsnprintf" => Some((
            "format_string",
            "medium",
            "format string vulnerability if format is user-controlled",
        )),
        "system" => Some((
            "injection",
            "critical",
            "shell injection risk; use exec* family directly",
        )),
        "popen" => Some((
            "injection",
            "critical",
            "shell injection risk; use pipe+fork+exec",
        )),
        "exec" | "execl" | "execle" | "execlp" | "execv" | "execvp" | "execvpe" => Some((
            "injection",
            "high",
            "command execution; validate all arguments",
        )),
        "mktemp" => Some(("race", "medium", "TOCTOU race; use mkstemp")),
        "tmpnam" => Some(("temp_file", "medium", "TOCTOU race; use tmpfile or mkstemp")),
        "realpath" => Some((
            "path_traversal",
            "low",
            "buffer overflow in some implementations; check buffer size",
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_perspective_finds_dangerous_functions() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO functions (id, name, investigation_id) VALUES ('f1', 'strcpy', 'inv1')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name, investigation_id) VALUES ('f2', 'main', 'inv1')",
            &[],
        )
        .unwrap();

        let findings = pattern_perspective(&db, "inv1", 1);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("strcpy")));
        assert_eq!(findings[0].cycle_discovered, 1);
    }

    #[test]
    fn test_pattern_perspective_handles_versioned_names() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO functions (id, name, investigation_id) VALUES ('f1', 'system@GLIBC_2.2.5', 'inv1')",
            &[],
        )
        .unwrap();

        let findings = pattern_perspective(&db, "inv1", 1);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("system")));
    }

    #[test]
    fn test_dangerous_api_info() {
        assert!(dangerous_api_info("strcpy").is_some());
        assert!(dangerous_api_info("system").is_some());
        assert!(dangerous_api_info("printf").is_some());
        assert!(dangerous_api_info("malloc").is_none());
    }
}
