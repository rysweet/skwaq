//! Multi-perspective analysis functions.
//!
//! Each perspective examines the binary from a different angle:
//! - **Pattern perspective**: Fast, broad pattern matching for dangerous APIs.
//! - **Dataflow perspective**: Traces actual data flow paths from sources to sinks.
//! - **Context perspective**: Validates existing findings by checking reachability
//!   and sanitization, acting as a "critic" that challenges false positives.

use crate::analysis::findings::{Finding, FindingLocation, FindingStatus, FindingUpdate};
use crate::graph::GraphDb;
use uuid::Uuid;

/// First perspective: pattern matching (fast, broad).
///
/// Scans the graph for dangerous API usage by checking function names,
/// imports, and data sinks against a known-dangerous list.
pub fn pattern_perspective(db: &GraphDb, _inv_id: &str, cycle: u32) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Check functions for dangerous API names
    if let Ok(mut stmt) = db.conn().prepare("SELECT f.name, f.address FROM functions f") {
        if let Ok(rows) = stmt.query_map([], |row| {
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
    if let Ok(mut stmt) = db
        .conn()
        .prepare("SELECT s.name FROM symbols s WHERE s.symbol_type = 'import'")
    {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
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
        .prepare("SELECT s.name, s.danger_level FROM data_sinks s")
    {
        if let Ok(rows) = stmt.query_map([], |row| {
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

/// Second perspective: data flow analysis (traces actual paths).
///
/// Finds unsanitized data flow paths from sources to sinks, both from
/// pre-computed taint flows and on-the-fly call graph traversal.
pub fn dataflow_perspective(db: &GraphDb, _inv_id: &str, cycle: u32) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check pre-computed taint flows
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            for row in rows.flatten() {
                let (source, sink, path) = row;
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: format!("Unsanitized flow: {} -> {}", source, sink),
                    description: format!(
                        "Data flows from source '{}' to dangerous sink '{}' without sanitization",
                        source, sink
                    ),
                    severity: "high".to_string(),
                    category: "taint".to_string(),
                    location: FindingLocation {
                        file: String::new(),
                        function: sink.clone(),
                        line: None,
                        address: None,
                    },
                    evidence: vec![format!("Taint path: {}", path)],
                    status: FindingStatus::New,
                    cycle_discovered: cycle,
                    cycle_last_updated: cycle,
                });
            }
        }
    }

    // Discover paths via call graph (recursive CTE)
    let max_depth: u32 = 10;

    let sources: Vec<String> = db
        .conn()
        .prepare("SELECT DISTINCT name FROM data_sources")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(0))
                .ok()
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();

    let sinks: Vec<String> = db
        .conn()
        .prepare("SELECT DISTINCT name FROM data_sinks")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(0))
                .ok()
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();

    if sources.is_empty() || sinks.is_empty() {
        return findings;
    }

    // Deduplicate against pre-computed flows
    let existing_pairs: std::collections::HashSet<(String, String)> = findings
        .iter()
        .map(|f| {
            let parts: Vec<&str> = f.title.splitn(2, " -> ").collect();
            let src = parts
                .first()
                .unwrap_or(&"")
                .trim_start_matches("Unsanitized flow: ")
                .to_string();
            let snk = parts.get(1).unwrap_or(&"").to_string();
            (src, snk)
        })
        .collect();

    for source in &sources {
        if let Ok(mut id_stmt) = db
            .conn()
            .prepare("SELECT id FROM functions WHERE name = ?1")
        {
            let source_ids: Vec<String> = id_stmt
                .query_map([source.as_str()], |row| row.get::<_, String>(0))
                .ok()
                .map(|rows| rows.flatten().collect())
                .unwrap_or_default();

            for source_id in &source_ids {
                let sql = "WITH RECURSIVE call_chain(func_id, func_name, path, depth) AS ( \
                             SELECT f.id, f.name, f.name, 0 \
                             FROM functions f WHERE f.id = ?1 \
                             UNION ALL \
                             SELECT f2.id, f2.name, cc.path || ' -> ' || f2.name, cc.depth + 1 \
                             FROM calls c \
                             JOIN call_chain cc ON c.caller_id = cc.func_id \
                             JOIN functions f2 ON c.callee_id = f2.id \
                             WHERE cc.depth < ?2 \
                         ) \
                         SELECT func_name, path FROM call_chain WHERE depth > 0";

                if let Ok(mut cte_stmt) = db.conn().prepare(sql) {
                    if let Ok(rows) = cte_stmt
                        .query_map(rusqlite::params![source_id.as_str(), max_depth], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                        })
                    {
                        for row in rows.flatten() {
                            let (func_name, path) = row;
                            if sinks.contains(&func_name)
                                && !existing_pairs
                                    .contains(&(source.clone(), func_name.clone()))
                            {
                                findings.push(Finding {
                                    id: Uuid::new_v4().to_string(),
                                    title: format!(
                                        "Unsanitized flow: {} -> {}",
                                        source, func_name
                                    ),
                                    description: format!(
                                        "Call graph path from source '{}' reaches dangerous sink '{}'",
                                        source, func_name
                                    ),
                                    severity: "high".to_string(),
                                    category: "taint".to_string(),
                                    location: FindingLocation {
                                        file: String::new(),
                                        function: func_name,
                                        line: None,
                                        address: None,
                                    },
                                    evidence: vec![format!("Call path: {}", path)],
                                    status: FindingStatus::New,
                                    cycle_discovered: cycle,
                                    cycle_last_updated: cycle,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Third perspective: context validation (checks if findings are reachable/exploitable).
///
/// Acts as a "critic" that challenges existing findings by checking:
/// - Is the dangerous function actually called with external input?
/// - Is there input validation/sanitization between source and sink?
/// - Is the code path actually reachable from an entry point?
/// - Does the function have bounds checking the pattern detector missed?
pub fn context_perspective(
    db: &GraphDb,
    _inv_id: &str,
    existing_findings: &[Finding],
    cycle: u32,
) -> (Vec<FindingUpdate>, Vec<Finding>) {
    let mut updates = Vec::new();
    let mut new_findings = Vec::new();

    for finding in existing_findings {
        if finding.status == FindingStatus::Invalidated {
            continue;
        }

        let func_name = &finding.location.function;
        let base = func_name.split('@').next().unwrap_or(func_name);

        if finding.category == "taint" {
            // For taint findings: check if sanitization exists
            if check_sanitization_exists(db, finding) {
                updates.push(FindingUpdate {
                    finding_id: finding.id.clone(),
                    new_status: FindingStatus::Invalidated,
                    reason: format!(
                        "Sanitization detected between source and sink in flow: {}",
                        finding.title
                    ),
                });
            } else {
                updates.push(FindingUpdate {
                    finding_id: finding.id.clone(),
                    new_status: FindingStatus::Confirmed,
                    reason: "No sanitization found; taint path is exploitable".to_string(),
                });
            }
        } else {
            // For pattern findings: check if the dangerous API is actually
            // called with external (tainted) input
            if check_called_with_external_input(db, base) {
                updates.push(FindingUpdate {
                    finding_id: finding.id.clone(),
                    new_status: FindingStatus::Confirmed,
                    reason: format!(
                        "Function '{}' is called with data derived from external input",
                        base
                    ),
                });
            } else if check_has_bounds_checking(db, base) {
                updates.push(FindingUpdate {
                    finding_id: finding.id.clone(),
                    new_status: FindingStatus::Invalidated,
                    reason: format!(
                        "Function '{}' appears to have bounds checking or is not reached by external input",
                        base
                    ),
                });
            } else {
                // Can't confirm or deny -- challenge it
                updates.push(FindingUpdate {
                    finding_id: finding.id.clone(),
                    new_status: FindingStatus::Challenged,
                    reason: format!(
                        "Unable to confirm external input reaches '{}'; needs manual review",
                        base
                    ),
                });
            }
        }
    }

    // Deeper analysis: look for wrapper functions that hide dangerous operations
    new_findings.extend(detect_indirect_dangerous_calls(db, existing_findings, cycle));

    (updates, new_findings)
}

/// Check if any sanitization function exists between a taint source and sink.
fn check_sanitization_exists(db: &GraphDb, finding: &Finding) -> bool {
    // Known sanitization functions
    const SANITIZERS: &[&str] = &[
        "validate",
        "sanitize",
        "check",
        "verify",
        "bounds_check",
        "strlcpy",
        "strlcat",
        "snprintf",
        "strncpy_s",
        "strcpy_s",
    ];

    // Extract the path from evidence if available
    for ev in &finding.evidence {
        let path_str = ev
            .trim_start_matches("Taint path: ")
            .trim_start_matches("Call path: ");
        let hops: Vec<&str> = path_str.split(" -> ").map(|s| s.trim()).collect();

        // Check if any intermediate hop is a sanitizer
        // Skip first (source) and last (sink)
        if hops.len() > 2 {
            for hop in &hops[1..hops.len() - 1] {
                let base = hop.split('@').next().unwrap_or(hop);
                if SANITIZERS.iter().any(|s| base.contains(s)) {
                    return true;
                }
            }
        }
    }

    // Also check if a sanitizer is between source and sink in the call graph
    let func_name = &finding.location.function;
    let base = func_name.split('@').next().unwrap_or(func_name);

    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT f.name FROM calls c \
         JOIN functions f ON c.caller_id = f.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name LIKE ?1",
    ) {
        if let Ok(rows) = stmt.query_map([format!("%{}%", base)], |row| row.get::<_, String>(0)) {
            for row in rows.flatten() {
                let caller_base = row.split('@').next().unwrap_or(&row);
                if SANITIZERS.iter().any(|s| caller_base.contains(s)) {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if a dangerous function is called with data from an external source.
fn check_called_with_external_input(db: &GraphDb, func_name: &str) -> bool {
    // Check if any data source reaches this function through the call graph
    let sql = "SELECT count(*) FROM data_sources ds \
               JOIN functions f_src ON f_src.name = ds.name \
               JOIN calls c ON c.caller_id = f_src.id \
               JOIN functions f_dst ON c.callee_id = f_dst.id \
               WHERE f_dst.name LIKE ?1";

    if let Ok(count) = db
        .conn()
        .query_row(sql, [format!("%{}%", func_name)], |row| {
            row.get::<_, i64>(0)
        })
    {
        if count > 0 {
            return true;
        }
    }

    // Check indirect paths (2 hops)
    let sql2 = "SELECT count(*) FROM data_sources ds \
                JOIN functions f_src ON f_src.name = ds.name \
                JOIN calls c1 ON c1.caller_id = f_src.id \
                JOIN calls c2 ON c2.caller_id = c1.callee_id \
                JOIN functions f_dst ON c2.callee_id = f_dst.id \
                WHERE f_dst.name LIKE ?1";

    if let Ok(count) = db
        .conn()
        .query_row(sql2, [format!("%{}%", func_name)], |row| {
            row.get::<_, i64>(0)
        })
    {
        if count > 0 {
            return true;
        }
    }

    false
}

/// Check if a function has associated bounds checking (e.g., safe variants).
fn check_has_bounds_checking(db: &GraphDb, func_name: &str) -> bool {
    // Safe replacement functions suggest bounds checking is in place
    let safe_variants: std::collections::HashMap<&str, &[&str]> = [
        ("strcpy", &["strlcpy", "strncpy", "strcpy_s"] as &[&str]),
        ("strcat", &["strlcat", "strncat", "strcat_s"]),
        ("sprintf", &["snprintf", "sprintf_s"]),
        ("gets", &["fgets", "gets_s"]),
        ("scanf", &["scanf_s"]),
    ]
    .into_iter()
    .collect();

    if let Some(safe_list) = safe_variants.get(func_name) {
        // If the binary also imports a safe variant, the dangerous usage
        // might be mitigated
        for safe_fn in *safe_list {
            let sql = "SELECT count(*) FROM functions WHERE name LIKE ?1";
            if let Ok(count) = db.conn().query_row(sql, [format!("%{}%", safe_fn)], |row| {
                row.get::<_, i64>(0)
            }) {
                if count > 0 {
                    return true;
                }
            }
        }
    }

    false
}

/// Look for wrapper functions that call dangerous APIs indirectly.
/// These are functions that are not themselves dangerous but delegate
/// to dangerous functions, potentially hiding the risk.
fn detect_indirect_dangerous_calls(
    db: &GraphDb,
    existing_findings: &[Finding],
    cycle: u32,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let existing_funcs: std::collections::HashSet<String> = existing_findings
        .iter()
        .map(|f| {
            f.location
                .function
                .split('@')
                .next()
                .unwrap_or(&f.location.function)
                .to_string()
        })
        .collect();

    // Find functions that call dangerous functions but aren't themselves flagged
    let sql = "SELECT DISTINCT f_caller.name, f_callee.name \
               FROM calls c \
               JOIN functions f_caller ON c.caller_id = f_caller.id \
               JOIN functions f_callee ON c.callee_id = f_callee.id";

    if let Ok(mut stmt) = db.conn().prepare(sql) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                let (caller, callee) = row;
                let callee_base = callee.split('@').next().unwrap_or(&callee);
                let caller_base = caller.split('@').next().unwrap_or(&caller);

                // If callee is dangerous and caller is not already flagged
                if dangerous_api_info(callee_base).is_some()
                    && !existing_funcs.contains(caller_base)
                    && dangerous_api_info(caller_base).is_none()
                {
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        title: format!("Wrapper for dangerous API: {}", caller_base),
                        description: format!(
                            "Function '{}' wraps dangerous function '{}' — callers may not realize the risk",
                            caller_base, callee_base
                        ),
                        severity: "medium".to_string(),
                        category: "indirect".to_string(),
                        location: FindingLocation {
                            file: String::new(),
                            function: caller.clone(),
                            line: None,
                            address: None,
                        },
                        evidence: vec![format!("{} -> {}", caller_base, callee_base)],
                        status: FindingStatus::New,
                        cycle_discovered: cycle,
                        cycle_last_updated: cycle,
                    });
                }
            }
        }
    }

    findings
}

/// Look up danger info for a function name. Returns (category, severity, reason).
fn dangerous_api_info(name: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match name {
        "strcpy" => Some(("memory", "critical", "unbounded copy; use strncpy or strlcpy")),
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
        "strncpy" => Some((
            "memory",
            "low",
            "may not null-terminate; prefer strlcpy",
        )),
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
            "INSERT INTO functions (id, name) VALUES ('f1', 'strcpy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'main')",
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
            "INSERT INTO functions (id, name) VALUES ('f1', 'system@GLIBC_2.2.5')",
            &[],
        )
        .unwrap();

        let findings = pattern_perspective(&db, "inv1", 1);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("system")));
    }

    #[test]
    fn test_dataflow_perspective_finds_taint_paths() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type, danger_level) VALUES ('sink1', 'strcpy', 'memory', 'critical')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv -> process -> strcpy', 0)",
            &[],
        )
        .unwrap();

        let findings = dataflow_perspective(&db, "inv1", 2);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.title.contains("recv") && f.title.contains("strcpy")));
    }

    #[test]
    fn test_context_perspective_invalidates_sanitized() {
        let db = GraphDb::in_memory().unwrap();

        let finding = Finding {
            id: "f1".to_string(),
            title: "Unsanitized flow: recv -> strcpy".to_string(),
            description: String::new(),
            severity: "high".to_string(),
            category: "taint".to_string(),
            location: FindingLocation {
                file: String::new(),
                function: "strcpy".to_string(),
                line: None,
                address: None,
            },
            evidence: vec!["Taint path: recv -> validate_input -> strcpy".to_string()],
            status: FindingStatus::New,
            cycle_discovered: 1,
            cycle_last_updated: 1,
        };

        let (updates, _new) = context_perspective(&db, "inv1", &[finding], 3);
        // Should detect "validate" in the path and invalidate
        assert!(!updates.is_empty());
        assert_eq!(updates[0].new_status, FindingStatus::Invalidated);
    }

    #[test]
    fn test_context_perspective_confirms_no_sanitizer() {
        let db = GraphDb::in_memory().unwrap();

        let finding = Finding {
            id: "f1".to_string(),
            title: "Unsanitized flow: recv -> strcpy".to_string(),
            description: String::new(),
            severity: "high".to_string(),
            category: "taint".to_string(),
            location: FindingLocation {
                file: String::new(),
                function: "strcpy".to_string(),
                line: None,
                address: None,
            },
            evidence: vec!["Taint path: recv -> process -> strcpy".to_string()],
            status: FindingStatus::New,
            cycle_discovered: 1,
            cycle_last_updated: 1,
        };

        let (updates, _new) = context_perspective(&db, "inv1", &[finding], 3);
        assert!(!updates.is_empty());
        assert_eq!(updates[0].new_status, FindingStatus::Confirmed);
    }

    #[test]
    fn test_detect_indirect_dangerous_calls() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'my_copy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'strcpy')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f1', 'f2')",
            &[],
        )
        .unwrap();

        let existing = vec![Finding {
            id: "e1".to_string(),
            title: "Dangerous API: strcpy".to_string(),
            description: String::new(),
            severity: "critical".to_string(),
            category: "memory".to_string(),
            location: FindingLocation {
                file: String::new(),
                function: "strcpy".to_string(),
                line: None,
                address: None,
            },
            evidence: vec![],
            status: FindingStatus::New,
            cycle_discovered: 1,
            cycle_last_updated: 1,
        }];

        let new = detect_indirect_dangerous_calls(&db, &existing, 3);
        assert!(!new.is_empty());
        assert!(new[0].title.contains("my_copy"));
        assert_eq!(new[0].category, "indirect");
    }

    #[test]
    fn test_dangerous_api_info() {
        assert!(dangerous_api_info("strcpy").is_some());
        assert!(dangerous_api_info("system").is_some());
        assert!(dangerous_api_info("printf").is_none());
        assert!(dangerous_api_info("malloc").is_none());
    }
}
