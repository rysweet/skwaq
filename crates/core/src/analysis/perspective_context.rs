//! Context perspective: validates existing findings by checking reachability
//! and sanitization, acting as a "critic" that challenges false positives.

use crate::analysis::findings::{Finding, FindingLocation, FindingStatus, FindingUpdate};
use crate::analysis::perspective_pattern::dangerous_api_info;
use crate::graph::GraphDb;
use uuid::Uuid;

/// Third perspective: context validation (checks if findings are reachable/exploitable).
///
/// Acts as a "critic" that challenges existing findings by checking:
/// - Is the dangerous function actually called with external input?
/// - Is there input validation/sanitization between source and sink?
/// - Is the code path actually reachable from an entry point?
/// - Does the function have bounds checking the pattern detector missed?
pub fn context_perspective(
    db: &GraphDb,
    inv_id: &str,
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
    new_findings.extend(detect_indirect_dangerous_calls(
        db,
        inv_id,
        existing_findings,
        cycle,
    ));

    (updates, new_findings)
}

/// Check if a function name matches a sanitizer by exact or word-level comparison.
fn is_sanitizer_name(name: &str) -> bool {
    const SANITIZER_WORDS: &[&str] = &["validate", "sanitize", "check", "verify"];
    const SANITIZER_EXACT: &[&str] = &[
        "bounds_check",
        "strlcpy",
        "strlcat",
        "snprintf",
        "strncpy_s",
        "strcpy_s",
    ];
    if SANITIZER_EXACT.contains(&name) {
        return true;
    }
    let words: Vec<&str> = name.split('_').collect();
    SANITIZER_WORDS.iter().any(|s| words.contains(s))
}

/// Check if any sanitization function exists between a taint source and sink.
fn check_sanitization_exists(db: &GraphDb, finding: &Finding) -> bool {
    // Extract the path from evidence if available
    for ev in &finding.evidence {
        let path_str = ev
            .trim_start_matches("Taint path: ")
            .trim_start_matches("Call path: ");
        let hops: Vec<&str> = path_str.split(" -> ").map(|s| s.trim()).collect();

        // Check if any intermediate hop (not source, not sink) is a sanitizer
        if hops.len() > 2 {
            for hop in &hops[1..hops.len() - 1] {
                let base = hop.split('@').next().unwrap_or(hop);
                if is_sanitizer_name(base) {
                    return true;
                }
            }
        }
    }

    // Check if a sanitizer exists between source and sink in the call graph.
    // Build the path from evidence, then look for sanitizers along it.
    let func_name = &finding.location.function;
    let base = func_name.split('@').next().unwrap_or(func_name);

    // Look for intermediate functions between a caller and the sink
    // that have sanitizer-like names.
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT f.name FROM calls c \
         JOIN functions f ON c.caller_id = f.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name LIKE ?1",
    ) {
        if let Ok(rows) = stmt.query_map([format!("%{}%", base)], |row| row.get::<_, String>(0)) {
            for row in rows.flatten() {
                let caller_base = row.split('@').next().unwrap_or(&row);
                if is_sanitizer_name(caller_base) {
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
            if let Ok(count) = db
                .conn()
                .query_row(sql, [format!("%{}%", safe_fn)], |row| row.get::<_, i64>(0))
            {
                if count > 0 {
                    return true;
                }
            }
        }
    }

    false
}

/// Look for wrapper functions that call dangerous APIs indirectly.
fn detect_indirect_dangerous_calls(
    db: &GraphDb,
    inv_id: &str,
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
               JOIN functions f_callee ON c.callee_id = f_callee.id \
               WHERE f_caller.investigation_id = ?1";

    if let Ok(mut stmt) = db.conn().prepare(sql) {
        if let Ok(rows) = stmt.query_map([inv_id], |row| {
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

#[cfg(test)]
mod tests {
    use super::*;

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
            "INSERT INTO functions (id, name, investigation_id) VALUES ('f1', 'my_copy', 'inv1')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name, investigation_id) VALUES ('f2', 'strcpy', 'inv1')",
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

        let new = detect_indirect_dangerous_calls(&db, "inv1", &existing, 3);
        assert!(!new.is_empty());
        assert!(new[0].title.contains("my_copy"));
        assert_eq!(new[0].category, "indirect");
    }
}
