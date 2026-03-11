//! Dataflow perspective: traces actual data flow paths from sources to sinks.

use crate::analysis::findings::{Finding, FindingLocation, FindingStatus};
use crate::graph::GraphDb;
use uuid::Uuid;

/// Second perspective: data flow analysis (traces actual paths).
///
/// Finds unsanitized data flow paths from sources to sinks, both from
/// pre-computed taint flows and on-the-fly call graph traversal.
pub fn dataflow_perspective(db: &GraphDb, inv_id: &str, cycle: u32) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check pre-computed taint flows
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0 AND s.investigation_id = ?1",
    ) {
        if let Ok(rows) = stmt.query_map([inv_id], |row| {
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
        .prepare("SELECT DISTINCT name FROM data_sources WHERE investigation_id = ?1")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([inv_id], |row| row.get::<_, String>(0))
                .ok()
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();

    let sinks: Vec<String> = db
        .conn()
        .prepare("SELECT DISTINCT name FROM data_sinks WHERE investigation_id = ?1")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([inv_id], |row| row.get::<_, String>(0))
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
            .prepare("SELECT id FROM functions WHERE name = ?1 AND investigation_id = ?2")
        {
            let source_ids: Vec<String> = id_stmt
                .query_map(rusqlite::params![source.as_str(), inv_id], |row| {
                    row.get::<_, String>(0)
                })
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
                                && !existing_pairs.contains(&(source.clone(), func_name.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataflow_perspective_finds_taint_paths() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO data_sources (id, name, source_type, investigation_id) VALUES ('src1', 'recv', 'network', 'inv1')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type, danger_level, investigation_id) VALUES ('sink1', 'strcpy', 'memory', 'critical', 'inv1')",
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
}
