//! Cypher-to-SQL translation and read-only query execution.

use crate::graph::GraphDb;

/// Translate common Cypher-like query patterns to parameterized SQL.
///
/// Returns `(sql, params)` where params contains the investigation_id
/// for the `?1` placeholder. Only predefined patterns are supported;
/// arbitrary SQL (including raw SELECT from the LLM) is rejected.
pub fn translate_to_sql(query: &str, investigation_id: &str) -> Result<(String, Vec<String>), String> {
    let q = query.trim();
    let upper = q.to_uppercase();

    if upper.contains("FUNCTION") && upper.contains("RETURN") {
        return Ok((
            "SELECT name, address, decompiled FROM functions WHERE investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    if upper.contains("CALL") {
        return Ok((
            "SELECT f1.name as caller, f2.name as callee FROM calls c \
             JOIN functions f1 ON c.caller_id = f1.id \
             JOIN functions f2 ON c.callee_id = f2.id \
             WHERE f1.investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    if upper.contains("TAINT") || upper.contains("FLOW") {
        return Ok((
            "SELECT s.name, k.name, tf.path, tf.sanitized FROM taint_flows tf \
             JOIN data_sources s ON tf.source_id = s.id \
             JOIN data_sinks k ON tf.sink_id = k.id \
             WHERE s.investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    let q_preview: String = q.chars().take(80).collect();
    Err(format!(
        "Unsupported query pattern. Use Cypher-like queries with FUNCTION/RETURN, CALL, or TAINT/FLOW keywords. Got: {}",
        q_preview
    ))
}

/// Execute a read-only parameterized SQL query and return results as a Vec of JSON objects.
pub fn execute_read_query(
    db: &GraphDb,
    sql: &str,
    params: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let stmt = db.conn().prepare(sql)?;
    if !stmt.readonly() {
        return Ok(vec![serde_json::json!({"error": "Only read-only queries are allowed. Write operations are not permitted."})]);
    }
    let mut stmt = stmt;
    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();

    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        let mut obj = serde_json::Map::new();
        for (i, col_name) in column_names.iter().enumerate() {
            let val: rusqlite::Result<String> = row.get(i);
            match val {
                Ok(s) => {
                    obj.insert(col_name.clone(), serde_json::Value::String(s));
                }
                Err(_) => {
                    let fval: rusqlite::Result<f64> = row.get(i);
                    match fval {
                        Ok(f) => {
                            obj.insert(col_name.clone(), serde_json::json!(f));
                        }
                        Err(_) => {
                            let ival: rusqlite::Result<i64> = row.get(i);
                            match ival {
                                Ok(n) => {
                                    obj.insert(col_name.clone(), serde_json::json!(n));
                                }
                                Err(_) => {
                                    obj.insert(col_name.clone(), serde_json::Value::Null);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(serde_json::Value::Object(obj))
    })?;

    let results: Vec<serde_json::Value> = rows
        .filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("Error reading query result row: {e}");
                None
            }
        })
        .collect();
    Ok(results)
}

/// Create a finding in the database.
pub(super) fn execute_create_finding(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled");
    let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");
    let description = args.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
    let cwe_id = args.get("cwe_id").and_then(|v| v.as_str()).unwrap_or("");

    let finding_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    tracing::info!("Tool create_finding: {title} [{severity}]");

    let evidence = serde_json::json!({
        "description": description, "function": function, "cwe_id": cwe_id,
    });

    db.execute(
        "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id, \
         status, severity, category) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        &[
            &finding_id as &dyn rusqlite::types::ToSql, &title,
            &evidence.to_string(), &"vuln_hunter", &timestamp,
            &investigation_id, &"new", &severity, &cwe_id,
        ],
    )?;

    Ok(serde_json::json!({
        "status": "ok", "finding_id": finding_id,
        "title": title, "severity": severity,
        "investigation_id": investigation_id
    }))
}

/// Search for functions with similar names or patterns.
pub(super) fn execute_search_similar(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let code = args.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let code_preview: String = code.chars().take(40).collect();
    tracing::info!("Tool search_similar: {code_preview}...");

    let search_pattern = format!("%{}%", code.replace('%', ""));
    let mut stmt = db.conn().prepare(
        "SELECT name, address, decompiled FROM functions \
         WHERE investigation_id = ?1 AND (decompiled LIKE ?2 OR name LIKE ?2) LIMIT ?3",
    )?;

    let rows = stmt.query_map(
        rusqlite::params![investigation_id, search_pattern, limit as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
    )?;

    let results: Vec<serde_json::Value> = rows
        .filter_map(|r| r.ok())
        .map(|(name, addr, decompiled)| {
            let preview_raw = if decompiled.chars().count() > 200 {
                format!("{}...", decompiled.chars().take(200).collect::<String>())
            } else {
                decompiled
            };
            serde_json::json!({
                "name": name, "address": addr,
                "preview": format!("<code_data>\n{}\n</code_data>", preview_raw)
            })
        })
        .collect();

    Ok(serde_json::json!({"status": "ok", "results": results, "count": results.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readonly_enforcement_in_execute_read_query() {
        let db = GraphDb::in_memory().unwrap();

        // Directly test execute_read_query with a write statement
        let result = execute_read_query(&db, "INSERT INTO functions (id, name) VALUES ('evil', 'injected')", &[]).unwrap();

        // Should return an error entry instead of executing
        assert_eq!(result.len(), 1);
        assert!(
            result[0].get("error").is_some(),
            "Write query should be rejected by readonly check"
        );

        // Verify nothing was inserted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM functions WHERE name = 'injected'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_translate_to_sql_blocks_unrecognised_patterns() {
        // INSERT should be rejected
        let result = translate_to_sql("INSERT INTO functions VALUES ('x', 'y')", "inv1");
        assert!(result.is_err());

        // UPDATE should be rejected
        let result = translate_to_sql("UPDATE functions SET name = 'hacked'", "inv1");
        assert!(result.is_err());

        // Raw SELECT should also be rejected (no pass-through)
        let result = translate_to_sql("SELECT * FROM functions", "inv1");
        assert!(result.is_err());

        // Recognised Cypher-like patterns should work and use parameterized queries
        let result = translate_to_sql("MATCH (f:Function) RETURN f", "inv1");
        assert!(result.is_ok());
        let (sql, params) = result.unwrap();
        assert!(sql.contains("?1"));
        assert_eq!(params, vec!["inv1"]);

        let result = translate_to_sql("MATCH (c:Call) RETURN c", "inv1");
        assert!(result.is_ok());
        let (sql, params) = result.unwrap();
        assert!(sql.contains("?1"));
        assert_eq!(params, vec!["inv1"]);
    }
}
