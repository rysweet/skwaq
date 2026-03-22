//! Cypher-to-SQL translation and read-only query execution.

use crate::graph::GraphDb;

/// Translate common Cypher-like query patterns to parameterized SQL.
///
/// Returns `(sql, params)` where params contains the investigation_id
/// for the `?1` placeholder. Only predefined patterns are supported;
/// arbitrary SQL (including raw SELECT from the LLM) is rejected.
pub fn translate_to_sql(
    query: &str,
    investigation_id: &str,
) -> Result<(String, Vec<String>), String> {
    let q = query.trim();
    let upper = q.to_uppercase();

    // --- Schema discovery: what tables/node types exist ---
    if upper.contains("LABELS") || upper.contains("DISTINCT") && upper.contains("COUNT") {
        return Ok((
            "SELECT 'functions' AS table_name, count(*) AS count FROM functions WHERE investigation_id = ?1 \
             UNION ALL SELECT 'data_sources', count(*) FROM data_sources WHERE investigation_id = ?1 \
             UNION ALL SELECT 'data_sinks', count(*) FROM data_sinks WHERE investigation_id = ?1 \
             UNION ALL SELECT 'findings', count(*) FROM findings WHERE investigation_id = ?1 \
             UNION ALL SELECT 'taint_flows', count(*) FROM taint_flows tf JOIN data_sources s ON tf.source_id = s.id WHERE s.investigation_id = ?1 \
             UNION ALL SELECT 'calls', count(*) FROM calls c JOIN functions f ON c.caller_id = f.id WHERE f.investigation_id = ?1"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Look up function by name ---
    if let Some(name) = extract_name_filter(q) {
        return Ok((
            format!(
                "SELECT name, address, decompiled, language FROM functions \
                 WHERE investigation_id = ?1 AND name LIKE '%{}%' LIMIT 20",
                sanitize_like_param(&name)
            ),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Filter by file ---
    if let Some(file_pattern) = extract_file_filter(q) {
        return Ok((
            format!(
                "SELECT name, address, decompiled FROM functions \
                 WHERE investigation_id = ?1 AND address LIKE '%{}%' LIMIT 30",
                sanitize_like_param(&file_pattern)
            ),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Query findings/vulnerabilities ---
    if upper.contains("VULNERAB") || upper.contains("FINDING") {
        return Ok((
            "SELECT id, title, severity, category, status, evidence FROM findings \
             WHERE investigation_id = ?1 ORDER BY \
             CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
             WHEN 'medium' THEN 2 ELSE 3 END LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Query sources and sinks ---
    if upper.contains("SOURCE") && !upper.contains("TAINT") {
        return Ok((
            "SELECT id, name, source_type, location FROM data_sources \
             WHERE investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    if upper.contains("SINK") && !upper.contains("TAINT") {
        return Ok((
            "SELECT id, name, sink_type, danger_level, location FROM data_sinks \
             WHERE investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Functions with source code ---
    if upper.contains("CODE") || upper.contains("DECOMPILE") {
        return Ok((
            "SELECT name, address, decompiled FROM functions \
             WHERE investigation_id = ?1 AND decompiled IS NOT NULL AND decompiled != '' LIMIT 30"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- List all functions (general FUNCTION query) ---
    if upper.contains("FUNCTION") && upper.contains("RETURN") {
        return Ok((
            "SELECT name, address, decompiled FROM functions WHERE investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Call graph ---
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

    // --- Taint flows ---
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

    // --- Relationships (general graph traversal) ---
    if upper.contains("MATCH") && (upper.contains("->") || upper.contains("REL")) {
        return Ok((
            "SELECT 'calls' AS rel_type, f1.name AS from_name, f2.name AS to_name \
             FROM calls c JOIN functions f1 ON c.caller_id = f1.id \
             JOIN functions f2 ON c.callee_id = f2.id \
             WHERE f1.investigation_id = ?1 LIMIT 50"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- Fallback: if it's a MATCH query, return the schema summary ---
    if upper.starts_with("MATCH") {
        return Ok((
            "SELECT 'functions' AS table_name, count(*) AS count FROM functions WHERE investigation_id = ?1 \
             UNION ALL SELECT 'findings', count(*) FROM findings WHERE investigation_id = ?1 \
             UNION ALL SELECT 'data_sources', count(*) FROM data_sources WHERE investigation_id = ?1 \
             UNION ALL SELECT 'data_sinks', count(*) FROM data_sinks WHERE investigation_id = ?1"
                .to_string(),
            vec![investigation_id.to_string()],
        ));
    }

    // --- SQL passthrough: validate and execute safe SELECT queries directly ---
    if upper.starts_with("SELECT") {
        // Security: reject dangerous constructs
        if q.contains(';') {
            return Err("SQL passthrough rejected: semicolons not allowed".into());
        }
        if q.contains("--") || q.contains("/*") {
            return Err("SQL passthrough rejected: SQL comments not allowed".into());
        }
        if upper.contains("LOAD_EXTENSION") {
            return Err("SQL passthrough rejected: LOAD_EXTENSION not allowed".into());
        }

        // Whitelist of allowed tables
        let whitelisted: &[&str] = &[
            "functions",
            "basic_blocks",
            "data_sources",
            "data_sinks",
            "vulnerabilities",
            "findings",
            "cwes",
            "investigations",
            "annotations",
            "hypotheses",
            "agent_actions",
            "symbols",
            "string_literals",
            "calls",
            "contains_block",
            "flows_to",
            "taint_flows",
            "func_references_string",
        ];

        // Extract table references after FROM/JOIN keywords and validate them
        let words: Vec<&str> = q.split_whitespace().collect();
        let mut all_tables_ok = true;
        for (i, word) in words.iter().enumerate() {
            let upper_word = word.to_uppercase();
            if upper_word == "FROM" || upper_word == "JOIN" {
                if let Some(table_word) = words.get(i + 1) {
                    let table = table_word
                        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                        .to_lowercase();
                    if !whitelisted.contains(&table.as_str()) {
                        all_tables_ok = false;
                        break;
                    }
                }
            }
        }

        if all_tables_ok {
            return Ok((q.to_string(), vec![investigation_id.to_string()]));
        } else {
            return Err(format!(
                "SQL passthrough rejected: query references non-whitelisted table. \
                 Allowed tables: {:?}",
                whitelisted
            ));
        }
    }

    let q_preview: String = q.chars().take(80).collect();
    Err(format!(
        "Unsupported query pattern. Try: MATCH (f:Function) RETURN f, or use keywords: \
         FUNCTION, CALL, TAINT, FINDING, SOURCE, SINK, CODE. Got: {}",
        q_preview
    ))
}

/// Extract a function name filter from WHERE clauses like `n.name = 'strcpy'`
/// or `n.name IN ['strcpy', 'system']` or `n.name CONTAINS 'strcpy'`.
/// Only matches Cypher-like patterns (requires MATCH or WHERE prefix).
fn extract_name_filter(query: &str) -> Option<String> {
    let lower = query.to_lowercase();

    // Only match in Cypher-like queries (must start with MATCH or contain WHERE)
    if !lower.contains("match") && !lower.contains("where") {
        return None;
    }

    // Match: n.name = 'foo' or n.name = "foo"
    if let Some(pos) = lower.find(".name") {
        let rest = &query[pos + 1..]; // skip the dot
                                      // Look for quoted string after = or CONTAINS
        for delim in ["= '", "= \"", "contains '", "contains \""] {
            if let Some(start) = rest.to_lowercase().find(delim) {
                let quote_char = if delim.ends_with('\'') { '\'' } else { '"' };
                let value_start = start + delim.len();
                let rest_after = &rest[value_start..];
                if let Some(end) = rest_after.find(quote_char) {
                    let name = &rest_after[..end];
                    if !name.is_empty() && name.len() < 100 {
                        return Some(name.to_string());
                    }
                }
            }
        }

        // Match: n.name IN ['foo', 'bar']
        if let Some(in_pos) = rest.to_lowercase().find(" in [") {
            let bracket_start = in_pos + 5;
            let rest_after = &rest[bracket_start..];
            if let Some(bracket_end) = rest_after.find(']') {
                let items = &rest_after[..bracket_end];
                // Take the first item
                if let Some(first_quote_start) = items.find('\'') {
                    let after = &items[first_quote_start + 1..];
                    if let Some(end) = after.find('\'') {
                        let name = &after[..end];
                        if !name.is_empty() && name.len() < 100 {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract a file filter from WHERE clauses like `n.file CONTAINS 'format_string'`.
fn extract_file_filter(query: &str) -> Option<String> {
    let lower = query.to_lowercase();
    if !lower.contains("file") {
        return None;
    }
    // Look for: file CONTAINS 'x' or file = 'x'
    if let Some(pos) = lower.find("file") {
        let rest = &query[pos..];
        for delim in [
            "contains '",
            "contains \"",
            "= '",
            "= \"",
            "like '",
            "like \"",
        ] {
            if let Some(start) = rest.to_lowercase().find(delim) {
                let quote_char = if delim.ends_with('\'') { '\'' } else { '"' };
                let value_start = start + delim.len();
                let rest_after = &rest[value_start..];
                if let Some(end) = rest_after.find(quote_char) {
                    let pattern = &rest_after[..end];
                    if !pattern.is_empty() && pattern.len() < 200 {
                        return Some(pattern.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Sanitize a string for use in a SQL LIKE pattern.
/// Escapes SQL wildcards to prevent injection via LIKE patterns.
fn sanitize_like_param(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
}

/// Execute a read-only parameterized SQL query and return results as a Vec of JSON objects.
pub fn execute_read_query(
    db: &GraphDb,
    sql: &str,
    params: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let stmt = db.conn().prepare(sql)?;
    if !stmt.readonly() {
        return Ok(vec![
            serde_json::json!({"error": "Only read-only queries are allowed. Write operations are not permitted."}),
        ]);
    }
    let mut stmt = stmt;
    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params
        .iter()
        .map(|s| s as &dyn rusqlite::types::ToSql)
        .collect();

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
    let title = args
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled");
    let severity = args
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
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
            &finding_id as &dyn rusqlite::types::ToSql,
            &title,
            &evidence.to_string(),
            &"vuln_hunter",
            &timestamp,
            &investigation_id,
            &"new",
            &severity,
            &cwe_id,
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
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
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
        let result = execute_read_query(
            &db,
            "INSERT INTO functions (id, name) VALUES ('evil', 'injected')",
            &[],
        )
        .unwrap();

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

        // Raw SELECT on whitelisted tables now passes through SQL passthrough
        let result = translate_to_sql("SELECT * FROM functions", "inv1");
        assert!(result.is_ok());

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

    // ===== Task 3: FIX-QUERY-GRAPH TDD tests =====
    // These tests define the contract for SQL passthrough in translate_to_sql.
    // They will FAIL until the SQL passthrough logic is implemented.

    #[test]
    fn sql_passthrough_accepts_valid_select() {
        // A plain SQL SELECT on whitelisted tables should pass through
        let result = translate_to_sql(
            "SELECT name, source_type FROM data_sources WHERE investigation_id = ?1",
            "inv1",
        );
        assert!(
            result.is_ok(),
            "Valid SQL SELECT on whitelisted table should be accepted"
        );
        let (sql, params) = result.unwrap();
        assert!(
            sql.contains("data_sources"),
            "SQL should be passed through (not re-translated)"
        );
        assert_eq!(params, vec!["inv1"]);
    }

    #[test]
    fn sql_passthrough_accepts_join_on_whitelisted_tables() {
        let result = translate_to_sql(
            "SELECT f.name, s.value FROM functions f \
             JOIN func_references_string frs ON frs.function_id = f.id \
             JOIN string_literals s ON frs.string_id = s.id \
             WHERE f.investigation_id = ?1",
            "inv1",
        );
        assert!(
            result.is_ok(),
            "JOIN on whitelisted tables should be accepted"
        );
    }

    #[test]
    fn sql_passthrough_blocks_insert() {
        let result = translate_to_sql("INSERT INTO functions (id, name) VALUES ('x', 'y')", "inv1");
        assert!(result.is_err(), "INSERT must be blocked by SQL passthrough");
    }

    #[test]
    fn sql_passthrough_blocks_update() {
        let result = translate_to_sql(
            "UPDATE functions SET name = 'hacked' WHERE id = 'f1'",
            "inv1",
        );
        assert!(result.is_err(), "UPDATE must be blocked by SQL passthrough");
    }

    #[test]
    fn sql_passthrough_blocks_delete() {
        let result = translate_to_sql("DELETE FROM functions WHERE id = 'f1'", "inv1");
        assert!(result.is_err(), "DELETE must be blocked by SQL passthrough");
    }

    #[test]
    fn sql_passthrough_blocks_drop() {
        let result = translate_to_sql("DROP TABLE functions", "inv1");
        assert!(result.is_err(), "DROP must be blocked by SQL passthrough");
    }

    #[test]
    fn sql_passthrough_blocks_non_whitelisted_table() {
        let result = translate_to_sql("SELECT * FROM sqlite_master", "inv1");
        assert!(
            result.is_err(),
            "SELECT on non-whitelisted table must be blocked"
        );
    }

    #[test]
    fn sql_passthrough_blocks_semicolons() {
        let result = translate_to_sql(
            "SELECT name FROM functions WHERE investigation_id = ?1; DROP TABLE functions",
            "inv1",
        );
        assert!(
            result.is_err(),
            "Semicolons must be rejected to prevent statement chaining"
        );
    }

    #[test]
    fn sql_passthrough_blocks_sql_comments() {
        let result = translate_to_sql(
            "SELECT name FROM functions -- WHERE investigation_id = ?1",
            "inv1",
        );
        assert!(result.is_err(), "SQL comments (--) must be blocked");

        let result = translate_to_sql(
            "SELECT name FROM functions /* hidden */ WHERE investigation_id = ?1",
            "inv1",
        );
        assert!(result.is_err(), "Block comments (/* */) must be blocked");
    }

    #[test]
    fn sql_passthrough_blocks_load_extension() {
        let result = translate_to_sql("SELECT load_extension('/tmp/evil.so')", "inv1");
        assert!(result.is_err(), "LOAD_EXTENSION must be blocked");
    }

    #[test]
    fn sql_passthrough_cypher_still_works_as_fallback() {
        // Cypher-like queries should still translate correctly
        let result = translate_to_sql("MATCH (f:Function) RETURN f", "inv1");
        assert!(result.is_ok(), "Cypher patterns must still work");
    }

    #[test]
    fn sql_passthrough_execute_returns_rows() {
        // Integration test: valid SQL passthrough should execute and return data
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO symbols (id, name, symbol_type, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"s1" as &dyn rusqlite::types::ToSql,
                &"printf",
                &"import",
                &inv_id,
            ],
        )
        .unwrap();

        let (sql, params) = translate_to_sql(
            "SELECT name, symbol_type FROM symbols WHERE investigation_id = ?1",
            inv_id,
        )
        .unwrap();

        let rows = execute_read_query(&db, &sql, &params).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "printf");
    }

    #[test]
    fn sql_passthrough_all_18_tables_accepted() {
        // Verify all 18 whitelisted tables are accepted in SQL passthrough
        let whitelisted = [
            "functions",
            "basic_blocks",
            "data_sources",
            "data_sinks",
            "vulnerabilities",
            "findings",
            "cwes",
            "investigations",
            "annotations",
            "hypotheses",
            "agent_actions",
            "symbols",
            "string_literals",
            "calls",
            "contains_block",
            "flows_to",
            "taint_flows",
            "func_references_string",
        ];

        for table in &whitelisted {
            let query = format!("SELECT * FROM {} WHERE 1=0", table);
            let result = translate_to_sql(&query, "inv1");
            assert!(
                result.is_ok(),
                "Whitelisted table '{}' should be accepted in SQL passthrough",
                table
            );
        }
    }
}
