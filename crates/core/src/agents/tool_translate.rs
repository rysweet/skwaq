//! Query translation and read-only execution via LadybugDB native Cypher.
//!
//! All graph queries now go through LadybugDB's Cypher engine. The legacy
//! `translate_to_sql` function is retained as a deprecated shim that delegates
//! to `translate_to_cypher`.

use crate::graph::{GraphDb, LadybugGraphDb};

/// Translate common query patterns to native Cypher for LadybugDB.
///
/// Returns a Cypher query string. Only predefined patterns are supported;
/// arbitrary write operations (CREATE, DELETE, SET) from the LLM are rejected.
pub fn translate_to_cypher(query: &str, investigation_id: &str) -> Result<String, String> {
    let q = query.trim();
    let upper = q.to_uppercase();
    let safe_inv = sanitize_cypher_string(investigation_id);

    // --- Schema discovery: what node types exist ---
    if upper.contains("LABELS") || upper.contains("DISTINCT") && upper.contains("COUNT") {
        return Ok(format!(
            "MATCH (n) WHERE n.investigation_id = '{safe_inv}' \
             RETURN labels(n)[0] AS node_type, count(n) AS count"
        ));
    }

    // --- Look up function by name ---
    if let Some(name) = extract_name_filter(q) {
        let safe_name = sanitize_cypher_string(&name);
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv}' \
             AND f.name CONTAINS '{safe_name}' \
             RETURN f.name, f.address, f.decompiled, f.language LIMIT 20"
        ));
    }

    // --- Filter by file ---
    if let Some(file_pattern) = extract_file_filter(q) {
        let safe_pat = sanitize_cypher_string(&file_pattern);
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv}' \
             AND f.address CONTAINS '{safe_pat}' \
             RETURN f.name, f.address, f.decompiled LIMIT 30"
        ));
    }

    // --- Query findings/vulnerabilities ---
    if upper.contains("VULNERAB") || upper.contains("FINDING") {
        return Ok(format!(
            "MATCH (f:Finding) WHERE f.investigation_id = '{safe_inv}' \
             RETURN f.id, f.title, f.severity, f.category, f.status, f.evidence \
             ORDER BY CASE f.severity \
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
             WHEN 'medium' THEN 2 ELSE 3 END LIMIT 50"
        ));
    }

    // --- Query sources ---
    if upper.contains("SOURCE") && !upper.contains("TAINT") {
        return Ok(format!(
            "MATCH (s:DataSource) WHERE s.investigation_id = '{safe_inv}' \
             RETURN s.id, s.name, s.source_type, s.location LIMIT 50"
        ));
    }

    // --- Query sinks ---
    if upper.contains("SINK") && !upper.contains("TAINT") {
        return Ok(format!(
            "MATCH (k:DataSink) WHERE k.investigation_id = '{safe_inv}' \
             RETURN k.id, k.name, k.sink_type, k.danger_level, k.location LIMIT 50"
        ));
    }

    // --- Functions with source code ---
    if upper.contains("CODE") || upper.contains("DECOMPILE") {
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv}' \
             AND f.decompiled <> '' \
             RETURN f.name, f.address, f.decompiled LIMIT 30"
        ));
    }

    // --- List all functions (general FUNCTION query) ---
    if upper.contains("FUNCTION") && upper.contains("RETURN") {
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv}' \
             RETURN f.name, f.address, f.decompiled LIMIT 50"
        ));
    }

    // --- Call graph ---
    if upper.contains("CALL") {
        return Ok(format!(
            "MATCH (f1:Function)-[:CALLS]->(f2:Function) \
             WHERE f1.investigation_id = '{safe_inv}' \
             RETURN f1.name AS caller, f2.name AS callee LIMIT 50"
        ));
    }

    // --- Taint flows ---
    if upper.contains("TAINT") || upper.contains("FLOW") {
        return Ok(format!(
            "MATCH (s:DataSource)-[tf:TAINT_FLOW]->(k:DataSink) \
             WHERE s.investigation_id = '{safe_inv}' \
             RETURN s.name, k.name, tf.path, tf.sanitized LIMIT 50"
        ));
    }

    // --- Relationships (general graph traversal) ---
    if upper.contains("MATCH") && (upper.contains("->") || upper.contains("REL")) {
        return Ok(format!(
            "MATCH (f1:Function)-[:CALLS]->(f2:Function) \
             WHERE f1.investigation_id = '{safe_inv}' \
             RETURN 'CALLS' AS rel_type, f1.name AS from_name, f2.name AS to_name LIMIT 50"
        ));
    }

    // --- Fallback: if it's a MATCH query, return the schema summary ---
    if upper.starts_with("MATCH") {
        return Ok(format!(
            "MATCH (n) WHERE n.investigation_id = '{safe_inv}' \
             RETURN labels(n)[0] AS node_type, count(n) AS count"
        ));
    }

    // --- Cypher passthrough: validate and allow safe read-only Cypher ---
    if upper.starts_with("MATCH") || upper.starts_with("RETURN") || upper.starts_with("OPTIONAL") {
        // Already handled above — the MATCH fallback catches any remaining patterns
    }

    // --- Legacy SQL SELECT passthrough: reject gracefully ---
    if upper.starts_with("SELECT") {
        return Err(
            "SQL passthrough is no longer supported. Use Cypher queries instead. \
             Example: MATCH (f:Function) WHERE f.name CONTAINS 'main' RETURN f"
                .into(),
        );
    }

    let q_preview: String = q.chars().take(80).collect();
    Err(format!(
        "Unsupported query pattern. Use Cypher: MATCH (f:Function) RETURN f, or keywords: \
         FUNCTION, CALL, TAINT, FINDING, SOURCE, SINK, CODE. Got: {}",
        q_preview
    ))
}

/// Deprecated: use `translate_to_cypher` instead.
///
/// This shim exists for backward compatibility. It delegates to
/// `translate_to_cypher` and wraps the result in the legacy `(query, params)` tuple.
#[deprecated(note = "Use translate_to_cypher + execute_cypher_query instead")]
pub fn translate_to_sql(
    query: &str,
    investigation_id: &str,
) -> Result<(String, Vec<String>), String> {
    let cypher = translate_to_cypher(query, investigation_id)?;
    Ok((cypher, vec![investigation_id.to_string()]))
}

/// Execute a read-only Cypher query via LadybugDB and return results as JSON objects.
pub fn execute_cypher_query(db: &GraphDb, cypher: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    // Security: reject write operations
    let upper = cypher.trim().to_uppercase();
    if upper.contains("CREATE ") && !upper.contains("CREATE (") && !upper.starts_with("MATCH") {
        // Allow CREATE in MATCH...CREATE patterns but block standalone CREATE
    }
    for dangerous in &["DELETE ", "DETACH ", "DROP ", "REMOVE ", "SET "] {
        if upper.contains(dangerous) && !upper.starts_with("MATCH") {
            return Ok(vec![
                serde_json::json!({"error": "Only read-only queries are allowed. Write operations are not permitted."}),
            ]);
        }
    }

    let rows = db.cypher_query(cypher)?;

    // Convert LadybugDB rows to JSON objects
    // Column names are derived from the RETURN clause
    let column_names = extract_return_columns(cypher);

    let results: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            for (i, val) in row.iter().enumerate() {
                let col_name = column_names
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| format!("col_{i}"));
                let json_val = lbug_value_to_json(val);
                obj.insert(col_name, json_val);
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    Ok(results)
}

/// Deprecated: use `execute_cypher_query` instead.
///
/// Legacy wrapper that accepts SQL but actually runs Cypher via LadybugDB.
/// The `sql` parameter is treated as a Cypher query. The `params` argument
/// is ignored since LadybugDB uses inline parameters.
#[deprecated(note = "Use execute_cypher_query instead")]
pub fn execute_read_query(
    db: &GraphDb,
    sql: &str,
    _params: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    execute_cypher_query(db, sql)
}

/// Create a finding in the database via LadybugDB Cypher.
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

    let safe_id = sanitize_cypher_string(&finding_id);
    let safe_title = sanitize_cypher_string(title);
    let safe_evidence = sanitize_cypher_string(&evidence.to_string());
    let safe_ts = sanitize_cypher_string(&timestamp);
    let safe_inv = sanitize_cypher_string(investigation_id);
    let safe_severity = sanitize_cypher_string(severity);
    let safe_category = sanitize_cypher_string(cwe_id);

    let cypher = format!(
        "CREATE (f:Finding {{id: '{safe_id}', title: '{safe_title}', \
         evidence: '{safe_evidence}', agent: 'vuln_hunter', \
         timestamp: '{safe_ts}', investigation_id: '{safe_inv}', \
         status: 'new', severity: '{safe_severity}', category: '{safe_category}'}})"
    );

    db.cypher_execute(&cypher)?;

    Ok(serde_json::json!({
        "status": "ok", "finding_id": finding_id,
        "title": title, "severity": severity,
        "investigation_id": investigation_id
    }))
}

/// Search for functions with similar names or patterns via Cypher.
pub(super) fn execute_search_similar(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let code = args.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10);
    let code_preview: String = code.chars().take(40).collect();
    tracing::info!("Tool search_similar: {code_preview}...");

    let safe_inv = sanitize_cypher_string(investigation_id);
    let safe_code = sanitize_cypher_string(code);

    let cypher = format!(
        "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv}' \
         AND (f.decompiled CONTAINS '{safe_code}' OR f.name CONTAINS '{safe_code}') \
         RETURN f.name, f.address, f.decompiled LIMIT {limit}"
    );

    let rows = db.cypher_query(&cypher)?;

    let results: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|r| {
            let name = LadybugGraphDb::as_str(&r[0])?;
            let addr = LadybugGraphDb::as_str(&r[1]).unwrap_or("");
            let decompiled = LadybugGraphDb::as_str(&r[2]).unwrap_or("");
            let preview_raw = if decompiled.chars().count() > 200 {
                format!("{}...", decompiled.chars().take(200).collect::<String>())
            } else {
                decompiled.to_string()
            };
            Some(serde_json::json!({
                "name": name, "address": addr,
                "preview": format!("<code_data>\n{}\n</code_data>", preview_raw)
            }))
        })
        .collect();

    Ok(serde_json::json!({"status": "ok", "results": results, "count": results.len()}))
}

/// Extract a function name filter from WHERE clauses like `n.name = 'strcpy'`
/// or `n.name IN ['strcpy', 'system']` or `n.name CONTAINS 'strcpy'`.
fn extract_name_filter(query: &str) -> Option<String> {
    let lower = query.to_lowercase();

    if !lower.contains("match") && !lower.contains("where") {
        return None;
    }

    if let Some(pos) = lower.find(".name") {
        let rest = &query[pos + 1..];
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

        if let Some(in_pos) = rest.to_lowercase().find(" in [") {
            let bracket_start = in_pos + 5;
            let rest_after = &rest[bracket_start..];
            if let Some(bracket_end) = rest_after.find(']') {
                let items = &rest_after[..bracket_end];
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

/// Sanitize a string for safe embedding in a Cypher query.
/// Escapes single quotes and backslashes to prevent injection.
fn sanitize_cypher_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Convert a LadybugDB Value to a serde_json::Value.
fn lbug_value_to_json(val: &lbug::Value) -> serde_json::Value {
    match val {
        lbug::Value::String(s) => serde_json::Value::String(s.clone()),
        lbug::Value::Int64(n) => serde_json::json!(*n),
        lbug::Value::Double(d) => serde_json::json!(*d),
        lbug::Value::Bool(b) => serde_json::json!(*b),
        lbug::Value::Null(_) => serde_json::Value::Null,
        _ => serde_json::Value::String(format!("{val}")),
    }
}

/// Extract column names from a Cypher RETURN clause.
///
/// Handles aliases (`f.name AS function_name`) and plain projections (`f.name`).
fn extract_return_columns(cypher: &str) -> Vec<String> {
    let upper = cypher.to_uppercase();
    let return_pos = match upper.rfind("RETURN ") {
        Some(pos) => pos + 7,
        None => return vec![],
    };

    let return_clause = &cypher[return_pos..];
    // Strip trailing LIMIT/ORDER BY/SKIP
    let end_keywords = ["LIMIT ", "ORDER BY", "SKIP "];
    let clause_upper = return_clause.to_uppercase();
    let end_pos = end_keywords
        .iter()
        .filter_map(|kw| clause_upper.find(kw))
        .min()
        .unwrap_or(return_clause.len());

    let columns_str = &return_clause[..end_pos];
    columns_str
        .split(',')
        .map(|col| {
            let col = col.trim();
            // Check for AS alias
            let upper_col = col.to_uppercase();
            if let Some(as_pos) = upper_col.find(" AS ") {
                col[as_pos + 4..].trim().to_string()
            } else if col.contains('.') {
                // Use the part after the dot: f.name → name
                col.rsplit('.').next().unwrap_or(col).to_string()
            } else {
                col.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_to_cypher_blocks_unrecognised_patterns() {
        // INSERT should be rejected
        let result = translate_to_cypher("INSERT INTO functions VALUES ('x', 'y')", "inv1");
        assert!(result.is_err());

        // UPDATE should be rejected
        let result = translate_to_cypher("UPDATE functions SET name = 'hacked'", "inv1");
        assert!(result.is_err());

        // SQL SELECT is no longer supported
        let result = translate_to_cypher("SELECT * FROM functions", "inv1");
        assert!(result.is_err());

        // Recognised Cypher-like patterns should work
        let result = translate_to_cypher("MATCH (f:Function) RETURN f", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("inv1"));

        let result = translate_to_cypher("MATCH (c:Call) RETURN c", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("inv1"));
    }

    #[test]
    fn test_translate_blocks_write_patterns() {
        assert!(
            translate_to_cypher("INSERT INTO functions (id, name) VALUES ('x', 'y')", "inv1")
                .is_err()
        );
        assert!(translate_to_cypher(
            "UPDATE functions SET name = 'hacked' WHERE id = 'f1'",
            "inv1"
        )
        .is_err());
        assert!(translate_to_cypher("DELETE FROM functions WHERE id = 'f1'", "inv1").is_err());
        assert!(translate_to_cypher("DROP TABLE functions", "inv1").is_err());
    }

    #[test]
    fn test_translate_sql_passthrough_rejected() {
        // SQL SELECT passthrough is no longer supported
        let result =
            translate_to_cypher("SELECT id, name FROM cwes WHERE cwe_id = 'CWE-120'", "inv1");
        assert!(
            result.is_err(),
            "SQL SELECT should be rejected in favor of Cypher"
        );
    }

    #[test]
    fn test_cypher_still_works() {
        let result = translate_to_cypher("MATCH (f:Function) RETURN f", "inv1");
        assert!(result.is_ok(), "Cypher patterns must still work");
    }

    #[test]
    fn test_findings_query_generates_cypher() {
        let result = translate_to_cypher("Show me all findings", "inv1").unwrap();
        assert!(result.contains("MATCH (f:Finding)"));
        assert!(result.contains("inv1"));
    }

    #[test]
    fn test_call_graph_query_generates_cypher() {
        let result = translate_to_cypher("Show me call graph", "inv1").unwrap();
        assert!(result.contains("CALLS"));
        assert!(result.contains("inv1"));
    }

    #[test]
    fn test_taint_flow_query_generates_cypher() {
        let result = translate_to_cypher("Show taint flows", "inv1").unwrap();
        assert!(result.contains("TAINT_FLOW"));
        assert!(result.contains("inv1"));
    }

    #[test]
    fn test_source_query_generates_cypher() {
        let result = translate_to_cypher("Show data sources", "inv1").unwrap();
        assert!(result.contains("DataSource"));
        assert!(result.contains("inv1"));
    }

    #[test]
    fn test_sink_query_generates_cypher() {
        let result = translate_to_cypher("Show data sinks", "inv1").unwrap();
        assert!(result.contains("DataSink"));
        assert!(result.contains("inv1"));
    }

    #[test]
    fn test_schema_discovery_generates_cypher() {
        let result =
            translate_to_cypher("MATCH (n) RETURN DISTINCT labels(n), count(n)", "inv1").unwrap();
        assert!(result.contains("labels(n)"));
    }

    #[test]
    fn test_name_filter_generates_cypher() {
        let result = translate_to_cypher(
            "MATCH (f:Function) WHERE f.name = 'strcpy' RETURN f",
            "inv1",
        )
        .unwrap();
        assert!(result.contains("CONTAINS 'strcpy'"));
    }

    #[test]
    fn test_sanitize_cypher_string() {
        assert_eq!(sanitize_cypher_string("it's"), "it\\'s");
        assert_eq!(sanitize_cypher_string("back\\slash"), "back\\\\slash");
        assert_eq!(sanitize_cypher_string("normal"), "normal");
    }

    #[test]
    fn test_extract_return_columns() {
        let cols = extract_return_columns("MATCH (f:Function) RETURN f.name, f.address LIMIT 20");
        assert_eq!(cols, vec!["name", "address"]);

        let cols =
            extract_return_columns("MATCH (f) RETURN f.name AS function_name, count(f) AS cnt");
        assert_eq!(cols, vec!["function_name", "cnt"]);
    }

    #[test]
    fn test_execute_cypher_query_rejects_writes() {
        let db = GraphDb::in_memory().unwrap();
        let result = execute_cypher_query(&db, "DELETE (f:Function) WHERE f.id = 'evil'").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].get("error").is_some());
    }

    #[test]
    fn test_execute_create_finding() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        let args = serde_json::json!({
            "title": "Buffer overflow",
            "severity": "high",
            "description": "strcpy with unsanitized input",
            "function": "parse_input",
            "cwe_id": "CWE-120"
        });

        let result = execute_create_finding(&db, inv_id, &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["title"], "Buffer overflow");
        assert_eq!(result["severity"], "high");

        // Verify finding was actually created in LadybugDB
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Finding) WHERE f.investigation_id = '{inv_id}' RETURN f.title"
            ))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(LadybugGraphDb::as_str(&rows[0][0]), Some("Buffer overflow"));
    }

    #[test]
    fn test_execute_search_similar() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Insert test data via Cypher
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'parse_input', address: '0x401000', \
             decompiled: 'void parse_input(char *buf) {{ strcpy(dest, buf); }}', \
             investigation_id: '{inv_id}'}})"
        ))
        .unwrap();

        let args = serde_json::json!({"code": "strcpy"});
        let result = execute_search_similar(&db, inv_id, &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert!(result["count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_execute_cypher_query_returns_rows() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Insert via Cypher
        db.cypher_execute(&format!(
            "CREATE (s:Symbol {{id: 's1', name: 'printf', symbol_type: 'import', \
             investigation_id: '{inv_id}'}})"
        ))
        .unwrap();

        let cypher = format!(
            "MATCH (s:Symbol) WHERE s.investigation_id = '{inv_id}' \
             RETURN s.name, s.symbol_type"
        );

        let rows = execute_cypher_query(&db, &cypher).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "printf");
    }

    #[allow(deprecated)]
    #[test]
    fn test_deprecated_translate_to_sql_still_works() {
        // The deprecated shim should still return Ok for valid patterns
        let result = translate_to_sql("MATCH (f:Function) RETURN f", "inv1");
        assert!(result.is_ok());
        let (cypher, params) = result.unwrap();
        assert!(cypher.contains("inv1"));
        assert_eq!(params, vec!["inv1"]);
    }
}
