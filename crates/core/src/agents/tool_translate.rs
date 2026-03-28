//! Cypher query translation and execution for the graph database.
//!
//! Converts LLM query patterns into native Cypher queries for LadybugDB.
//! All graph queries go through `cypher_query()`/`cypher_execute()` which
//! safely scope the C++ FFI connection lifetime.

use crate::graph::ladybug_db::LadybugGraphDb;
use crate::graph::GraphDb;

/// Escape a string for embedding in a Cypher single-quoted literal.
///
/// Follows the same pattern as `MemoryStore::esc` in store.rs.
pub(super) fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Validate that an investigation_id contains only safe characters.
fn validate_investigation_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("Empty investigation_id".into());
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Invalid investigation_id: only alphanumeric, underscore, and hyphen allowed".into(),
        );
    }
    Ok(())
}

/// Build a schema summary Cypher query for the given investigation.
fn schema_summary(inv: &str) -> (String, Vec<String>) {
    (
        format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
             RETURN 'Function' AS table_name, count(f) AS count \
             UNION ALL \
             MATCH (s:DataSource) WHERE s.investigation_id = '{inv}' \
             RETURN 'DataSource' AS table_name, count(s) AS count \
             UNION ALL \
             MATCH (k:DataSink) WHERE k.investigation_id = '{inv}' \
             RETURN 'DataSink' AS table_name, count(k) AS count \
             UNION ALL \
             MATCH (fd:Finding) WHERE fd.investigation_id = '{inv}' \
             RETURN 'Finding' AS table_name, count(fd) AS count"
        ),
        vec!["table_name".into(), "count".into()],
    )
}

/// Translate common Cypher-like query patterns into native Cypher.
///
/// Returns `(cypher, column_names)` on success. Only predefined patterns
/// are supported; arbitrary input is rejected.
pub fn translate_to_cypher(
    query: &str,
    investigation_id: &str,
) -> Result<(String, Vec<String>), String> {
    validate_investigation_id(investigation_id)?;
    let q = query.trim();
    let upper = q.to_uppercase();
    let inv = esc(investigation_id);

    // --- Schema discovery: what node types exist ---
    if upper.contains("LABELS") || (upper.contains("DISTINCT") && upper.contains("COUNT")) {
        return Ok(schema_summary(&inv));
    }

    // --- Look up function by name ---
    if let Some(name) = extract_name_filter(q) {
        return Ok((
            format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
                 AND f.name CONTAINS '{name}' \
                 RETURN f.name, f.address, f.decompiled, f.language LIMIT 20",
                name = esc(&name)
            ),
            vec![
                "name".into(),
                "address".into(),
                "decompiled".into(),
                "language".into(),
            ],
        ));
    }

    // --- Filter by file ---
    if let Some(file_pattern) = extract_file_filter(q) {
        return Ok((
            format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
                 AND f.address CONTAINS '{pat}' \
                 RETURN f.name, f.address, f.decompiled LIMIT 30",
                pat = esc(&file_pattern)
            ),
            vec!["name".into(), "address".into(), "decompiled".into()],
        ));
    }

    // --- Query findings/vulnerabilities ---
    if upper.contains("VULNERAB") || upper.contains("FINDING") {
        return Ok((
            format!(
                "MATCH (f:Finding) WHERE f.investigation_id = '{inv}' \
                 RETURN f.id, f.title, f.severity, f.category, f.status, f.evidence \
                 ORDER BY CASE f.severity \
                 WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
                 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 50"
            ),
            vec![
                "id".into(),
                "title".into(),
                "severity".into(),
                "category".into(),
                "status".into(),
                "evidence".into(),
            ],
        ));
    }

    // --- Query sources ---
    if upper.contains("SOURCE") && !upper.contains("TAINT") {
        return Ok((
            format!(
                "MATCH (s:DataSource) WHERE s.investigation_id = '{inv}' \
                 RETURN s.id, s.name, s.source_type, s.location LIMIT 50"
            ),
            vec![
                "id".into(),
                "name".into(),
                "source_type".into(),
                "location".into(),
            ],
        ));
    }

    // --- Query sinks ---
    if upper.contains("SINK") && !upper.contains("TAINT") {
        return Ok((
            format!(
                "MATCH (k:DataSink) WHERE k.investigation_id = '{inv}' \
                 RETURN k.id, k.name, k.sink_type, k.danger_level, k.location LIMIT 50"
            ),
            vec![
                "id".into(),
                "name".into(),
                "sink_type".into(),
                "danger_level".into(),
                "location".into(),
            ],
        ));
    }

    // --- Functions with source code ---
    if upper.contains("CODE") || upper.contains("DECOMPILE") {
        return Ok((
            format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
                 AND f.decompiled <> '' \
                 RETURN f.name, f.address, f.decompiled LIMIT 30"
            ),
            vec!["name".into(), "address".into(), "decompiled".into()],
        ));
    }

    // --- List all functions (general FUNCTION query) ---
    if upper.contains("FUNCTION") && upper.contains("RETURN") {
        return Ok((
            format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
                 RETURN f.name, f.address, f.decompiled LIMIT 50"
            ),
            vec!["name".into(), "address".into(), "decompiled".into()],
        ));
    }

    // --- Call graph ---
    if upper.contains("CALL") {
        return Ok((
            format!(
                "MATCH (f1:Function)-[:CALLS]->(f2:Function) \
                 WHERE f1.investigation_id = '{inv}' \
                 RETURN f1.name AS caller, f2.name AS callee LIMIT 50"
            ),
            vec!["caller".into(), "callee".into()],
        ));
    }

    // --- Taint flows ---
    if upper.contains("TAINT") || upper.contains("FLOW") {
        return Ok((
            format!(
                "MATCH (s:DataSource)-[t:TAINT_FLOW]->(k:DataSink) \
                 WHERE s.investigation_id = '{inv}' \
                 RETURN s.name, k.name, t.path, t.sanitized LIMIT 50"
            ),
            vec![
                "source_name".into(),
                "sink_name".into(),
                "path".into(),
                "sanitized".into(),
            ],
        ));
    }

    // --- Relationships (general graph traversal) ---
    if upper.contains("MATCH") && (upper.contains("->") || upper.contains("REL")) {
        return Ok((
            format!(
                "MATCH (f1:Function)-[:CALLS]->(f2:Function) \
                 WHERE f1.investigation_id = '{inv}' \
                 RETURN 'CALLS' AS rel_type, f1.name AS from_name, f2.name AS to_name LIMIT 50"
            ),
            vec!["rel_type".into(), "from_name".into(), "to_name".into()],
        ));
    }

    // --- Fallback for MATCH queries: schema summary ---
    if upper.starts_with("MATCH") {
        return Ok(schema_summary(&inv));
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
pub(super) fn extract_name_filter(query: &str) -> Option<String> {
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
pub(super) fn extract_file_filter(query: &str) -> Option<String> {
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

/// Execute a Cypher read query and return results as JSON objects.
///
/// Uses `db.cypher_query()` which safely scopes the C++ FFI connection.
/// Results are fully materialized (collected into Vec) before the
/// connection is dropped — critical for memory safety with the lbug crate.
pub fn execute_cypher_read_query(
    db: &GraphDb,
    cypher: &str,
    columns: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let rows = db.cypher_query(cypher)?;
    let results: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            for (i, col) in columns.iter().enumerate() {
                if i < row.len() {
                    let val = if let Some(s) = LadybugGraphDb::as_str(&row[i]) {
                        serde_json::Value::String(s.to_string())
                    } else if let Some(n) = LadybugGraphDb::as_i64(&row[i]) {
                        serde_json::json!(n)
                    } else if let Some(d) = LadybugGraphDb::as_f64(&row[i]) {
                        serde_json::json!(d)
                    } else {
                        serde_json::Value::Null
                    };
                    obj.insert(col.clone(), val);
                }
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    Ok(results)
}

/// Create a finding in the graph database via Cypher.
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

    let cypher = format!(
        "CREATE (f:Finding {{id: '{id}', title: '{title}', evidence: '{ev}', \
         agent: 'vuln_hunter', timestamp: '{ts}', investigation_id: '{inv}', \
         status: 'new', severity: '{sev}', category: '{cat}'}})",
        id = esc(&finding_id),
        title = esc(title),
        ev = esc(&evidence.to_string()),
        ts = esc(&timestamp),
        inv = esc(investigation_id),
        sev = esc(severity),
        cat = esc(cwe_id),
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
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let code_preview: String = code.chars().take(40).collect();
    tracing::info!("Tool search_similar: {code_preview}...");

    let search_term = esc(code);
    let inv = esc(investigation_id);

    let cypher = format!(
        "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
         AND (f.decompiled CONTAINS '{search}' OR f.name CONTAINS '{search}') \
         RETURN f.name, f.address, f.decompiled LIMIT {limit}",
        search = search_term,
    );

    let rows = db.cypher_query(&cypher)?;
    let results: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|row| {
            if row.len() < 3 {
                return None;
            }
            let name = LadybugGraphDb::as_str(&row[0])?.to_string();
            let addr = LadybugGraphDb::as_str(&row[1]).unwrap_or("").to_string();
            let decompiled = LadybugGraphDb::as_str(&row[2]).unwrap_or("").to_string();
            let preview_raw = if decompiled.chars().count() > 200 {
                format!("{}...", decompiled.chars().take(200).collect::<String>())
            } else {
                decompiled
            };
            Some(serde_json::json!({
                "name": name, "address": addr,
                "preview": format!("<code_data>\n{}\n</code_data>", preview_raw)
            }))
        })
        .collect();

    Ok(serde_json::json!({"status": "ok", "results": results, "count": results.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_to_cypher_blocks_unrecognized_patterns() {
        // INSERT should be rejected
        let result = translate_to_cypher("INSERT INTO functions VALUES ('x', 'y')", "inv1");
        assert!(result.is_err());

        // UPDATE should be rejected
        let result = translate_to_cypher("UPDATE functions SET name = 'hacked'", "inv1");
        assert!(result.is_err());

        // SELECT should be rejected (no SQL passthrough in Cypher mode)
        let result = translate_to_cypher("SELECT * FROM functions", "inv1");
        assert!(result.is_err());
    }

    #[test]
    fn test_translate_to_cypher_recognized_patterns() {
        // Cypher-like MATCH with FUNCTION keyword
        let result = translate_to_cypher("MATCH (f:Function) RETURN f", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("Function"));
        assert!(cypher.contains("inv1"));
        assert_eq!(cols, vec!["name", "address", "decompiled"]);

        // Call graph
        let result = translate_to_cypher("MATCH (c:Call) RETURN c", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("CALLS"));
        assert_eq!(cols, vec!["caller", "callee"]);
    }

    #[test]
    fn test_translate_to_cypher_findings_pattern() {
        let result = translate_to_cypher("Show me all findings", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("Finding"));
        assert!(cypher.contains("severity"));
        assert!(cols.contains(&"id".to_string()));
        assert!(cols.contains(&"title".to_string()));
    }

    #[test]
    fn test_translate_to_cypher_name_filter() {
        let result =
            translate_to_cypher("MATCH (n:Function) WHERE n.name = 'strcpy' RETURN n", "inv1");
        assert!(result.is_ok());
        let (cypher, _cols) = result.unwrap();
        assert!(cypher.contains("CONTAINS 'strcpy'"));
    }

    #[test]
    fn test_translate_to_cypher_taint_pattern() {
        let result = translate_to_cypher("Show me taint flows", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("TAINT_FLOW"));
        assert!(cols.contains(&"source_name".to_string()));
        assert!(cols.contains(&"sink_name".to_string()));
    }

    #[test]
    fn test_validate_investigation_id() {
        assert!(validate_investigation_id("abc-123_def").is_ok());
        assert!(validate_investigation_id("").is_err());
        assert!(validate_investigation_id("abc;DROP").is_err());
        assert!(validate_investigation_id("abc'OR'1'='1").is_err());
    }

    #[test]
    fn test_esc_function() {
        assert_eq!(esc("hello"), "hello");
        assert_eq!(esc("it's"), "it\\'s");
        assert_eq!(esc("back\\slash"), "back\\\\slash");
        assert_eq!(esc("both'and\\"), "both\\'and\\\\");
    }

    #[test]
    fn test_translate_to_cypher_schema_discovery() {
        let result = translate_to_cypher("MATCH (n) RETURN DISTINCT LABELS(n), COUNT(n)", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("Function"));
        assert!(cypher.contains("DataSource"));
        assert!(cypher.contains("DataSink"));
        assert!(cypher.contains("Finding"));
        assert_eq!(cols, vec!["table_name", "count"]);
    }

    #[test]
    fn test_execute_cypher_read_query_with_data() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Insert test data into LadybugDB
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'main', address: '0x1000', \
             decompiled: 'void main() {{}}', investigation_id: '{}'}})",
            inv_id
        ))
        .unwrap();

        let columns = vec![
            "name".to_string(),
            "address".to_string(),
            "decompiled".to_string(),
        ];
        let cypher = format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{}' \
             RETURN f.name, f.address, f.decompiled LIMIT 10",
            inv_id
        );

        let rows = execute_cypher_read_query(&db, &cypher, &columns).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "main");
        assert_eq!(rows[0]["address"], "0x1000");
    }

    #[test]
    fn test_execute_create_finding_via_cypher() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        let args = serde_json::json!({
            "title": "Buffer Overflow",
            "severity": "critical",
            "description": "Stack buffer overflow in strcpy",
            "function": "vulnerable_func",
            "cwe_id": "CWE-120"
        });

        let result = execute_create_finding(&db, inv_id, &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["title"], "Buffer Overflow");
        assert_eq!(result["severity"], "critical");

        // Verify finding exists in LadybugDB
        let finding_id = result["finding_id"].as_str().unwrap();
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Finding {{id: '{}'}}) RETURN f.title, f.severity",
                finding_id
            ))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(LadybugGraphDb::as_str(&rows[0][0]), Some("Buffer Overflow"));
        assert_eq!(LadybugGraphDb::as_str(&rows[0][1]), Some("critical"));
    }

    #[test]
    fn test_execute_search_similar_via_cypher() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Insert test functions into LadybugDB
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'strcpy_wrapper', address: '0x1000', \
             decompiled: 'void strcpy_wrapper(char *d, char *s) {{ strcpy(d, s); }}', \
             investigation_id: '{}'}})",
            inv_id
        ))
        .unwrap();

        let args = serde_json::json!({"code": "strcpy", "limit": 10});
        let result = execute_search_similar(&db, inv_id, &args).unwrap();
        assert_eq!(result["status"], "ok");
        let count = result["count"].as_u64().unwrap();
        assert!(count >= 1, "Should find at least one matching function");
    }

    #[test]
    fn test_translate_to_cypher_source_pattern() {
        let result = translate_to_cypher("Show me data sources", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("DataSource"));
        assert!(cols.contains(&"source_type".to_string()));
    }

    #[test]
    fn test_translate_to_cypher_sink_pattern() {
        let result = translate_to_cypher("Show me data sinks", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        assert!(cypher.contains("DataSink"));
        assert!(cols.contains(&"danger_level".to_string()));
    }

    #[test]
    fn test_translate_to_cypher_code_pattern() {
        let result = translate_to_cypher("Show me functions with decompiled code", "inv1");
        assert!(result.is_ok());
        let (cypher, _cols) = result.unwrap();
        assert!(cypher.contains("decompiled <> ''"));
    }

    #[test]
    fn test_translate_to_cypher_match_fallback() {
        let result = translate_to_cypher("MATCH (x:SomeUnknown) RETURN x", "inv1");
        assert!(result.is_ok());
        let (cypher, cols) = result.unwrap();
        // Should return schema summary
        assert!(cypher.contains("count"));
        assert_eq!(cols, vec!["table_name", "count"]);
    }

    // ===== TDD: extract_name_filter edge cases =====

    #[test]
    fn test_extract_name_filter_equals_single_quote() {
        let q = "MATCH (n:Function) WHERE n.name = 'system' RETURN n";
        assert_eq!(extract_name_filter(q), Some("system".to_string()));
    }

    #[test]
    fn test_extract_name_filter_equals_double_quote() {
        let q = r#"MATCH (n:Function) WHERE n.name = "gets" RETURN n"#;
        assert_eq!(extract_name_filter(q), Some("gets".to_string()));
    }

    #[test]
    fn test_extract_name_filter_contains() {
        let q = "MATCH (n:Function) WHERE n.name CONTAINS 'recv' RETURN n";
        assert_eq!(extract_name_filter(q), Some("recv".to_string()));
    }

    #[test]
    fn test_extract_name_filter_in_list() {
        let q = "MATCH (n:Function) WHERE n.name IN ['strcpy', 'strcat'] RETURN n";
        // Should extract the first item
        assert_eq!(extract_name_filter(q), Some("strcpy".to_string()));
    }

    #[test]
    fn test_extract_name_filter_no_match_keyword() {
        // No MATCH or WHERE — should return None
        let q = "SELECT name FROM functions";
        assert_eq!(extract_name_filter(q), None);
    }

    #[test]
    fn test_extract_name_filter_empty_name() {
        let q = "MATCH (n:Function) WHERE n.name = '' RETURN n";
        assert_eq!(extract_name_filter(q), None);
    }

    #[test]
    fn test_extract_name_filter_very_long_name_rejected() {
        let long = "a".repeat(150);
        let q = format!("MATCH (n:Function) WHERE n.name = '{}' RETURN n", long);
        assert_eq!(extract_name_filter(&q), None, "Names >= 100 chars should be rejected");
    }

    // ===== TDD: extract_file_filter edge cases =====

    #[test]
    fn test_extract_file_filter_contains() {
        let q = "MATCH (n) WHERE n.file CONTAINS 'format_string' RETURN n";
        assert_eq!(extract_file_filter(q), Some("format_string".to_string()));
    }

    #[test]
    fn test_extract_file_filter_equals() {
        let q = "MATCH (n) WHERE n.file = 'main.c' RETURN n";
        assert_eq!(extract_file_filter(q), Some("main.c".to_string()));
    }

    #[test]
    fn test_extract_file_filter_like() {
        let q = "MATCH (n) WHERE n.file LIKE '%.c' RETURN n";
        assert_eq!(extract_file_filter(q), Some("%.c".to_string()));
    }

    #[test]
    fn test_extract_file_filter_no_file_keyword() {
        let q = "MATCH (n) WHERE n.name = 'main' RETURN n";
        assert_eq!(extract_file_filter(q), None);
    }

    #[test]
    fn test_extract_file_filter_empty_pattern() {
        let q = "MATCH (n) WHERE n.file = '' RETURN n";
        assert_eq!(extract_file_filter(q), None);
    }

    #[test]
    fn test_extract_file_filter_very_long_pattern_rejected() {
        let long = "x".repeat(250);
        let q = format!("MATCH (n) WHERE n.file = '{}' RETURN n", long);
        assert_eq!(extract_file_filter(&q), None, "Patterns >= 200 chars should be rejected");
    }

    // ===== TDD: esc() adversarial inputs =====

    #[test]
    fn test_esc_null_bytes() {
        // Null bytes should pass through (lbug handles them)
        let result = esc("hello\0world");
        assert!(result.contains('\0'));
    }

    #[test]
    fn test_esc_nested_escapes() {
        // Already-escaped input should get double-escaped
        assert_eq!(esc("it\\'s"), "it\\\\\\'s");
    }

    #[test]
    fn test_esc_unicode() {
        assert_eq!(esc("héllo wörld"), "héllo wörld");
        assert_eq!(esc("日本語"), "日本語");
    }

    #[test]
    fn test_esc_empty_string() {
        assert_eq!(esc(""), "");
    }

    #[test]
    fn test_esc_only_special_chars() {
        assert_eq!(esc("'''"), "\\'\\'\\'");
        assert_eq!(esc("\\\\"), "\\\\\\\\");
    }

    // ===== TDD: validate_investigation_id edge cases =====

    #[test]
    fn test_validate_investigation_id_with_spaces() {
        assert!(validate_investigation_id("has space").is_err());
    }

    #[test]
    fn test_validate_investigation_id_with_dots() {
        assert!(validate_investigation_id("inv.123").is_err());
    }

    #[test]
    fn test_validate_investigation_id_with_slashes() {
        assert!(validate_investigation_id("../../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_investigation_id_cypher_injection() {
        assert!(validate_investigation_id("inv' OR '1'='1").is_err());
        assert!(validate_investigation_id("inv}) RETURN n//").is_err());
    }

    #[test]
    fn test_validate_investigation_id_valid_formats() {
        assert!(validate_investigation_id("inv-1").is_ok());
        assert!(validate_investigation_id("inv_2").is_ok());
        assert!(validate_investigation_id("abc123").is_ok());
        assert!(validate_investigation_id("A").is_ok());
    }

    // ===== TDD: translate_to_cypher — investigation_id always in output =====

    #[test]
    fn test_all_cypher_patterns_include_investigation_id() {
        let patterns = [
            "MATCH (n) RETURN DISTINCT LABELS(n), COUNT(n)",
            "MATCH (n:Function) WHERE n.name = 'main' RETURN n",
            "MATCH (n) WHERE n.file CONTAINS 'test.c' RETURN n",
            "Show me findings",
            "Show me data sources",
            "Show me sinks",
            "Show me decompiled code",
            "MATCH (f:Function) RETURN f",
            "Show me call graph",
            "Show me taint flows",
            "MATCH (a)-[r]->(b) RETURN a, r, b",
            "MATCH (x:Unknown) RETURN x",
        ];
        for pat in &patterns {
            let result = translate_to_cypher(pat, "test-inv-42");
            match result {
                Ok((cypher, _)) => {
                    assert!(
                        cypher.contains("test-inv-42"),
                        "Pattern '{}' generated Cypher without investigation_id: {}",
                        pat,
                        cypher
                    );
                }
                Err(_) => {
                    // Unrecognized patterns are fine — they return Err
                }
            }
        }
    }

    // ===== TDD: translate_to_cypher — all patterns have LIMIT =====

    #[test]
    fn test_non_schema_patterns_have_limit() {
        let patterns_with_limit = [
            "MATCH (n:Function) WHERE n.name = 'main' RETURN n",
            "MATCH (n) WHERE n.file CONTAINS 'test.c' RETURN n",
            "Show me findings",
            "Show me data sources",
            "Show me sinks",
            "Show me decompiled code",
            "MATCH (f:Function) RETURN f",
            "Show me call graph",
            "Show me taint flows",
            "MATCH (a)-[r]->(b) RETURN a, r, b",
        ];
        for pat in &patterns_with_limit {
            if let Ok((cypher, _)) = translate_to_cypher(pat, "inv1") {
                assert!(
                    cypher.contains("LIMIT"),
                    "Pattern '{}' generated Cypher without LIMIT: {}",
                    pat,
                    cypher
                );
            }
        }
    }

    // ===== TDD: execute_cypher_read_query edge cases =====

    #[test]
    fn test_execute_cypher_read_query_empty_results() {
        let db = GraphDb::in_memory().unwrap();
        let columns = vec!["name".to_string()];
        let cypher = "MATCH (f:Function) WHERE f.investigation_id = 'nonexistent' RETURN f.name";
        let rows = execute_cypher_read_query(&db, cypher, &columns).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_execute_cypher_read_query_more_columns_than_data() {
        let db = GraphDb::in_memory().unwrap();
        db.cypher_execute(
            "CREATE (f:Function {id: 'f1', name: 'test', investigation_id: 'inv1'})",
        )
        .unwrap();

        // Request 5 columns but query only returns 1
        let columns = vec![
            "name".into(),
            "extra1".into(),
            "extra2".into(),
            "extra3".into(),
            "extra4".into(),
        ];
        let cypher = "MATCH (f:Function) WHERE f.investigation_id = 'inv1' RETURN f.name";
        let rows = execute_cypher_read_query(&db, cypher, &columns).unwrap();
        assert_eq!(rows.len(), 1);
        // First column should be present; extras should be absent (not panicking)
        assert_eq!(rows[0]["name"], "test");
    }

    // ===== TDD: execute_create_finding with defaults =====

    #[test]
    fn test_execute_create_finding_minimal_args() {
        let db = GraphDb::in_memory().unwrap();
        // Only required field missing — should use defaults
        let args = serde_json::json!({});
        let result = execute_create_finding(&db, "inv1", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["title"], "Untitled");
        assert_eq!(result["severity"], "medium");
    }

    #[test]
    fn test_execute_create_finding_special_chars_in_title() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({
            "title": "Buffer overflow in func('user_input')",
            "severity": "high"
        });
        let result = execute_create_finding(&db, "inv1", &args).unwrap();
        assert_eq!(result["status"], "ok");
        // Verify the finding can be retrieved (escaping worked)
        let finding_id = result["finding_id"].as_str().unwrap();
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Finding {{id: '{}'}}) RETURN f.title",
                finding_id
            ))
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    // ===== TDD: execute_search_similar edge cases =====

    #[test]
    fn test_execute_search_similar_empty_code() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"code": "", "limit": 5});
        let result = execute_search_similar(&db, "inv1", &args).unwrap();
        assert_eq!(result["status"], "ok");
        // Empty search should still return ok (just possibly empty results)
    }

    #[test]
    fn test_execute_search_similar_respects_limit() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "inv1";

        // Insert multiple functions
        for i in 0..5 {
            db.cypher_execute(&format!(
                "CREATE (f:Function {{id: 'f{i}', name: 'func_{i}', address: '0x{i}000', \
                 decompiled: 'void func_{i}() {{ target(); }}', investigation_id: '{inv_id}'}})",
            ))
            .unwrap();
        }

        let args = serde_json::json!({"code": "target", "limit": 2});
        let result = execute_search_similar(&db, inv_id, &args).unwrap();
        assert_eq!(result["status"], "ok");
        let count = result["count"].as_u64().unwrap();
        assert!(count <= 2, "Should respect limit=2, got {}", count);
    }

    #[test]
    fn test_execute_search_similar_decompiled_preview_truncated() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "inv1";
        let long_code = "x".repeat(500);
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'long_func', address: '0x1000', \
             decompiled: '{code}', investigation_id: '{inv_id}'}})",
            code = esc(&long_code),
        ))
        .unwrap();

        let args = serde_json::json!({"code": "xxx", "limit": 10});
        let result = execute_search_similar(&db, inv_id, &args).unwrap();
        if let Some(results) = result["results"].as_array() {
            if !results.is_empty() {
                let preview = results[0]["preview"].as_str().unwrap();
                // Preview should be truncated (200 chars + "..." + wrapper)
                assert!(
                    preview.len() < long_code.len(),
                    "Preview should be truncated for long decompiled code"
                );
            }
        }
    }

    // ===== TDD: no SQL strings in production code =====

    #[test]
    fn test_no_sql_in_production_code() {
        // Static analysis: verify this module contains zero SQL keywords in
        // non-test, non-comment code. We test this by checking the translate
        // function never generates SQL.
        let sql_patterns = [
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "FROM ", "INTO ",
        ];
        let test_queries = [
            "MATCH (n) RETURN DISTINCT LABELS(n), COUNT(n)",
            "MATCH (n:Function) WHERE n.name = 'main' RETURN n",
            "Show me findings",
            "Show me data sources",
            "Show me sinks",
            "Show me code",
            "MATCH (f:Function) RETURN f",
            "Show me calls",
            "Show me taint flows",
            "MATCH (a)-[r]->(b) RETURN a, r, b",
            "MATCH (x:Unknown) RETURN x",
        ];
        for query in &test_queries {
            if let Ok((cypher, _)) = translate_to_cypher(query, "inv1") {
                for sql in &sql_patterns {
                    assert!(
                        !cypher.to_uppercase().contains(&sql.to_uppercase()),
                        "translate_to_cypher('{}') produced SQL keyword '{}' in output: {}",
                        query,
                        sql,
                        cypher
                    );
                }
            }
        }
    }

    // ===== TDD: translate_to_cypher with whitespace/case variations =====

    #[test]
    fn test_translate_to_cypher_case_insensitive() {
        // lowercase
        let r1 = translate_to_cypher("show me findings", "inv1");
        assert!(r1.is_ok());
        // UPPERCASE
        let r2 = translate_to_cypher("SHOW ME FINDINGS", "inv1");
        assert!(r2.is_ok());
        // Mixed
        let r3 = translate_to_cypher("Show Me Findings", "inv1");
        assert!(r3.is_ok());
    }

    #[test]
    fn test_translate_to_cypher_leading_trailing_whitespace() {
        let result = translate_to_cypher("   Show me findings   ", "inv1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_translate_to_cypher_empty_query() {
        let result = translate_to_cypher("", "inv1");
        assert!(result.is_err(), "Empty query should be rejected");
    }

    #[test]
    fn test_translate_to_cypher_whitespace_only_query() {
        let result = translate_to_cypher("   ", "inv1");
        assert!(result.is_err(), "Whitespace-only query should be rejected");
    }

    // ===== TDD: Cypher injection via query patterns =====

    #[test]
    fn test_translate_to_cypher_injection_in_name_filter() {
        // Attempt injection through name value
        let q = "MATCH (n:Function) WHERE n.name = 'x' RETURN n UNION MATCH (m) DELETE m//' RETURN n";
        let result = translate_to_cypher(q, "inv1");
        // Should succeed but the injected payload is escaped in the Cypher output
        if let Ok((cypher, _)) = result {
            // The output must NOT contain the raw DELETE — it should be inside a CONTAINS string
            assert!(
                !cypher.contains("DELETE"),
                "Injection payload must not appear as executable Cypher: {}",
                cypher
            );
        }
    }

    #[test]
    fn test_translate_to_cypher_injection_in_investigation_id() {
        // Investigation ID validation should block this
        let result = translate_to_cypher("MATCH (f:Function) RETURN f", "inv' OR '1'='1");
        assert!(result.is_err(), "Injection in investigation_id must be rejected");
    }

    #[test]
    fn test_translate_to_cypher_injection_in_file_filter() {
        let q = "MATCH (n) WHERE n.file CONTAINS 'x' RETURN n UNION DELETE (m)//' RETURN n";
        let result = translate_to_cypher(q, "inv1");
        if let Ok((cypher, _)) = result {
            assert!(
                !cypher.contains("DELETE"),
                "Injection via file filter must not produce executable DELETE: {}",
                cypher
            );
        }
    }

    // ===== TDD: esc() with Cypher-specific dangerous patterns =====

    #[test]
    fn test_esc_cypher_comment() {
        // Cypher comments use // — should pass through (only quotes/backslashes escaped)
        let result = esc("value' // comment");
        assert_eq!(result, "value\\' // comment");
    }

    #[test]
    fn test_esc_cypher_curly_braces() {
        // Curly braces are Cypher map syntax — esc() doesn't escape them
        // (they're safe inside string literals)
        let result = esc("value {key: 'nested'}");
        assert_eq!(result, "value {key: \\'nested\\'}");
    }

    // ===== TDD: execute_cypher_read_query with null/missing values =====

    #[test]
    fn test_execute_cypher_read_query_null_property() {
        let db = GraphDb::in_memory().unwrap();
        // Create a function node missing the 'decompiled' property
        db.cypher_execute(
            "CREATE (f:Function {id: 'f1', name: 'minimal', investigation_id: 'inv1'})",
        )
        .unwrap();

        let columns = vec!["name".to_string(), "decompiled".to_string()];
        let cypher =
            "MATCH (f:Function) WHERE f.investigation_id = 'inv1' RETURN f.name, f.decompiled";
        let rows = execute_cypher_read_query(&db, cypher, &columns).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], "minimal");
        // Missing property should be null, not crash
        assert!(
            rows[0]["decompiled"].is_null() || rows[0]["decompiled"] == "",
            "Missing property should be null or empty string, got: {:?}",
            rows[0]["decompiled"]
        );
    }

    // ===== TDD: execute_create_finding with special chars =====

    #[test]
    fn test_execute_create_finding_backslash_in_description() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({
            "title": "Path traversal",
            "description": "File path: C:\\Windows\\System32\\cmd.exe",
            "severity": "high"
        });
        let result = execute_create_finding(&db, "inv1", &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify finding was stored (backslashes escaped correctly for Cypher)
        let finding_id = result["finding_id"].as_str().unwrap();
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Finding {{id: '{}'}}) RETURN f.title",
                finding_id
            ))
            .unwrap();
        assert_eq!(rows.len(), 1, "Finding must be retrievable after storage");
    }

    // ===== TDD: search_similar with Cypher injection =====

    #[test]
    fn test_execute_search_similar_injection_in_code() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "inv1";
        create_function_for_translate_test(
            &db,
            "f1",
            "safe_func",
            "0x1000",
            "void safe_func() {}",
            inv_id,
        );

        // Attempt injection via the code search parameter
        let args = serde_json::json!({
            "code": "' RETURN n UNION MATCH (m) DELETE m//",
            "limit": 10
        });
        let result = execute_search_similar(&db, inv_id, &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify the function still exists (no deletion occurred)
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{}' RETURN count(f)",
                inv_id
            ))
            .unwrap();
        let count = LadybugGraphDb::as_i64(&rows[0][0]).unwrap();
        assert_eq!(count, 1, "Injection must not delete data");
    }

    /// Helper for tests in this module that need a Function node.
    fn create_function_for_translate_test(
        db: &GraphDb,
        id: &str,
        name: &str,
        address: &str,
        decompiled: &str,
        investigation_id: &str,
    ) {
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: '{}', name: '{}', address: '{}', decompiled: '{}', \
             confidence: 0.9, investigation_id: '{}', language: 'unknown'}})",
            esc(id),
            esc(name),
            esc(address),
            esc(decompiled),
            esc(investigation_id)
        ))
        .unwrap();
    }
}
