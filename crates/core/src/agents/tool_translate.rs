//! Native Cypher query generation and read-only query execution via LadybugDB.
//!
//! All graph queries are now generated as Cypher and executed directly against
//! LadybugDB. The legacy SQL translation path has been removed.

use crate::graph::{GraphDb, LadybugGraphDb};

/// Sanitize a string for safe interpolation into a Cypher single-quoted literal.
///
/// Escapes backslashes, single quotes, newlines, carriage returns, and null bytes.
/// Normalizes fullwidth apostrophes (U+FF07) to prevent bypass attempts.
pub fn sanitize_cypher_param(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\0', "")
        .replace('\u{FF07}', "\\'") // fullwidth apostrophe normalization
}

/// Validate that an investigation_id contains only safe characters.
fn validate_investigation_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("investigation_id cannot be empty".into());
    }
    if id.len() > 128 {
        return Err("investigation_id too long".into());
    }
    if id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        Ok(())
    } else {
        Err(format!(
            "investigation_id contains invalid characters: {}",
            id.chars().take(20).collect::<String>()
        ))
    }
}

/// Translate common query patterns to native Cypher queries for LadybugDB.
///
/// Returns the Cypher query string with values already interpolated (sanitized).
/// Only predefined patterns and validated Cypher passthrough are supported.
pub fn translate_to_cypher(query: &str, investigation_id: &str) -> Result<String, String> {
    validate_investigation_id(investigation_id)?;

    let q = query.trim();
    if q.is_empty() {
        return Err("Empty query".into());
    }
    let upper = q.to_uppercase();

    // Reject SQL statements outright
    if upper.starts_with("INSERT")
        || upper.starts_with("UPDATE")
        || upper.starts_with("DELETE")
        || upper.starts_with("DROP")
        || upper.starts_with("ALTER")
        || upper.starts_with("CREATE")
    {
        return Err(format!(
            "Write operations are not allowed. Got: {}",
            q.chars().take(40).collect::<String>()
        ));
    }

    // Reject raw SQL SELECT — these must go through Cypher now
    if upper.starts_with("SELECT") {
        return Err(
            "SQL SELECT queries are no longer supported. Use Cypher MATCH queries instead.".into(),
        );
    }

    let safe_inv_id = sanitize_cypher_param(investigation_id);

    // --- Schema discovery: what node types exist ---
    if upper.contains("LABELS") || (upper.contains("DISTINCT") && upper.contains("COUNT")) {
        return Ok(format!(
            "MATCH (n) WHERE n.investigation_id = '{safe_inv_id}' \
             RETURN labels(n)[0] AS node_type, count(n) AS count \
             ORDER BY count DESC"
        ));
    }

    // --- Look up function by name ---
    if let Some(name) = extract_name_filter(q) {
        let safe_name = sanitize_cypher_param(&name);
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv_id}' \
             AND f.name CONTAINS '{safe_name}' \
             RETURN f.name, f.address, f.decompiled, f.language LIMIT 20"
        ));
    }

    // --- Filter by file ---
    if let Some(file_pattern) = extract_file_filter(q) {
        let safe_pattern = sanitize_cypher_param(&file_pattern);
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv_id}' \
             AND f.address CONTAINS '{safe_pattern}' \
             RETURN f.name, f.address, f.decompiled LIMIT 30"
        ));
    }

    // --- Query findings/vulnerabilities ---
    if upper.contains("VULNERAB") || upper.contains("FINDING") {
        return Ok(format!(
            "MATCH (f:Finding) WHERE f.investigation_id = '{safe_inv_id}' \
             RETURN f.id, f.title, f.severity, f.category, f.status, f.evidence \
             ORDER BY CASE WHEN f.severity = 'critical' THEN 0 \
             WHEN f.severity = 'high' THEN 1 WHEN f.severity = 'medium' THEN 2 \
             ELSE 3 END LIMIT 50"
        ));
    }

    // --- Query sources (not taint) ---
    if upper.contains("SOURCE") && !upper.contains("TAINT") {
        return Ok(format!(
            "MATCH (s:DataSource) WHERE s.investigation_id = '{safe_inv_id}' \
             RETURN s.id, s.name, s.source_type, s.location LIMIT 50"
        ));
    }

    // --- Query sinks (not taint) ---
    if upper.contains("SINK") && !upper.contains("TAINT") {
        return Ok(format!(
            "MATCH (k:DataSink) WHERE k.investigation_id = '{safe_inv_id}' \
             RETURN k.id, k.name, k.sink_type, k.danger_level, k.location LIMIT 50"
        ));
    }

    // --- Functions with source code ---
    if upper.contains("CODE") || upper.contains("DECOMPILE") {
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv_id}' \
             AND f.decompiled <> '' \
             RETURN f.name, f.address, f.decompiled LIMIT 30"
        ));
    }

    // --- List all functions (general FUNCTION query) ---
    if upper.contains("FUNCTION") && upper.contains("RETURN") {
        return Ok(format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv_id}' \
             RETURN f.name, f.address, f.decompiled LIMIT 50"
        ));
    }

    // --- Call graph ---
    if upper.contains("CALL") {
        return Ok(format!(
            "MATCH (caller:Function)-[:CALLS]->(callee:Function) \
             WHERE caller.investigation_id = '{safe_inv_id}' \
             RETURN caller.name, callee.name LIMIT 50"
        ));
    }

    // --- Taint flows ---
    if upper.contains("TAINT") || upper.contains("FLOW") {
        return Ok(format!(
            "MATCH (s:DataSource)-[t:TAINT_FLOW]->(k:DataSink) \
             WHERE s.investigation_id = '{safe_inv_id}' \
             RETURN s.name, k.name, t.path, t.sanitized LIMIT 50"
        ));
    }

    // --- Relationships (general graph traversal) ---
    if upper.contains("MATCH") && (upper.contains("->") || upper.contains("REL")) {
        return Ok(format!(
            "MATCH (caller:Function)-[:CALLS]->(callee:Function) \
             WHERE caller.investigation_id = '{safe_inv_id}' \
             RETURN 'CALLS' AS rel_type, caller.name AS from_name, callee.name AS to_name \
             LIMIT 50"
        ));
    }

    // --- Fallback: if it's a MATCH query, try Cypher passthrough ---
    if upper.starts_with("MATCH") || upper.starts_with("RETURN") {
        return validate_cypher_passthrough(q);
    }

    let q_preview: String = q.chars().take(80).collect();
    Err(format!(
        "Unsupported query pattern. Try: MATCH (f:Function) RETURN f, or use keywords: \
         FUNCTION, CALL, TAINT, FINDING, SOURCE, SINK, CODE. Got: {}",
        q_preview
    ))
}

/// Validate and allow a raw Cypher query to pass through (read-only only).
///
/// Multi-layer security:
/// 1. Must start with MATCH or RETURN
/// 2. Write keywords (CREATE, DELETE, SET, REMOVE, MERGE, DETACH) are rejected
/// 3. Only whitelisted node labels are allowed
/// 4. Semicolons and comments are rejected
fn validate_cypher_passthrough(cypher: &str) -> Result<String, String> {
    let upper = cypher.to_uppercase();

    // Must start with MATCH or RETURN
    if !upper.starts_with("MATCH") && !upper.starts_with("RETURN") {
        return Err("Cypher passthrough rejected: query must start with MATCH or RETURN".into());
    }

    // Reject semicolons
    if cypher.contains(';') {
        return Err("Cypher passthrough rejected: semicolons not allowed".into());
    }

    // Reject comments
    if cypher.contains("//") || cypher.contains("/*") {
        return Err("Cypher passthrough rejected: comments not allowed".into());
    }

    // Reject write keywords using token-boundary checking
    let write_keywords = ["CREATE", "DELETE", "SET", "REMOVE", "MERGE", "DETACH"];
    let tokens: Vec<String> = tokenize_cypher(&upper);
    for kw in &write_keywords {
        if tokens.iter().any(|t| t == *kw) {
            return Err(format!(
                "Cypher passthrough rejected: write keyword '{}' not allowed",
                kw
            ));
        }
    }

    // Validate node labels against whitelist
    let whitelisted_labels = [
        "FUNCTION",
        "FINDING",
        "DATASOURCE",
        "DATASINK",
        "SYMBOL",
        "STRINGLITERAL",
        "INVESTIGATION",
        "CWE",
        "ANNOTATION",
        "BASICBLOCK",
        "VULNERABILITY",
        "HYPOTHESIS",
        "AGENTACTION",
    ];

    // Extract labels from :LabelName patterns
    for (i, token) in tokens.iter().enumerate() {
        if token == ":" {
            if let Some(label) = tokens.get(i + 1) {
                // Skip relationship types (they appear inside [...])
                let prefix = tokens[..i].join(" ");
                if prefix.contains("[") && !prefix.contains("]") {
                    continue; // Inside a relationship pattern
                }
                if !whitelisted_labels.contains(&label.as_str()) {
                    return Err(format!(
                        "Cypher passthrough rejected: non-whitelisted node label '{}'. \
                         Allowed: {:?}",
                        label, whitelisted_labels
                    ));
                }
            }
        }
    }

    Ok(cypher.to_string())
}

/// Tokenize a Cypher query string by splitting on whitespace and punctuation boundaries.
/// Punctuation characters become individual tokens.
fn tokenize_cypher(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in s.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            tokens.push(ch.to_string());
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
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
        for delim in ["contains '", "contains \"", "= '", "= \""] {
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

/// Execute a read-only Cypher query via LadybugDB and return results as JSON objects.
///
/// The `columns` parameter provides the column names for mapping positional results.
/// Returns an error if any row has a different number of columns than expected.
pub fn execute_cypher_query(
    db: &GraphDb,
    cypher: &str,
    columns: &[&str],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let rows = db.cypher_query(cypher).map_err(|e| {
        anyhow::anyhow!("Cypher query execution failed: {}", e)
    })?;

    let mut results = Vec::with_capacity(rows.len());
    for row in &rows {
        if row.len() != columns.len() {
            return Err(anyhow::anyhow!(
                "Column count mismatch: expected {} columns but got {}",
                columns.len(),
                row.len()
            ));
        }
        let mut obj = serde_json::Map::new();
        for (i, col_name) in columns.iter().enumerate() {
            let val = &row[i];
            let json_val = lbug_value_to_json(val);
            obj.insert(col_name.to_string(), json_val);
        }
        results.push(serde_json::Value::Object(obj));
    }
    Ok(results)
}

/// Convert a LadybugDB Value to a serde_json::Value.
fn lbug_value_to_json(val: &lbug::Value) -> serde_json::Value {
    if let Some(s) = LadybugGraphDb::as_str(val) {
        serde_json::Value::String(s.to_string())
    } else if let Some(n) = LadybugGraphDb::as_i64(val) {
        serde_json::json!(n)
    } else if let Some(f) = LadybugGraphDb::as_f64(val) {
        serde_json::json!(f)
    } else {
        serde_json::Value::Null
    }
}

/// Create a finding in the database via Cypher CREATE.
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

    let safe_id = sanitize_cypher_param(&finding_id);
    let safe_title = sanitize_cypher_param(title);
    let safe_evidence = sanitize_cypher_param(&evidence.to_string());
    let safe_timestamp = sanitize_cypher_param(&timestamp);
    let safe_inv_id = sanitize_cypher_param(investigation_id);
    let safe_severity = sanitize_cypher_param(severity);
    let safe_category = sanitize_cypher_param(cwe_id);

    let cypher = format!(
        "CREATE (f:Finding {{id: '{safe_id}', title: '{safe_title}', \
         evidence: '{safe_evidence}', agent: 'vuln_hunter', \
         timestamp: '{safe_timestamp}', investigation_id: '{safe_inv_id}', \
         status: 'new', severity: '{safe_severity}', category: '{safe_category}'}})"
    );

    db.cypher_execute(&cypher)?;

    Ok(serde_json::json!({
        "status": "ok", "finding_id": finding_id,
        "title": title, "severity": severity,
        "investigation_id": investigation_id
    }))
}

/// Search for functions with similar names or patterns via Cypher CONTAINS.
pub(super) fn execute_search_similar(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let code = args.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let code_preview: String = code.chars().take(40).collect();
    tracing::info!("Tool search_similar: {code_preview}...");

    let safe_code = sanitize_cypher_param(code);
    let safe_inv_id = sanitize_cypher_param(investigation_id);

    let cypher = format!(
        "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv_id}' \
         AND (f.decompiled CONTAINS '{safe_code}' OR f.name CONTAINS '{safe_code}') \
         RETURN f.name, f.address, f.decompiled LIMIT {limit}"
    );

    let rows = db.cypher_query(&cypher)?;

    let results: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|row| {
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

    // ===== sanitize_cypher_param tests =====

    #[test]
    fn test_sanitize_escapes_single_quotes() {
        assert_eq!(sanitize_cypher_param("it's"), "it\\'s");
    }

    #[test]
    fn test_sanitize_escapes_backslash() {
        assert_eq!(sanitize_cypher_param("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_sanitize_strips_null_bytes() {
        assert_eq!(sanitize_cypher_param("ab\0cd"), "abcd");
    }

    #[test]
    fn test_sanitize_normalizes_fullwidth_apostrophe() {
        assert_eq!(sanitize_cypher_param("it\u{FF07}s"), "it\\'s");
    }

    #[test]
    fn test_sanitize_escapes_newlines() {
        assert_eq!(sanitize_cypher_param("line1\nline2"), "line1\\nline2");
        assert_eq!(sanitize_cypher_param("line1\rline2"), "line1\\rline2");
    }

    #[test]
    fn test_sanitize_safe_string_passes_through() {
        assert_eq!(sanitize_cypher_param("hello_world"), "hello_world");
    }

    #[test]
    fn test_sanitize_combined_dangerous_input() {
        let input = "a'\\\0\n\u{FF07}b";
        let result = sanitize_cypher_param(input);
        assert!(!result.contains('\0'));
        assert!(!result.contains('\u{FF07}'));
        // Single quotes must be escaped
        assert!(!result.contains("'") || result.contains("\\'"));
    }

    // ===== translate_to_cypher: pattern branches =====

    #[test]
    fn test_schema_discovery() {
        let result = translate_to_cypher("MATCH (n) RETURN DISTINCT labels(n), COUNT(n)", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("labels(n)"));
        assert!(cypher.contains("inv1"));
        // Must not contain SQL
        assert!(!cypher.to_uppercase().contains("SELECT"));
    }

    #[test]
    fn test_function_by_name() {
        let result =
            translate_to_cypher("MATCH (f:Function) WHERE f.name = 'strcpy' RETURN f", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CONTAINS 'strcpy'"));
        assert!(cypher.contains("inv1"));
    }

    #[test]
    fn test_file_filter() {
        let result = translate_to_cypher(
            "MATCH (f:Function) WHERE f.file CONTAINS 'main.c' RETURN f",
            "inv1",
        );
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CONTAINS 'main.c'"));
    }

    #[test]
    fn test_findings_query() {
        let result = translate_to_cypher("show me all findings", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("Finding"));
        assert!(cypher.contains("inv1"));
    }

    #[test]
    fn test_sources_query() {
        let result = translate_to_cypher("list data sources", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("DataSource"));
    }

    #[test]
    fn test_sinks_query() {
        let result = translate_to_cypher("list data sinks", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("DataSink"));
    }

    #[test]
    fn test_code_query() {
        let result = translate_to_cypher("show decompiled code", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("decompiled"));
        assert!(cypher.contains("<> ''"));
    }

    #[test]
    fn test_list_functions() {
        let result =
            translate_to_cypher("MATCH (f:Function) RETURN f.name, f.address", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("Function"));
    }

    #[test]
    fn test_call_graph() {
        let result = translate_to_cypher("show call graph", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CALLS"));
        assert!(cypher.contains("caller"));
    }

    #[test]
    fn test_taint_flows() {
        let result = translate_to_cypher("show taint flows", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("TAINT_FLOW"));
    }

    #[test]
    fn test_relationships() {
        let result = translate_to_cypher("MATCH (a)-[r]->(b) RETURN a, r, b", "inv1");
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("CALLS"));
        assert!(cypher.contains("rel_type"));
    }

    #[test]
    fn test_fallback_match() {
        let result = translate_to_cypher("MATCH (n:Function) RETURN count(n)", "inv1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_return_type_is_string() {
        let result = translate_to_cypher("show findings", "inv1").unwrap();
        // It's a String, not a tuple
        assert!(!result.is_empty());
    }

    #[test]
    fn test_case_insensitivity() {
        let r1 = translate_to_cypher("show FINDINGS", "inv1");
        let r2 = translate_to_cypher("show findings", "inv1");
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }

    // ===== Rejection tests =====

    #[test]
    fn test_rejects_sql_insert() {
        let result = translate_to_cypher("INSERT INTO functions VALUES ('x', 'y')", "inv1");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_sql_update() {
        let result = translate_to_cypher("UPDATE functions SET name = 'hacked'", "inv1");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_sql_select() {
        let result = translate_to_cypher("SELECT * FROM functions", "inv1");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_empty_query() {
        let result = translate_to_cypher("", "inv1");
        assert!(result.is_err());
    }

    // ===== investigation_id validation =====

    #[test]
    fn test_rejects_injection_in_investigation_id() {
        let result = translate_to_cypher("show findings", "inv1' OR 1=1 --");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_accepts_valid_investigation_id() {
        let result = translate_to_cypher("show findings", "inv-123_abc");
        assert!(result.is_ok());
    }

    // ===== Security: injection via name =====

    #[test]
    fn test_injection_in_function_name() {
        let result = translate_to_cypher(
            "MATCH (f:Function) WHERE f.name = 'test\\' OR 1=1 //' RETURN f",
            "inv1",
        );
        assert!(result.is_ok());
        let cypher = result.unwrap();
        // The injected quote should be escaped
        assert!(cypher.contains("\\\\'"));
    }

    #[test]
    fn test_null_byte_in_function_name() {
        let result = translate_to_cypher(
            "MATCH (f:Function) WHERE f.name = 'test\0evil' RETURN f",
            "inv1",
        );
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(!cypher.contains('\0'));
    }

    // ===== Cypher passthrough validation =====

    #[test]
    fn test_passthrough_allows_match() {
        let result = validate_cypher_passthrough(
            "MATCH (f:Function) WHERE f.name = 'main' RETURN f.name",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_passthrough_rejects_create() {
        let result =
            validate_cypher_passthrough("MATCH (n) CREATE (m:Function {name: 'evil'})");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CREATE"));
    }

    #[test]
    fn test_passthrough_rejects_delete() {
        let result = validate_cypher_passthrough("MATCH (n) DELETE n");
        assert!(result.is_err());
    }

    #[test]
    fn test_passthrough_rejects_set() {
        let result = validate_cypher_passthrough("MATCH (n) SET n.name = 'hacked'");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SET"));
    }

    #[test]
    fn test_passthrough_rejects_remove() {
        let result = validate_cypher_passthrough("MATCH (n) REMOVE n.name");
        assert!(result.is_err());
    }

    #[test]
    fn test_passthrough_rejects_merge() {
        let result = validate_cypher_passthrough("MERGE (n:Function {name: 'x'})");
        assert!(result.is_err());
    }

    #[test]
    fn test_passthrough_rejects_semicolons() {
        let result = validate_cypher_passthrough(
            "MATCH (n:Function) RETURN n; MATCH (m) DELETE m",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("semicolons"));
    }

    #[test]
    fn test_passthrough_rejects_comments() {
        let result = validate_cypher_passthrough(
            "MATCH (n:Function) // RETURN n DELETE n",
        );
        assert!(result.is_err());

        let result = validate_cypher_passthrough(
            "MATCH (n:Function) /* hidden */ RETURN n",
        );
        assert!(result.is_err());
    }

    // ===== Output validation =====

    #[test]
    fn test_no_sql_keywords_in_output() {
        let patterns = [
            "show findings",
            "list data sources",
            "show call graph",
            "show taint flows",
            "show decompiled code",
        ];
        for pattern in &patterns {
            let result = translate_to_cypher(pattern, "inv1").unwrap();
            let upper = result.to_uppercase();
            assert!(
                !upper.contains("SELECT "),
                "Output for '{}' contains SQL SELECT",
                pattern
            );
            assert!(
                !upper.contains(" FROM ") || upper.contains("FROM_NAME"),
                "Output for '{}' contains SQL FROM",
                pattern
            );
        }
    }

    #[test]
    fn test_investigation_scoping() {
        let patterns = [
            "show findings",
            "list data sources",
            "show call graph",
            "MATCH (f:Function) WHERE f.name = 'main' RETURN f",
        ];
        for pattern in &patterns {
            let result = translate_to_cypher(pattern, "my-inv-123").unwrap();
            assert!(
                result.contains("my-inv-123"),
                "Output for '{}' does not contain investigation_id",
                pattern
            );
        }
    }

    #[test]
    fn test_limit_clauses() {
        let patterns = [
            "show findings",
            "list data sources",
            "show call graph",
        ];
        for pattern in &patterns {
            let result = translate_to_cypher(pattern, "inv1").unwrap();
            assert!(
                result.contains("LIMIT"),
                "Output for '{}' does not contain LIMIT",
                pattern
            );
        }
    }

    // ===== Edge cases =====

    #[test]
    fn test_whitespace_trimming() {
        let result = translate_to_cypher("   show findings   ", "inv1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_special_chars_in_names() {
        let result = translate_to_cypher(
            "MATCH (f:Function) WHERE f.name = 'foo<bar>&baz' RETURN f",
            "inv1",
        );
        assert!(result.is_ok());
        let cypher = result.unwrap();
        assert!(cypher.contains("foo<bar>&baz"));
    }

    // ===== Integration: execute_cypher_query =====

    #[test]
    fn test_execute_cypher_query_basic() {
        let db = GraphDb::in_memory().unwrap();
        db.cypher_execute(
            "CREATE (f:Function {id: 'f1', name: 'main', address: '0x1000', investigation_id: 'inv1'})",
        )
        .unwrap();

        let results = execute_cypher_query(
            &db,
            "MATCH (f:Function {id: 'f1'}) RETURN f.name, f.address",
            &["name", "address"],
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["name"], "main");
        assert_eq!(results[0]["address"], "0x1000");
    }

    #[test]
    fn test_execute_cypher_query_empty_result() {
        let db = GraphDb::in_memory().unwrap();
        let results = execute_cypher_query(
            &db,
            "MATCH (f:Function {id: 'nonexistent'}) RETURN f.name",
            &["name"],
        )
        .unwrap();
        assert_eq!(results.len(), 0);
    }

    // ===== Integration: create_finding =====

    #[test]
    fn test_create_finding_cypher() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({
            "title": "Buffer Overflow",
            "severity": "critical",
            "description": "Stack buffer overflow in strcpy",
            "function": "vuln_func",
            "cwe_id": "CWE-120"
        });

        let result = execute_create_finding(&db, "inv1", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["title"], "Buffer Overflow");

        // Verify it was created in LadybugDB
        let rows = db
            .cypher_query("MATCH (f:Finding) WHERE f.investigation_id = 'inv1' RETURN f.title")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(LadybugGraphDb::as_str(&rows[0][0]), Some("Buffer Overflow"));
    }

    // ===== Integration: search_similar =====

    #[test]
    fn test_search_similar_cypher() {
        let db = GraphDb::in_memory().unwrap();
        db.cypher_execute(
            "CREATE (f:Function {id: 'f1', name: 'strcpy_wrapper', address: '0x1000', \
             decompiled: 'void strcpy_wrapper(char *dst, char *src) { strcpy(dst, src); }', \
             investigation_id: 'inv1'})",
        )
        .unwrap();

        let args = serde_json::json!({"code": "strcpy", "limit": 10});
        let result = execute_search_similar(&db, "inv1", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert!(result["count"].as_u64().unwrap() >= 1);
    }
}
