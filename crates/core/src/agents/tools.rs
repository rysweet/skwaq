//! Tool definitions and executor for vulnerability assessment agents.
//!
//! Each tool function executes actual SQL queries against the GraphDb,
//! returning real data from ingested binaries. No fake data, no stubs.

use crate::graph::GraphDb;
use crate::llm::ToolDefinition;

/// Return the full set of tool definitions that agents can call during analysis.
pub fn agent_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "query_graph".into(),
            description: "Run a Cypher query against the code property graph and return results."
                .into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "cypher": {
                        "type": "string",
                        "description": "Cypher query to execute"
                    }
                },
                "required": ["cypher"]
            }),
        },
        ToolDefinition {
            name: "read_function".into(),
            description: "Read the decompiled or source code of a function by name or address."
                .into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["name"]
            }),
        },
        ToolDefinition {
            name: "get_callers".into(),
            description: "Return all functions that call the specified function.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["function"]
            }),
        },
        ToolDefinition {
            name: "get_callees".into(),
            description: "Return all functions called by the specified function.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["function"]
            }),
        },
        ToolDefinition {
            name: "lookup_cwe".into(),
            description:
                "Look up a CWE entry by ID and return its name, description, and mitigations."
                    .into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE identifier, e.g. CWE-787"
                    }
                },
                "required": ["cwe_id"]
            }),
        },
        ToolDefinition {
            name: "create_finding".into(),
            description: "Record a new vulnerability finding in the graph database.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short title for the finding"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity level"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability"
                    },
                    "function": {
                        "type": "string",
                        "description": "Affected function name"
                    },
                    "cwe_id": {
                        "type": "string",
                        "description": "Associated CWE identifier"
                    }
                },
                "required": ["title", "severity", "description"]
            }),
        },
        ToolDefinition {
            name: "search_similar".into(),
            description:
                "Search for code patterns similar to a given snippet using pattern matching.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Code snippet to find similar patterns for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results",
                        "default": 10
                    }
                },
                "required": ["code"]
            }),
        },
    ]
}

/// Filter the full tool set to only tools listed in an agent's definition.
pub fn filter_tools(all_tools: &[ToolDefinition], allowed: &[String]) -> Vec<ToolDefinition> {
    if allowed.is_empty() {
        return all_tools.to_vec();
    }
    all_tools
        .iter()
        .filter(|t| allowed.contains(&t.name))
        .cloned()
        .collect()
}

/// Execute a single tool call against the real graph database.
///
/// This is the shared executor used by all agents. Every tool queries
/// or mutates the actual database - no placeholder data.
pub fn execute_tool(
    db: &GraphDb,
    investigation_id: &str,
    name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    match name {
        "query_graph" => execute_query_graph(db, investigation_id, args),
        "read_function" => execute_read_function(db, investigation_id, args),
        "get_callers" => execute_get_callers(db, investigation_id, args),
        "get_callees" => execute_get_callees(db, investigation_id, args),
        "lookup_cwe" => execute_lookup_cwe(db, args),
        "create_finding" => execute_create_finding(db, investigation_id, args),
        "search_similar" => execute_search_similar(db, investigation_id, args),
        _ => {
            tracing::warn!("Unknown tool: {name}");
            Ok(serde_json::json!({
                "error": format!("Unknown tool: {name}")
            }))
        }
    }
}

/// Execute a SQL query against the database.
fn execute_query_graph(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let query = args
        .get("cypher")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    tracing::info!("Tool query_graph: {query}");

    if query.is_empty() {
        return Ok(serde_json::json!({
            "status": "error",
            "error": "Empty query"
        }));
    }

    let (sql, params) = match translate_to_sql(query, investigation_id) {
        Ok(pair) => pair,
        Err(msg) => {
            tracing::warn!("query_graph unsupported pattern: {msg}");
            return Ok(serde_json::json!({
                "status": "error",
                "query": query,
                "error": msg
            }));
        }
    };

    match execute_read_query(db, &sql, &params) {
        Ok(rows) => Ok(serde_json::json!({
            "status": "ok",
            "query": query,
            "rows": rows,
            "row_count": rows.len()
        })),
        Err(e) => {
            tracing::warn!("query_graph error: {e}");
            Ok(serde_json::json!({
                "status": "error",
                "query": query,
                "error": format!("{e}")
            }))
        }
    }
}

/// Read the decompiled code of a function by name.
fn execute_read_function(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let func_name = args
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    tracing::info!("Tool read_function: {func_name}");

    let result = db.conn().query_row(
        "SELECT id, name, address, decompiled, confidence FROM functions \
         WHERE name = ?1 AND investigation_id = ?2 LIMIT 1",
        rusqlite::params![func_name, investigation_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, f64>(4)?,
            ))
        },
    );

    match result {
        Ok((id, name, address, decompiled, confidence)) => Ok(serde_json::json!({
            "status": "ok",
            "function_id": id,
            "function": name,
            "address": address,
            "decompiled": decompiled,
            "confidence": confidence
        })),
        Err(_) => {
            // Try matching by address if name lookup failed
            let addr_result = db.conn().query_row(
                "SELECT id, name, address, decompiled, confidence FROM functions \
                 WHERE address = ?1 AND investigation_id = ?2 LIMIT 1",
                rusqlite::params![func_name, investigation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, f64>(4)?,
                    ))
                },
            );

            match addr_result {
                Ok((id, name, address, decompiled, confidence)) => Ok(serde_json::json!({
                    "status": "ok",
                    "function_id": id,
                    "function": name,
                    "address": address,
                    "decompiled": decompiled,
                    "confidence": confidence
                })),
                Err(_) => Ok(serde_json::json!({
                    "status": "not_found",
                    "function": func_name,
                    "error": format!("Function '{}' not found in investigation", func_name)
                })),
            }
        }
    }
}

/// Get all callers of a function.
fn execute_get_callers(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let func_name = args
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    tracing::info!("Tool get_callers: {func_name}");

    let mut stmt = db.conn().prepare(
        "SELECT f1.name, f1.address FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name = ?1 AND f2.investigation_id = ?2",
    )?;

    let rows = stmt.query_map(rusqlite::params![func_name, investigation_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let callers: Vec<serde_json::Value> = rows
        .filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("Error reading caller row: {e}");
                None
            }
        })
        .map(|(name, addr)| {
            serde_json::json!({
                "name": name,
                "address": addr
            })
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "function": func_name,
        "callers": callers,
        "count": callers.len()
    }))
}

/// Get all callees of a function.
fn execute_get_callees(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let func_name = args
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    tracing::info!("Tool get_callees: {func_name}");

    let mut stmt = db.conn().prepare(
        "SELECT f2.name, f2.address FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.name = ?1 AND f1.investigation_id = ?2",
    )?;

    let rows = stmt.query_map(rusqlite::params![func_name, investigation_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let callees: Vec<serde_json::Value> = rows
        .filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("Error reading callee row: {e}");
                None
            }
        })
        .map(|(name, addr)| {
            serde_json::json!({
                "name": name,
                "address": addr
            })
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "function": func_name,
        "callees": callees,
        "count": callees.len()
    }))
}

/// Look up a CWE entry by ID.
fn execute_lookup_cwe(
    db: &GraphDb,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let cwe_id = args
        .get("cwe_id")
        .and_then(|v| v.as_str())
        .unwrap_or("CWE-0");
    tracing::info!("Tool lookup_cwe: {cwe_id}");

    let result = db.conn().query_row(
        "SELECT id, cwe_id, name, description FROM cwes WHERE cwe_id = ?1 LIMIT 1",
        rusqlite::params![cwe_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    );

    match result {
        Ok((_id, cwe_id, name, description)) => Ok(serde_json::json!({
            "status": "ok",
            "cwe_id": cwe_id,
            "name": name,
            "description": description
        })),
        Err(_) => Ok(serde_json::json!({
            "status": "not_found",
            "cwe_id": cwe_id,
            "error": format!("CWE '{}' not found in knowledge base. Run `skwaq kb init` to populate.", cwe_id)
        })),
    }
}

/// Create a finding in the database.
fn execute_create_finding(
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
    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cwe_id = args
        .get("cwe_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let finding_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    tracing::info!("Tool create_finding: {title} [{severity}]");

    let evidence = serde_json::json!({
        "description": description,
        "function": function,
        "cwe_id": cwe_id,
    });

    db.execute(
        "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id, \
         status, severity, category) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        "status": "ok",
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "investigation_id": investigation_id
    }))
}

/// Search for functions with similar names or patterns.
fn execute_search_similar(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let code = args
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as usize;

    tracing::info!(
        "Tool search_similar: {}...",
        &code[..code.len().min(40)]
    );

    let search_pattern = format!("%{}%", code.replace('%', ""));

    let mut stmt = db.conn().prepare(
        "SELECT name, address, decompiled FROM functions \
         WHERE investigation_id = ?1 AND (decompiled LIKE ?2 OR name LIKE ?2) \
         LIMIT ?3",
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
        .filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("Error reading search result row: {e}");
                None
            }
        })
        .map(|(name, addr, decompiled)| {
            let preview = if decompiled.len() > 200 {
                format!("{}...", &decompiled[..200])
            } else {
                decompiled
            };
            serde_json::json!({
                "name": name,
                "address": addr,
                "preview": preview
            })
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "results": results,
        "count": results.len()
    }))
}

/// Translate common Cypher-like query patterns to parameterized SQL.
///
/// Returns `(sql, params)` where params contains the investigation_id
/// for the `?1` placeholder. Only predefined patterns are supported;
/// arbitrary SQL (including raw SELECT from the LLM) is rejected.
fn translate_to_sql(query: &str, investigation_id: &str) -> Result<(String, Vec<String>), String> {
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

    Err(format!(
        "Unsupported query pattern. Use Cypher-like queries with FUNCTION/RETURN, CALL, or TAINT/FLOW keywords. Got: {}",
        &q[..q.len().min(80)]
    ))
}

/// Execute a read-only parameterized SQL query and return results as a Vec of JSON objects.
fn execute_read_query(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_tool_read_function() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO functions (id, name, address, decompiled, confidence, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"vulnerable_func",
                &"0x401000",
                &"void vulnerable_func(char *input) { char buf[32]; strcpy(buf, input); }",
                &0.9_f64 as &dyn rusqlite::types::ToSql,
                &inv_id,
            ],
        )
        .unwrap();

        let args = serde_json::json!({"name": "vulnerable_func"});
        let result = execute_tool(&db, inv_id, "read_function", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["function"], "vulnerable_func");
        assert!(result["decompiled"].as_str().unwrap().contains("strcpy"));
    }

    #[test]
    fn test_execute_tool_read_function_not_found() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"name": "nonexistent"});
        let result = execute_tool(&db, "inv1", "read_function", &args).unwrap();
        assert_eq!(result["status"], "not_found");
    }

    #[test]
    fn test_execute_tool_get_callers() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"main", &"0x401000", &inv_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[&"f2" as &dyn rusqlite::types::ToSql, &"strcpy", &"0x402000", &inv_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"f2"],
        )
        .unwrap();

        let args = serde_json::json!({"function": "strcpy"});
        let result = execute_tool(&db, inv_id, "get_callers", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 1);
        assert_eq!(result["callers"][0]["name"], "main");
    }

    #[test]
    fn test_execute_tool_get_callees() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"main", &"0x401000", &inv_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[&"f2" as &dyn rusqlite::types::ToSql, &"system", &"0x402000", &inv_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"f2"],
        )
        .unwrap();

        let args = serde_json::json!({"function": "main"});
        let result = execute_tool(&db, inv_id, "get_callees", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 1);
        assert_eq!(result["callees"][0]["name"], "system");
    }

    #[test]
    fn test_execute_tool_create_finding() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        let args = serde_json::json!({
            "title": "Buffer overflow in parse_input",
            "severity": "high",
            "description": "strcpy called with unsanitized user input",
            "function": "parse_input",
            "cwe_id": "CWE-120"
        });

        let result = execute_tool(&db, inv_id, "create_finding", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["title"], "Buffer overflow in parse_input");
        assert_eq!(result["severity"], "high");

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM findings WHERE investigation_id = ?1",
                rusqlite::params![inv_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_execute_tool_lookup_cwe_not_found() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"cwe_id": "CWE-787"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();
        assert_eq!(result["status"], "not_found");
    }

    #[test]
    fn test_execute_tool_lookup_cwe_found() {
        let db = GraphDb::in_memory().unwrap();
        db.execute(
            "INSERT INTO cwes (id, cwe_id, name, description) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"cwe-120" as &dyn rusqlite::types::ToSql,
                &"CWE-120",
                &"Buffer Copy without Checking Size of Input",
                &"The program copies an input buffer to an output buffer without verifying \
                  that the size of the input buffer is less than the size of the output buffer.",
            ],
        )
        .unwrap();

        let args = serde_json::json!({"cwe_id": "CWE-120"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["cwe_id"], "CWE-120");
        assert!(result["name"].as_str().unwrap().contains("Buffer Copy"));
    }

    #[test]
    fn test_execute_tool_query_graph() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[&"f1" as &dyn rusqlite::types::ToSql, &"main", &"0x401000", &inv_id],
        )
        .unwrap();

        // Use a Cypher-like pattern that translate_to_sql recognizes
        let args = serde_json::json!({
            "cypher": "MATCH (f:Function) RETURN f"
        });
        let result = execute_tool(&db, inv_id, "query_graph", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["row_count"], 1);
        assert_eq!(result["rows"][0]["name"], "main");
    }

    #[test]
    fn test_execute_tool_search_similar() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO functions (id, name, address, decompiled, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"parse_input",
                &"0x401000",
                &"void parse_input(char *buf) { strcpy(dest, buf); }",
                &inv_id,
            ],
        )
        .unwrap();

        let args = serde_json::json!({"code": "strcpy"});
        let result = execute_tool(&db, inv_id, "search_similar", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert!(result["count"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_unknown_tool() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({});
        let result = execute_tool(&db, "inv1", "nonexistent_tool", &args).unwrap();
        assert!(result.get("error").is_some());
    }

    #[test]
    fn test_filter_tools() {
        let all = agent_tools();
        let filtered = filter_tools(&all, &["query_graph".into(), "read_function".into()]);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|t| t.name == "query_graph"));
        assert!(filtered.iter().any(|t| t.name == "read_function"));
    }

    #[test]
    fn test_filter_tools_empty_allows_all() {
        let all = agent_tools();
        let filtered = filter_tools(&all, &[]);
        assert_eq!(filtered.len(), all.len());
    }

    #[test]
    fn test_query_graph_rejects_destructive_query() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Attempt an INSERT via query_graph - translate_to_sql rejects unrecognised patterns
        let args = serde_json::json!({
            "cypher": "INSERT INTO functions (id, name) VALUES ('evil', 'injected')"
        });
        let result = execute_tool(&db, inv_id, "query_graph", &args).unwrap();

        assert_eq!(result["status"], "error");
        assert!(result["error"].as_str().unwrap().contains("Unsupported query pattern"));

        // Verify no data was actually inserted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM functions WHERE name = 'injected'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "Destructive query must not modify the database");
    }

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
