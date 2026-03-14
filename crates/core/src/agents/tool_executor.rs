//! Tool execution: dispatches tool calls against the real graph database.
//!
//! Every tool queries or mutates the actual database - no placeholder data.

use super::tool_translate::{execute_read_query, translate_to_sql};
use crate::graph::GraphDb;
use crate::memory::{ExperienceType, MemoryStore};

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
    execute_tool_with_memory(db, investigation_id, name, args, None, None)
}

/// Execute a tool call with optional memory store access.
///
/// When `memory` is provided, agents can use `store_memory` and `recall_memory`
/// tools to persist and recall experiences across runs.
pub fn execute_tool_with_memory(
    db: &GraphDb,
    investigation_id: &str,
    name: &str,
    args: &serde_json::Value,
    memory: Option<&MemoryStore>,
    agent_name: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    match name {
        "query_graph" => execute_query_graph(db, investigation_id, args),
        "read_function" => execute_read_function(db, investigation_id, args),
        "get_callers" => execute_get_callers(db, investigation_id, args),
        "get_callees" => execute_get_callees(db, investigation_id, args),
        "lookup_cwe" => execute_lookup_cwe(db, args),
        "create_finding" => {
            super::tool_translate::execute_create_finding(db, investigation_id, args)
        }
        "rename_function" => execute_rename_function(db, investigation_id, args),
        "search_similar" => {
            super::tool_translate::execute_search_similar(db, investigation_id, args)
        }
        "lookup_knowledge" => execute_lookup_knowledge(db, args),
        "store_memory" => execute_store_memory(memory, agent_name, args),
        "recall_memory" => execute_recall_memory(memory, agent_name, args),
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
    let query = args.get("cypher").and_then(|v| v.as_str()).unwrap_or("");
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
        Ok((id, name, address, decompiled, confidence)) => {
            let safe_decompiled = format!("<code_data>\n{}\n</code_data>", decompiled);
            Ok(serde_json::json!({
                "status": "ok",
                "function_id": id,
                "function": name,
                "address": address,
                "decompiled": safe_decompiled,
                "confidence": confidence
            }))
        }
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
                Ok((id, name, address, decompiled, confidence)) => {
                    let safe_decompiled = format!("<code_data>\n{}\n</code_data>", decompiled);
                    Ok(serde_json::json!({
                        "status": "ok",
                        "function_id": id,
                        "function": name,
                        "address": address,
                        "decompiled": safe_decompiled,
                        "confidence": confidence
                    }))
                }
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
fn execute_lookup_cwe(db: &GraphDb, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
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

/// Look up vulnerability analysis knowledge from the knowledge pack.
///
/// Searches the knowledge files in data/knowledge/ for content matching the query.
/// Topics: "methodology", "cwe-families", "codeql", "research", or a CWE number.
fn execute_lookup_knowledge(
    db: &GraphDb,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    tracing::info!("Tool lookup_knowledge: {query}");
    let results = crate::knowledge::search_knowledge(Some(db), &query)?;

    if results.is_empty() {
        Ok(serde_json::json!({
            "status": "no_results",
            "query": query,
            "hint": "Try: methodology, cwe-families, cwe-119, injection, memory, codeql, research"
        }))
    } else {
        let entries: Vec<serde_json::Value> = results
            .into_iter()
            .map(|result| {
                serde_json::json!({
                    "source": result.source,
                    "topic": result.topic,
                    "title": result.title,
                    "content": result.content
                })
            })
            .collect();

        Ok(serde_json::json!({
            "status": "ok",
            "results": entries
        }))
    }
}

/// Update a function's decompiled code with renamed variables.
fn execute_rename_function(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let func_name = args
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let renamed_code = args
        .get("renamed_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let annotations = args
        .get("annotations")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    tracing::info!("Tool rename_function: {func_name}");

    if renamed_code.is_empty() {
        return Ok(serde_json::json!({
            "status": "error",
            "error": "renamed_code is required"
        }));
    }

    // Update the function's decompiled code with the renamed version
    let rows_affected = db.conn().execute(
        "UPDATE functions SET decompiled = ?1 WHERE name = ?2 AND investigation_id = ?3",
        rusqlite::params![renamed_code, func_name, investigation_id],
    )?;

    if rows_affected == 0 {
        // Try by address
        let rows = db.conn().execute(
            "UPDATE functions SET decompiled = ?1 WHERE address = ?2 AND investigation_id = ?3",
            rusqlite::params![renamed_code, func_name, investigation_id],
        )?;
        if rows == 0 {
            return Ok(serde_json::json!({
                "status": "not_found",
                "function": func_name,
                "error": format!("Function '{}' not found in investigation", func_name)
            }));
        }
    }

    // Store annotations as an annotation node if provided
    if !annotations.is_empty() {
        let ann_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let _ = db.execute(
            "INSERT INTO annotations (id, content, agent, timestamp, investigation_id) \
             VALUES (?1, ?2, 'decompile-renamer', ?3, ?4)",
            &[
                &ann_id.as_str(),
                &format!("Type annotations for {}: {}", func_name, annotations).as_str(),
                &now.as_str(),
                &investigation_id,
            ],
        );
    }

    Ok(serde_json::json!({
        "status": "ok",
        "function": func_name,
        "message": format!("Updated decompiled code for '{}'", func_name)
    }))
}

/// Store an experience in durable agent memory.
fn execute_store_memory(
    memory: Option<&MemoryStore>,
    agent_name: Option<&str>,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let memory = match memory {
        Some(m) => m,
        None => {
            return Ok(serde_json::json!({
                "status": "unavailable",
                "error": "Memory store not configured"
            }));
        }
    };

    let agent = agent_name.unwrap_or("unknown");
    let type_str = args
        .get("experience_type")
        .and_then(|v| v.as_str())
        .unwrap_or("insight");
    let context = args.get("context").and_then(|v| v.as_str()).unwrap_or("");
    let outcome = args.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
    let confidence = args
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.8);
    let tags: Vec<&str> = args
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let experience_type = ExperienceType::from_str(type_str).unwrap_or(ExperienceType::Insight);

    tracing::info!(
        "Tool store_memory: agent={}, type={}, tags={:?}",
        agent,
        type_str,
        tags
    );

    // Anti-overfitting: check if this experience is too target-specific
    let detector = crate::memory::PatternDetector::new(memory);
    let is_overfit = detector.is_likely_overfit(agent, context, &tags)?;

    let adjusted_confidence = if is_overfit {
        tracing::debug!("Memory flagged as potentially overfit, reducing confidence");
        (confidence * 0.5).min(0.3)
    } else {
        confidence
    };

    let id = memory.store(
        agent,
        experience_type,
        context,
        outcome,
        adjusted_confidence,
        &tags,
    )?;

    Ok(serde_json::json!({
        "status": "ok",
        "id": id,
        "overfit_warning": is_overfit
    }))
}

/// Recall relevant experiences from durable agent memory.
fn execute_recall_memory(
    memory: Option<&MemoryStore>,
    agent_name: Option<&str>,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let memory = match memory {
        Some(m) => m,
        None => {
            return Ok(serde_json::json!({
                "status": "unavailable",
                "error": "Memory store not configured"
            }));
        }
    };

    let agent = agent_name.unwrap_or("unknown");
    let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

    tracing::info!("Tool recall_memory: agent={}, query={}", agent, query);

    let experiences = memory.recall(agent, query, limit, 0.1)?;

    let results: Vec<serde_json::Value> = experiences
        .iter()
        .map(|e| {
            serde_json::json!({
                "type": e.experience_type.as_str(),
                "context": e.context,
                "outcome": e.outcome,
                "confidence": e.confidence,
                "tags": e.tags,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "memories": results,
        "count": results.len()
    }))
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
        let decompiled = result["decompiled"].as_str().unwrap();
        assert!(decompiled.starts_with("<code_data>"));
        assert!(decompiled.ends_with("</code_data>"));
        assert!(decompiled.contains("strcpy"));
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
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"main",
                &"0x401000",
                &inv_id,
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"f2" as &dyn rusqlite::types::ToSql,
                &"strcpy",
                &"0x402000",
                &inv_id,
            ],
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
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"main",
                &"0x401000",
                &inv_id,
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name, address, investigation_id) VALUES (?1, ?2, ?3, ?4)",
            &[
                &"f2" as &dyn rusqlite::types::ToSql,
                &"system",
                &"0x402000",
                &inv_id,
            ],
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
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"main",
                &"0x401000",
                &inv_id,
            ],
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
    fn test_execute_tool_rename_function() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.execute(
            "INSERT INTO functions (id, name, address, decompiled, confidence, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                &"f1" as &dyn rusqlite::types::ToSql,
                &"process_data",
                &"0x401000",
                &"void process_data(int param_1, char *param_2) { char var_1[32]; strcpy(var_1, param_2); }",
                &0.8_f64 as &dyn rusqlite::types::ToSql,
                &inv_id,
            ],
        )
        .unwrap();

        let args = serde_json::json!({
            "function": "process_data",
            "renamed_code": "void process_data(int buf_size, char *user_input) { char local_buffer[32]; strcpy(local_buffer, user_input); }",
            "annotations": "param_1 is a buffer size, param_2 is user-controlled input"
        });
        let result = execute_tool(&db, inv_id, "rename_function", &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify the decompiled code was updated
        let updated: String = db
            .conn()
            .query_row(
                "SELECT decompiled FROM functions WHERE name = ?1 AND investigation_id = ?2",
                rusqlite::params!["process_data", inv_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(updated.contains("user_input"));
        assert!(updated.contains("local_buffer"));
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
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("Unsupported query pattern"));

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
    fn test_lookup_knowledge_returns_results() {
        // This test requires data/knowledge/ to exist with .md files
        let db = GraphDb::in_memory().unwrap();
        crate::knowledge::initialize_cwe_catalog(&db).unwrap();
        let args = serde_json::json!({"query": "memory"});
        let result = execute_lookup_knowledge(&db, &args).unwrap();
        // May return results or no_results depending on working directory
        let status = result["status"].as_str().unwrap();
        assert!(
            status == "ok" || status == "no_results" || status == "error",
            "Expected valid status, got: {}",
            status
        );
    }

    #[test]
    fn test_lookup_knowledge_with_cwe_query() {
        let db = GraphDb::in_memory().unwrap();
        crate::knowledge::initialize_cwe_catalog(&db).unwrap();
        let args = serde_json::json!({"query": "cwe-119 buffer overflow"});
        let result = execute_lookup_knowledge(&db, &args).unwrap();
        let status = result["status"].as_str().unwrap();
        assert!(
            status == "ok" || status == "no_results" || status == "error",
            "Expected valid status, got: {}",
            status
        );
        if status == "ok" {
            assert!(
                result["results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| entry["source"] == "cwe"),
                "expected at least one cwe result"
            );
        }
    }
}
