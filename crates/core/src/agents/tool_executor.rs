//! Tool execution: dispatches tool calls against the real graph database.
//!
//! Every tool queries or mutates the actual database - no placeholder data.
//! All graph queries use native Cypher via LadybugDB. SQLite is only used
//! for the CWE reference table (lookup_cwe).

use super::tool_translate::{esc, execute_cypher_read_query, translate_to_cypher};
use crate::graph::ladybug_db::LadybugGraphDb;
use crate::graph::GraphDb;
use crate::knowledge::search::search_knowledge_with_dir;
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
        "get_callers" => execute_get_call_neighbors(db, investigation_id, args, true),
        "get_callees" => execute_get_call_neighbors(db, investigation_id, args, false),
        "lookup_cwe" => execute_lookup_cwe(db, args),
        "create_finding" => {
            super::tool_translate::execute_create_finding(db, investigation_id, args, agent_name)
        }
        "rename_function" => execute_rename_function(db, investigation_id, args),
        "search_similar" => {
            super::tool_translate::execute_search_similar(db, investigation_id, args)
        }
        "lookup_knowledge" => execute_lookup_knowledge(db, args),
        "store_memory" => execute_store_memory(memory, agent_name, args),
        "recall_memory" => execute_recall_memory(memory, agent_name, args),
        "get_taint_paths" => execute_get_taint_paths(db, investigation_id, args),
        "get_cross_file_calls" => execute_get_cross_file_calls(db, investigation_id, args),
        "get_data_sources" => execute_get_data_sources(db, investigation_id, args),
        "get_imports" => execute_get_imports(db, investigation_id, args),
        _ => {
            tracing::warn!("Unknown tool: {name}");
            Ok(serde_json::json!({
                "error": format!("Unknown tool: {name}")
            }))
        }
    }
}

/// Execute a graph query via native Cypher.
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

    // Step 1: Try native Cypher via LadybugDB — no translation needed
    {
        match db.cypher_query(query) {
            Ok(rows) if !rows.is_empty() => {
                let json_rows: Vec<Vec<String>> = rows
                    .iter()
                    .map(|row| row.iter().map(|v| format!("{v}")).collect())
                    .collect();
                return Ok(serde_json::json!({
                    "status": "ok",
                    "query": query,
                    "backend": "ladybugdb",
                    "rows": json_rows,
                    "row_count": json_rows.len()
                }));
            }
            Ok(_) => {
                // Empty result — fall through to translated Cypher
            }
            Err(e) => {
                tracing::debug!("LadybugDB raw query failed, trying translation: {e}");
            }
        }
    }

    // Step 2: Translate to Cypher and execute
    match translate_to_cypher(query, investigation_id) {
        Ok((cypher, columns)) => match execute_cypher_read_query(db, &cypher, &columns) {
            Ok(rows) if !rows.is_empty() => Ok(serde_json::json!({
                "status": "ok",
                "query": query,
                "backend": "ladybugdb-translated",
                "rows": rows,
                "row_count": rows.len()
            })),
            Ok(_) => Ok(serde_json::json!({
                "status": "ok",
                "query": query,
                "rows": [],
                "row_count": 0
            })),
            Err(e) => {
                tracing::warn!("Translated Cypher failed: {e}");
                Ok(serde_json::json!({
                    "status": "error",
                    "query": query,
                    "error": format!("{e}")
                }))
            }
        },
        Err(msg) => {
            tracing::warn!("query_graph unsupported pattern: {msg}");
            Ok(serde_json::json!({
                "status": "error",
                "query": query,
                "error": msg
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

    let inv = esc(investigation_id);
    let name_esc = esc(func_name);

    // Try Cypher first (when LadybugDB is available)
    if db.has_ladybug() {
        let cypher = format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
             AND f.name = '{name_esc}' \
             RETURN f.id, f.name, f.address, f.decompiled, f.confidence LIMIT 1"
        );

        if let Some(val) = read_function_from_rows(db.cypher_query(&cypher).ok()) {
            return Ok(val);
        }

        // Try by address
        let cypher = format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' \
             AND f.address = '{name_esc}' \
             RETURN f.id, f.name, f.address, f.decompiled, f.confidence LIMIT 1"
        );

        if let Some(val) = read_function_from_rows(db.cypher_query(&cypher).ok()) {
            return Ok(val);
        }
    }

    // SQL fallback — always works (SQLite-only mode or LadybugDB miss)
    if let Ok(row) = db.conn().query_row(
        "SELECT id, name, address, decompiled, confidence FROM functions \
         WHERE investigation_id = ?1 AND (name = ?2 OR address = ?2) LIMIT 1",
        rusqlite::params![investigation_id, func_name],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, f64>(4)?,
            ))
        },
    ) {
        let safe_decompiled = format!("<code_data>\n{}\n</code_data>", row.3);
        return Ok(serde_json::json!({
            "status": "ok",
            "function_id": row.0,
            "function": row.1,
            "address": row.2,
            "decompiled": safe_decompiled,
            "confidence": row.4
        }));
    }

    Ok(serde_json::json!({
        "status": "not_found",
        "function": func_name,
        "error": format!("Function '{}' not found in investigation", func_name)
    }))
}

/// Extract a function result from Cypher query rows.
fn read_function_from_rows(rows: Option<Vec<Vec<lbug::Value>>>) -> Option<serde_json::Value> {
    let rows = rows?;
    let row = rows.first()?;
    if row.len() < 5 {
        return None;
    }
    let id = LadybugGraphDb::as_str(&row[0]).unwrap_or("").to_string();
    let name = LadybugGraphDb::as_str(&row[1]).unwrap_or("").to_string();
    let address = LadybugGraphDb::as_str(&row[2]).unwrap_or("").to_string();
    let decompiled = LadybugGraphDb::as_str(&row[3]).unwrap_or("").to_string();
    let confidence = LadybugGraphDb::as_f64(&row[4]).unwrap_or(0.0);
    let safe_decompiled = format!("<code_data>\n{}\n</code_data>", decompiled);
    Some(serde_json::json!({
        "status": "ok",
        "function_id": id,
        "function": name,
        "address": address,
        "decompiled": safe_decompiled,
        "confidence": confidence
    }))
}

/// Get callers or callees of a function.
///
/// When `callers=true`, returns functions that call the target.
/// When `callers=false`, returns functions the target calls.
fn execute_get_call_neighbors(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
    callers: bool,
) -> anyhow::Result<serde_json::Value> {
    let func_name = args
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let direction = if callers { "callers" } else { "callees" };
    tracing::info!("Tool get_{direction}: {func_name}");

    let (match_side, return_side) = if callers {
        ("callee", "caller")
    } else {
        ("caller", "callee")
    };

    let results: Vec<serde_json::Value> = if db.has_ladybug() {
        let cypher = format!(
            "MATCH (caller:Function)-[:CALLS]->(callee:Function) \
             WHERE {match_side}.name = '{}' AND {match_side}.investigation_id = '{}' \
             RETURN {return_side}.name, {return_side}.address LIMIT 50",
            esc(func_name),
            esc(investigation_id)
        );

        match db.cypher_query(&cypher) {
            Ok(rows) => rows
                .iter()
                .filter_map(|r| {
                    let name = LadybugGraphDb::as_str(&r[0])?.to_string();
                    let addr = LadybugGraphDb::as_str(&r[1]).unwrap_or("").to_string();
                    Some(serde_json::json!({"name": name, "address": addr}))
                })
                .collect(),
            Err(e) => {
                tracing::debug!("get_{direction} query failed: {e}");
                Vec::new()
            }
        }
    } else {
        // SQL fallback for SQLite-only mode
        let sql = if callers {
            "SELECT f1.name, f1.address FROM calls c \
             JOIN functions f2 ON c.callee_id = f2.id \
             JOIN functions f1 ON c.caller_id = f1.id \
             WHERE f2.name = ?1 AND f2.investigation_id = ?2 LIMIT 50"
        } else {
            "SELECT f2.name, f2.address FROM calls c \
             JOIN functions f1 ON c.caller_id = f1.id \
             JOIN functions f2 ON c.callee_id = f2.id \
             WHERE f1.name = ?1 AND f1.investigation_id = ?2 LIMIT 50"
        };
        let mut stmt = db
            .conn()
            .prepare(sql)
            .unwrap_or_else(|_| db.conn().prepare("SELECT '' WHERE 0").unwrap());
        stmt.query_map(rusqlite::params![func_name, investigation_id], |row| {
            Ok(serde_json::json!({
                "name": row.get::<_, String>(0)?,
                "address": row.get::<_, String>(1)?
            }))
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    };

    Ok(serde_json::json!({
        "status": "ok",
        "function": func_name,
        direction: results,
        "count": results.len()
    }))
}

/// Look up a CWE entry by ID.
///
/// CWEs are stored in SQLite (static reference table, not graph data).
fn execute_lookup_cwe(db: &GraphDb, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let cwe_id = args
        .get("cwe_id")
        .and_then(|v| v.as_str())
        .unwrap_or("CWE-0");
    tracing::info!("Tool lookup_cwe: {cwe_id}");

    let enriched = std::env::var("SKWAQ_CWE_KG_ENRICHED")
        .map(|v| v != "0")
        .unwrap_or(true);

    let result = db.conn().query_row(
        "SELECT id, cwe_id, name, description, parent_cwe, semantic_class, \
         danger_categories, detection_signals, skwaq_tools, fn_insight \
         FROM cwes WHERE cwe_id = ?1 LIMIT 1",
        rusqlite::params![cwe_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4).unwrap_or_default(),
                row.get::<_, String>(5).unwrap_or_default(),
                row.get::<_, String>(6).unwrap_or_default(),
                row.get::<_, String>(7).unwrap_or_default(),
                row.get::<_, String>(8).unwrap_or_default(),
                row.get::<_, String>(9).unwrap_or_default(),
            ))
        },
    );

    match result {
        Ok((
            _id,
            cwe_id,
            name,
            description,
            parent_cwe,
            semantic_class,
            danger_categories,
            detection_signals,
            skwaq_tools,
            fn_insight,
        )) => {
            if !enriched {
                // Legacy response for A/B testing
                return Ok(serde_json::json!({
                    "status": "ok",
                    "cwe_id": cwe_id,
                    "name": name,
                    "description": description
                }));
            }

            // Query children (CWEs that have this CWE as parent)
            let children = lookup_cwe_children(db, &cwe_id);

            let signals: Vec<&str> = if detection_signals.is_empty() {
                Vec::new()
            } else {
                detection_signals.split(',').collect()
            };
            let tools: Vec<&str> = if skwaq_tools.is_empty() {
                Vec::new()
            } else {
                skwaq_tools.split(',').collect()
            };
            let categories: Vec<&str> = if danger_categories.is_empty() {
                Vec::new()
            } else {
                danger_categories.split(',').collect()
            };

            let mut resp = serde_json::json!({
                "status": "ok",
                "cwe_id": cwe_id,
                "name": name,
                "description": description,
                "semantic_class": semantic_class,
                "danger_categories": categories,
                "detection_signals": signals,
                "recommended_tools": tools,
                "children": children,
            });

            if !parent_cwe.is_empty() {
                resp["parent_cwe"] = serde_json::json!(parent_cwe);
            }
            if !fn_insight.is_empty() {
                resp["fn_insight"] = serde_json::json!(fn_insight);
            }

            Ok(resp)
        }
        Err(_) => Ok(serde_json::json!({
            "status": "not_found",
            "cwe_id": cwe_id,
            "error": format!("CWE '{}' not found in knowledge base. Run `skwaq kb init` to populate.", cwe_id)
        })),
    }
}

/// Query the cwes table for children of a given CWE (entries whose parent_cwe matches).
fn lookup_cwe_children(db: &GraphDb, parent_cwe_id: &str) -> Vec<serde_json::Value> {
    let mut stmt = match db
        .conn()
        .prepare("SELECT cwe_id, name FROM cwes WHERE parent_cwe = ?1 ORDER BY cwe_id")
    {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = match stmt.query_map(rusqlite::params![parent_cwe_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    rows.filter_map(|r| r.ok())
        .map(|(id, name)| serde_json::json!({"cwe_id": id, "name": name}))
        .collect()
}

/// Look up vulnerability analysis knowledge from the knowledge pack.
///
/// Searches the knowledge files in data/knowledge/ for content matching the query.
/// Topics: "methodology", "cwe-families", "codeql", "research", or a CWE number.
fn execute_lookup_knowledge(
    db: &GraphDb,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let knowledge_dir = crate::knowledge::find_knowledge_dir().ok_or_else(|| {
        anyhow::anyhow!(
            "Knowledge pack directory not found. Expected one of: data/knowledge, ../data/knowledge, or crates/core/../../data/knowledge."
        )
    })?;
    execute_lookup_knowledge_with_dir(db, args, &knowledge_dir)
}

fn execute_lookup_knowledge_with_dir(
    db: &GraphDb,
    args: &serde_json::Value,
    knowledge_dir: &std::path::Path,
) -> anyhow::Result<serde_json::Value> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    tracing::info!("Tool lookup_knowledge: {query}");
    let results = match search_knowledge_with_dir(Some(db), &query, knowledge_dir) {
        Ok(results) => results,
        Err(error) => {
            return Ok(serde_json::json!({
                "status": "error",
                "query": query,
                "error": error.to_string(),
            }));
        }
    };

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

    tracing::info!("Tool rename_function: {func_name}");

    if renamed_code.is_empty() {
        return Ok(serde_json::json!({
            "status": "error",
            "error": "renamed_code is required"
        }));
    }

    let inv = esc(investigation_id);
    let name_esc = esc(func_name);
    let code = esc(renamed_code);

    if db.has_ladybug() {
        // Try by name — check existence then update via Cypher
        let check = format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' AND f.name = '{name_esc}' \
             RETURN f.name LIMIT 1"
        );
        if db
            .cypher_query(&check)
            .map(|r| !r.is_empty())
            .unwrap_or(false)
        {
            let update = format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{inv}' AND f.name = '{name_esc}' \
                 SET f.decompiled = '{code}'"
            );
            db.cypher_execute(&update)?;
            return Ok(serde_json::json!({
                "status": "ok",
                "function": func_name,
                "message": format!("Updated decompiled code for '{}'", func_name)
            }));
        }

        // Try by address
        let check = format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' AND f.address = '{name_esc}' \
             RETURN f.name LIMIT 1"
        );
        if db
            .cypher_query(&check)
            .map(|r| !r.is_empty())
            .unwrap_or(false)
        {
            let update = format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{inv}' AND f.address = '{name_esc}' \
                 SET f.decompiled = '{code}'"
            );
            db.cypher_execute(&update)?;
            return Ok(serde_json::json!({
                "status": "ok",
                "function": func_name,
                "message": format!("Updated decompiled code for '{}'", func_name)
            }));
        }
    }

    // SQL fallback — works in SQLite-only mode
    let updated = db
        .execute(
            "UPDATE functions SET decompiled = ?1 \
             WHERE investigation_id = ?2 AND (name = ?3 OR address = ?3)",
            &[
                &renamed_code as &dyn rusqlite::types::ToSql,
                &investigation_id,
                &func_name,
            ],
        )
        .unwrap_or(0);

    if updated > 0 {
        return Ok(serde_json::json!({
            "status": "ok",
            "function": func_name,
            "message": format!("Updated decompiled code for '{}'", func_name)
        }));
    }

    Ok(serde_json::json!({
        "status": "not_found",
        "function": func_name,
        "error": format!("Function '{}' not found in investigation", func_name)
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

/// Get taint flow paths involving a specific function.
fn execute_get_taint_paths(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
    let function: String = function.chars().take(256).collect();
    tracing::info!("Tool get_taint_paths: {function}");

    let inv = esc(investigation_id);
    let func_esc = esc(&function);

    // Get the function's file prefix to match taint sources/sinks in the same file
    let file_prefix: Option<String> = db
        .cypher_query(&format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' AND f.name = '{func_esc}' \
             RETURN f.address LIMIT 1"
        ))
        .ok()
        .and_then(|rows| {
            rows.first().and_then(|row| {
                LadybugGraphDb::as_str(&row[0]).and_then(|addr| {
                    addr.split(':')
                        .next()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                })
            })
        });

    let cypher = if let Some(ref prefix) = file_prefix {
        let pfx = esc(prefix);
        format!(
            "MATCH (s:DataSource)-[t:TAINT_FLOW]->(k:DataSink) \
             WHERE s.investigation_id = '{inv}' \
             AND (s.location STARTS WITH '{pfx}' OR k.location STARTS WITH '{pfx}') \
             RETURN s.name, k.name, t.path LIMIT 50"
        )
    } else {
        format!(
            "MATCH (s:DataSource)-[t:TAINT_FLOW]->(k:DataSink) \
             WHERE s.investigation_id = '{inv}' \
             RETURN s.name, k.name, t.path LIMIT 50"
        )
    };

    let paths: Vec<serde_json::Value> = match db.cypher_query(&cypher) {
        Ok(rows) => rows
            .iter()
            .filter_map(|r| {
                let source = LadybugGraphDb::as_str(&r[0])?.to_string();
                let sink = LadybugGraphDb::as_str(&r[1]).unwrap_or("").to_string();
                let path = LadybugGraphDb::as_str(&r[2]).unwrap_or("").to_string();
                Some(serde_json::json!({
                    "source": source,
                    "sink": sink,
                    "path": path,
                }))
            })
            .collect(),
        Err(e) => {
            tracing::debug!("get_taint_paths query failed: {e}");
            Vec::new()
        }
    };

    Ok(serde_json::json!({
        "status": "ok",
        "function": function,
        "taint_paths": paths,
        "count": paths.len()
    }))
}

/// Get cross-file call relationships for a function.
fn execute_get_cross_file_calls(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
    let function: String = function.chars().take(256).collect();
    tracing::info!("Tool get_cross_file_calls: {function}");

    let inv = esc(investigation_id);
    let func_esc = esc(&function);

    // Get the function's file prefix from its address
    let file_prefix: Option<String> = db
        .cypher_query(&format!(
            "MATCH (f:Function) WHERE f.investigation_id = '{inv}' AND f.name = '{func_esc}' \
             RETURN f.address LIMIT 1"
        ))
        .ok()
        .and_then(|rows| {
            rows.first().and_then(|row| {
                LadybugGraphDb::as_str(&row[0])
                    .map(|addr| addr.split(':').next().unwrap_or("").to_string())
            })
        });

    let mut results = Vec::new();

    if let Some(ref prefix) = file_prefix {
        // Get callees in different files
        let cypher = format!(
            "MATCH (f1:Function)-[:CALLS]->(f2:Function) \
             WHERE f1.investigation_id = '{inv}' AND f1.name = '{func_esc}' \
             RETURN f2.name, f2.address LIMIT 50"
        );
        if let Ok(rows) = db.cypher_query(&cypher) {
            for row in &rows {
                let name = LadybugGraphDb::as_str(&row[0]).unwrap_or("").to_string();
                let address = LadybugGraphDb::as_str(&row[1]).unwrap_or("").to_string();
                let callee_prefix = address.split(':').next().unwrap_or("");
                if callee_prefix != prefix {
                    results.push(serde_json::json!({
                        "name": name,
                        "address": address,
                        "direction": "callee",
                    }));
                }
            }
        }

        // Get callers from different files
        let cypher = format!(
            "MATCH (f1:Function)-[:CALLS]->(f2:Function) \
             WHERE f2.investigation_id = '{inv}' AND f2.name = '{func_esc}' \
             RETURN f1.name, f1.address LIMIT 50"
        );
        if let Ok(rows) = db.cypher_query(&cypher) {
            for row in &rows {
                let name = LadybugGraphDb::as_str(&row[0]).unwrap_or("").to_string();
                let address = LadybugGraphDb::as_str(&row[1]).unwrap_or("").to_string();
                let caller_prefix = address.split(':').next().unwrap_or("");
                if caller_prefix != prefix {
                    results.push(serde_json::json!({
                        "name": name,
                        "address": address,
                        "direction": "caller",
                    }));
                }
            }
        }
    }

    Ok(serde_json::json!({
        "status": "ok",
        "function": function,
        "cross_file_calls": results,
        "count": results.len()
    }))
}

/// Get all data sources for an investigation.
fn execute_get_data_sources(
    db: &GraphDb,
    investigation_id: &str,
    _args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    tracing::info!("Tool get_data_sources for investigation {investigation_id}");

    let inv = esc(investigation_id);
    let cypher = format!(
        "MATCH (s:DataSource) WHERE s.investigation_id = '{inv}' \
         RETURN s.name, s.source_type, s.location LIMIT 100"
    );

    let sources: Vec<serde_json::Value> = match db.cypher_query(&cypher) {
        Ok(rows) => rows
            .iter()
            .filter_map(|r| {
                let name = LadybugGraphDb::as_str(&r[0])?.to_string();
                let src_type = LadybugGraphDb::as_str(&r[1]).unwrap_or("").to_string();
                let location = LadybugGraphDb::as_str(&r[2]).unwrap_or("").to_string();
                Some(serde_json::json!({
                    "name": name,
                    "source_type": src_type,
                    "location": location,
                }))
            })
            .collect(),
        Err(e) => {
            tracing::debug!("get_data_sources query failed: {e}");
            Vec::new()
        }
    };

    Ok(serde_json::json!({
        "status": "ok",
        "data_sources": sources,
        "count": sources.len()
    }))
}

/// Get all import symbols for an investigation.
fn execute_get_imports(
    db: &GraphDb,
    investigation_id: &str,
    _args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    tracing::info!("Tool get_imports for investigation {investigation_id}");

    let inv = esc(investigation_id);
    let cypher = format!(
        "MATCH (s:Symbol) WHERE s.investigation_id = '{inv}' \
         AND s.symbol_type = 'import' \
         RETURN s.name, s.symbol_type LIMIT 100"
    );

    let imports: Vec<serde_json::Value> = match db.cypher_query(&cypher) {
        Ok(rows) => rows
            .iter()
            .filter_map(|r| {
                let name = LadybugGraphDb::as_str(&r[0])?.to_string();
                let sym_type = LadybugGraphDb::as_str(&r[1]).unwrap_or("").to_string();
                Some(serde_json::json!({
                    "name": name,
                    "symbol_type": sym_type,
                }))
            })
            .collect(),
        Err(e) => {
            tracing::debug!("get_imports query failed: {e}");
            Vec::new()
        }
    };

    Ok(serde_json::json!({
        "status": "ok",
        "imports": imports,
        "count": imports.len()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::search::initialize_cwe_catalog_with_dir;

    /// Helper: create a Function node in LadybugDB.
    fn create_function(
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

    /// Helper: create a CALLS relationship between two functions by id.
    fn create_calls(db: &GraphDb, caller_id: &str, callee_id: &str) {
        db.cypher_execute(&format!(
            "MATCH (a:Function), (b:Function) WHERE a.id = '{}' AND b.id = '{}' \
             CREATE (a)-[:CALLS]->(b)",
            esc(caller_id),
            esc(callee_id)
        ))
        .unwrap();
    }

    #[test]
    fn test_execute_tool_read_function() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        create_function(
            &db,
            "f1",
            "vulnerable_func",
            "0x401000",
            "void vulnerable_func(char *input) { char buf[32]; strcpy(buf, input); }",
            inv_id,
        );

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

        create_function(&db, "f1", "main", "0x401000", "", inv_id);
        create_function(&db, "f2", "strcpy", "0x402000", "", inv_id);
        create_calls(&db, "f1", "f2");

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

        create_function(&db, "f1", "main", "0x401000", "", inv_id);
        create_function(&db, "f2", "system", "0x402000", "", inv_id);
        create_calls(&db, "f1", "f2");

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

        // Verify finding was stored in LadybugDB
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Finding) WHERE f.investigation_id = '{}' RETURN f.title",
                inv_id
            ))
            .unwrap();
        assert_eq!(rows.len(), 1);
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

        create_function(&db, "f1", "main", "0x401000", "", inv_id);

        let args = serde_json::json!({
            "cypher": "MATCH (f:Function) RETURN f"
        });
        let result = execute_tool(&db, inv_id, "query_graph", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert!(result["row_count"].as_u64().unwrap() >= 1);
        // Verify data was found (format depends on backend path)
        let result_str = serde_json::to_string(&result["rows"]).unwrap();
        assert!(
            result_str.contains("main"),
            "Query should find the 'main' function"
        );
    }

    #[test]
    fn test_execute_tool_search_similar() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        create_function(
            &db,
            "f1",
            "parse_input",
            "0x401000",
            "void parse_input(char *buf) { strcpy(dest, buf); }",
            inv_id,
        );

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

        create_function(
            &db, "f1", "process_data", "0x401000",
            "void process_data(int param_1, char *param_2) { char var_1[32]; strcpy(var_1, param_2); }",
            inv_id,
        );

        let args = serde_json::json!({
            "function": "process_data",
            "renamed_code": "void process_data(int buf_size, char *user_input) { char local_buffer[32]; strcpy(local_buffer, user_input); }",
            "annotations": "param_1 is a buffer size, param_2 is user-controlled input"
        });
        let result = execute_tool(&db, inv_id, "rename_function", &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify the decompiled code was updated via Cypher
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Function) WHERE f.name = 'process_data' AND f.investigation_id = '{}' \
                 RETURN f.decompiled LIMIT 1",
                inv_id
            ))
            .unwrap();
        let updated = LadybugGraphDb::as_str(&rows[0][0]).unwrap();
        assert!(updated.contains("user_input"));
        assert!(updated.contains("local_buffer"));
    }

    #[test]
    fn test_query_graph_rejects_destructive_query() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Attempt an INSERT via query_graph — rejected by the translator
        let args = serde_json::json!({
            "cypher": "INSERT INTO functions (id, name) VALUES ('evil', 'injected')"
        });
        let result = execute_tool(&db, inv_id, "query_graph", &args).unwrap();

        assert_eq!(result["status"], "error");
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("Unsupported query pattern"));

        // Verify no data was actually inserted (defense-in-depth check)
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
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        std::fs::write(
            knowledge_dir.join("memory.md"),
            "# Memory\n\nUse durable memory to store generalized lessons about buffer overflows.",
        )
        .unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();
        let args = serde_json::json!({"query": "memory"});
        let result = execute_lookup_knowledge_with_dir(&db, &args, &knowledge_dir).unwrap();
        assert_eq!(result["status"], "ok");
        assert!(result["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["source"] == "knowledge-pack" && entry["topic"] == "memory" }));
    }

    #[test]
    fn test_lookup_knowledge_with_cwe_query() {
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        std::fs::write(
            knowledge_dir.join("memory.md"),
            "# Memory\n\nUse durable memory to store generalized lessons about buffer overflows.",
        )
        .unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();
        let args = serde_json::json!({"query": "cwe-119 buffer overflow"});
        let result = execute_lookup_knowledge_with_dir(&db, &args, &knowledge_dir).unwrap();
        assert_eq!(result["status"], "ok");
        assert!(
            result["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["source"] == "cwe"),
            "expected at least one cwe result"
        );
    }

    // ===== TDD: rename_function edge cases =====

    #[test]
    fn test_execute_tool_rename_function_empty_code() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        create_function(
            &db,
            "f1",
            "target_func",
            "0x401000",
            "void target_func() {}",
            inv_id,
        );

        let args = serde_json::json!({"function": "target_func", "renamed_code": ""});
        let result = execute_tool(&db, inv_id, "rename_function", &args).unwrap();
        assert_eq!(result["status"], "error");
        assert!(result["error"].as_str().unwrap().contains("renamed_code"));
    }

    #[test]
    fn test_execute_tool_rename_function_not_found() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({
            "function": "ghost_func",
            "renamed_code": "void ghost_func() {}"
        });
        let result = execute_tool(&db, "inv1", "rename_function", &args).unwrap();
        assert_eq!(result["status"], "not_found");
    }

    #[test]
    fn test_execute_tool_rename_function_by_address() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        create_function(
            &db,
            "f1",
            "sub_401000",
            "0x401000",
            "void sub_401000() {}",
            inv_id,
        );

        let args = serde_json::json!({
            "function": "0x401000",
            "renamed_code": "void process_input(int size, char *buf) { memcpy(dest, buf, size); }"
        });
        let result = execute_tool(&db, inv_id, "rename_function", &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify the update persisted
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Function) WHERE f.address = '0x401000' AND f.investigation_id = '{}' \
                 RETURN f.decompiled LIMIT 1",
                inv_id
            ))
            .unwrap();
        let updated = LadybugGraphDb::as_str(&rows[0][0]).unwrap();
        assert!(updated.contains("process_input"));
    }

    // ===== TDD: read_function by address =====

    #[test]
    fn test_execute_tool_read_function_by_address() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        create_function(
            &db,
            "f1",
            "sub_401000",
            "0x401000",
            "void sub_401000() {}",
            inv_id,
        );

        // Look up by address instead of name
        let args = serde_json::json!({"name": "0x401000"});
        let result = execute_tool(&db, inv_id, "read_function", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["address"], "0x401000");
    }

    // ===== TDD: query_graph empty query =====

    #[test]
    fn test_execute_tool_query_graph_empty() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"cypher": ""});
        let result = execute_tool(&db, "inv1", "query_graph", &args).unwrap();
        assert_eq!(result["status"], "error");
        assert!(result["error"].as_str().unwrap().contains("Empty"));
    }

    // ===== TDD: callers/callees with no results =====

    #[test]
    fn test_execute_tool_get_callers_empty() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        create_function(&db, "f1", "isolated_func", "0x401000", "", inv_id);

        let args = serde_json::json!({"function": "isolated_func"});
        let result = execute_tool(&db, inv_id, "get_callers", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
        assert!(result["callers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_execute_tool_get_callees_empty() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        create_function(&db, "f1", "leaf_func", "0x401000", "", inv_id);

        let args = serde_json::json!({"function": "leaf_func"});
        let result = execute_tool(&db, inv_id, "get_callees", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
        assert!(result["callees"].as_array().unwrap().is_empty());
    }

    // ===== TDD: investigation ID isolation in callers/callees =====

    #[test]
    fn test_callers_scoped_to_investigation() {
        let db = GraphDb::in_memory().unwrap();
        // Investigation A
        create_function(&db, "a1", "main", "0x1000", "", "inv-a");
        create_function(&db, "a2", "target", "0x2000", "", "inv-a");
        create_calls(&db, "a1", "a2");
        // Investigation B — same function names, different investigation
        create_function(&db, "b1", "other_main", "0x3000", "", "inv-b");
        create_function(&db, "b2", "target", "0x4000", "", "inv-b");
        create_calls(&db, "b1", "b2");

        let args = serde_json::json!({"function": "target"});
        let result = execute_tool(&db, "inv-a", "get_callers", &args).unwrap();
        assert_eq!(result["count"], 1);
        assert_eq!(result["callers"][0]["name"], "main");
    }

    // ===== TDD: memory tools without memory store =====

    #[test]
    fn test_store_memory_unavailable() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({
            "experience_type": "insight",
            "context": "test context",
            "outcome": "test outcome"
        });
        let result = execute_tool(&db, "inv1", "store_memory", &args).unwrap();
        assert_eq!(result["status"], "unavailable");
    }

    #[test]
    fn test_recall_memory_unavailable() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"query": "test"});
        let result = execute_tool(&db, "inv1", "recall_memory", &args).unwrap();
        assert_eq!(result["status"], "unavailable");
    }

    // ===== TDD: Cypher injection in handler args =====

    #[test]
    fn test_read_function_cypher_injection() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Try to inject Cypher via function name
        let args = serde_json::json!({"name": "' OR 1=1 RETURN n//"});
        let result = execute_tool(&db, inv_id, "read_function", &args).unwrap();
        // Should not crash, should return not_found (injection escaped)
        assert_eq!(result["status"], "not_found");
    }

    #[test]
    fn test_get_callers_cypher_injection() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"function": "x'}) RETURN n//"});
        let result = execute_tool(&db, "inv1", "get_callers", &args).unwrap();
        // Should not crash — esc() prevents injection
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
    }

    #[test]
    fn test_rename_function_cypher_injection_in_code() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        create_function(&db, "f1", "target", "0x1000", "old code", inv_id);

        // Attempt injection in renamed_code
        let args = serde_json::json!({
            "function": "target",
            "renamed_code": "injected'}) DELETE (n:Function)//"
        });
        let result = execute_tool(&db, inv_id, "rename_function", &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify original function still exists (injection was escaped, not executed)
        let rows = db
            .cypher_query(&format!(
                "MATCH (f:Function) WHERE f.investigation_id = '{}' RETURN count(f)",
                inv_id
            ))
            .unwrap();
        let count = LadybugGraphDb::as_i64(&rows[0][0]).unwrap();
        assert_eq!(
            count, 1,
            "Function must still exist after injection attempt"
        );
    }

    // ===== TDD: cross-file calls with nonexistent function =====

    #[test]
    fn test_execute_get_cross_file_calls_nonexistent() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"function": "nonexistent"});
        let result = execute_tool(&db, "inv1", "get_cross_file_calls", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
    }

    // ===== TDD: data sources/imports empty investigation =====

    #[test]
    fn test_execute_get_data_sources_empty() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({});
        let result = execute_tool(&db, "empty-inv", "get_data_sources", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
    }

    #[test]
    fn test_execute_get_imports_empty() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({});
        let result = execute_tool(&db, "empty-inv", "get_imports", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
    }

    // ===== TDD: FFI safety — special chars in function names =====

    #[test]
    fn test_function_with_special_chars_in_name() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        // C++ mangled names often have special characters
        let mangled = "_ZN5Class6methodEv";
        create_function(&db, "f1", mangled, "0x1000", "void method() {}", inv_id);

        let args = serde_json::json!({"name": mangled});
        let result = execute_tool(&db, inv_id, "read_function", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["function"], mangled);
    }

    #[test]
    fn test_function_with_quotes_in_decompiled() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        let code = "printf('hello world'); char *s = \"it's a test\";";
        create_function(&db, "f1", "print_test", "0x1000", &esc(code), inv_id);

        let args = serde_json::json!({"name": "print_test"});
        let result = execute_tool(&db, inv_id, "read_function", &args).unwrap();
        assert_eq!(result["status"], "ok");
        // Should not crash — quotes in decompiled code are handled
    }

    // ===== TDD: taint paths with special chars =====

    #[test]
    fn test_get_taint_paths_special_chars_in_function() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";
        // Function name with characters that need escaping
        let args = serde_json::json!({"function": "func'with\"quotes"});
        let result = execute_tool(&db, inv_id, "get_taint_paths", &args).unwrap();
        // Should not crash — esc() prevents Cypher syntax errors
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 0);
    }

    #[test]
    fn test_lookup_knowledge_surfaces_pack_errors() {
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        std::fs::create_dir_all(knowledge_dir.join("broken.md")).unwrap();

        let args = serde_json::json!({"query": "memory"});
        let result = execute_lookup_knowledge_with_dir(&db, &args, &knowledge_dir).unwrap();
        assert_eq!(result["status"], "error");
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("Failed to read knowledge pack"));
    }

    // ===== Graph tool execution tests =====

    #[test]
    fn test_execute_get_taint_paths() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Set up function, data source, data sink, and taint flow
        create_function(&db, "f1", "parse_input", "main.c:0x1000", "", inv_id);

        db.cypher_execute(&format!(
            "CREATE (s:DataSource {{id: 'ds1', name: 'user_input', source_type: 'stdin', \
             location: 'main.c:10', investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();

        db.cypher_execute(&format!(
            "CREATE (k:DataSink {{id: 'dk1', name: 'strcpy_call', sink_type: 'memory', \
             danger_level: 'high', location: 'main.c:20', investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();

        db.cypher_execute(
            "MATCH (s:DataSource), (k:DataSink) WHERE s.id = 'ds1' AND k.id = 'dk1' \
             CREATE (s)-[:TAINT_FLOW {path: 'user_input -> buf -> strcpy_call', sanitized: 0}]->(k)",
        )
        .unwrap();

        let args = serde_json::json!({"function": "parse_input"});
        let result = execute_tool(&db, inv_id, "get_taint_paths", &args).unwrap();

        assert_eq!(result["status"], "ok");
        let paths = result["taint_paths"]
            .as_array()
            .expect("taint_paths must be an array");
        assert!(!paths.is_empty(), "Should find at least one taint path");
        assert!(
            paths[0]["source"].as_str().unwrap().contains("user_input"),
            "Taint path should include source name"
        );
        assert!(
            paths[0]["sink"].as_str().unwrap().contains("strcpy_call"),
            "Taint path should include sink name"
        );
    }

    #[test]
    fn test_execute_get_taint_paths_no_results() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        let args = serde_json::json!({"function": "nonexistent"});
        let result = execute_tool(&db, inv_id, "get_taint_paths", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(
            result["taint_paths"].as_array().unwrap().len(),
            0,
            "No taint paths for nonexistent function"
        );
    }

    #[test]
    fn test_execute_get_cross_file_calls() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Two functions in different files
        create_function(&db, "f1", "caller_func", "src/main.c:0x1000", "", inv_id);
        create_function(&db, "f2", "callee_func", "src/util.c:0x2000", "", inv_id);
        // Same file function — should NOT appear in cross-file results
        create_function(&db, "f3", "same_file_func", "src/main.c:0x3000", "", inv_id);
        create_calls(&db, "f1", "f2");
        create_calls(&db, "f1", "f3");

        let args = serde_json::json!({"function": "caller_func"});
        let result = execute_tool(&db, inv_id, "get_cross_file_calls", &args).unwrap();

        assert_eq!(result["status"], "ok");
        let calls = result["cross_file_calls"]
            .as_array()
            .expect("cross_file_calls must be an array");
        // Should include callee_func (different file) but NOT same_file_func
        assert!(
            calls
                .iter()
                .any(|c| c["name"].as_str().unwrap() == "callee_func"),
            "Should include cross-file callee"
        );
        assert!(
            !calls
                .iter()
                .any(|c| c["name"].as_str().unwrap() == "same_file_func"),
            "Should exclude same-file calls"
        );
    }

    #[test]
    fn test_execute_get_data_sources() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.cypher_execute(&format!(
            "CREATE (s:DataSource {{id: 'ds1', name: 'env_var', source_type: 'environment', \
             location: 'config.c:15', investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();
        db.cypher_execute(&format!(
            "CREATE (s:DataSource {{id: 'ds2', name: 'network_recv', source_type: 'network', \
             location: 'net.c:42', investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();
        // Different investigation — should NOT appear
        db.cypher_execute(
            "CREATE (s:DataSource {id: 'ds3', name: 'other_source', source_type: 'file', \
             location: 'other.c:1', investigation_id: 'other-inv'})",
        )
        .unwrap();

        let args = serde_json::json!({});
        let result = execute_tool(&db, inv_id, "get_data_sources", &args).unwrap();

        assert_eq!(result["status"], "ok");
        let sources = result["data_sources"]
            .as_array()
            .expect("data_sources must be an array");
        assert_eq!(
            sources.len(),
            2,
            "Should return only sources for this investigation"
        );
        assert!(
            sources.iter().any(|s| s["name"] == "env_var"),
            "Should include env_var source"
        );
        assert!(
            sources.iter().any(|s| s["name"] == "network_recv"),
            "Should include network_recv source"
        );
    }

    #[test]
    fn test_execute_get_imports() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        // Insert import symbols via Cypher
        db.cypher_execute(&format!(
            "CREATE (s:Symbol {{id: 's1', name: 'stdio.h', symbol_type: 'import', \
             investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();
        db.cypher_execute(&format!(
            "CREATE (s:Symbol {{id: 's2', name: 'stdlib.h', symbol_type: 'import', \
             investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();
        // Non-import symbol — should NOT appear
        db.cypher_execute(&format!(
            "CREATE (s:Symbol {{id: 's3', name: 'local_var', symbol_type: 'local', \
             investigation_id: '{}'}})",
            esc(inv_id)
        ))
        .unwrap();

        let args = serde_json::json!({});
        let result = execute_tool(&db, inv_id, "get_imports", &args).unwrap();

        assert_eq!(result["status"], "ok");
        let imports = result["imports"]
            .as_array()
            .expect("imports must be an array");
        assert_eq!(imports.len(), 2, "Should return only import symbols");
        assert!(
            imports.iter().any(|i| i["name"] == "stdio.h"),
            "Should include stdio.h import"
        );
        assert!(
            imports.iter().any(|i| i["name"] == "stdlib.h"),
            "Should include stdlib.h import"
        );
    }

    // ===== CWE Knowledge Graph: enriched lookup_cwe tests =====

    #[test]
    fn test_lookup_cwe_enriched_response() {
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        // Unset feature flag to ensure enriched mode (default)
        std::env::remove_var("SKWAQ_CWE_KG_ENRICHED");

        let args = serde_json::json!({"cwe_id": "CWE-119"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["cwe_id"], "CWE-119");
        // Enriched fields should be present
        assert!(
            result.get("semantic_class").is_some(),
            "missing semantic_class"
        );
        assert!(
            result.get("detection_signals").is_some(),
            "missing detection_signals"
        );
        assert!(
            result.get("recommended_tools").is_some(),
            "missing recommended_tools"
        );
        assert!(
            result.get("danger_categories").is_some(),
            "missing danger_categories"
        );
        assert!(result.get("children").is_some(), "missing children");
    }

    #[test]
    fn test_lookup_cwe_children_query() {
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        std::env::remove_var("SKWAQ_CWE_KG_ENRICHED");

        let args = serde_json::json!({"cwe_id": "CWE-119"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();

        assert_eq!(result["status"], "ok");
        let children = result["children"].as_array().unwrap();
        // CWE-119 should have children (CWE-120, CWE-125, CWE-787, etc.)
        assert!(!children.is_empty(), "CWE-119 should have child CWEs");
        // Check that at least CWE-125 is a child
        assert!(
            children.iter().any(|c| c["cwe_id"] == "CWE-125"),
            "CWE-125 should be a child of CWE-119"
        );
    }

    #[test]
    fn test_lookup_cwe_feature_flag_legacy() {
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        // Set feature flag to 0 for legacy mode
        std::env::set_var("SKWAQ_CWE_KG_ENRICHED", "0");

        let args = serde_json::json!({"cwe_id": "CWE-119"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["cwe_id"], "CWE-119");
        // Legacy response should NOT have enriched fields
        assert!(
            result.get("semantic_class").is_none(),
            "legacy mode should not have semantic_class"
        );
        assert!(
            result.get("children").is_none(),
            "legacy mode should not have children"
        );
        assert!(
            result.get("detection_signals").is_none(),
            "legacy mode should not have detection_signals"
        );

        // Clean up env var
        std::env::remove_var("SKWAQ_CWE_KG_ENRICHED");
    }

    #[test]
    fn test_lookup_cwe_with_fn_insight() {
        let db = GraphDb::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let knowledge_dir = temp.path().join("knowledge");
        std::fs::create_dir_all(&knowledge_dir).unwrap();
        initialize_cwe_catalog_with_dir(&db, &knowledge_dir).unwrap();

        std::env::remove_var("SKWAQ_CWE_KG_ENRICHED");

        let args = serde_json::json!({"cwe_id": "CWE-119"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();

        assert_eq!(result["status"], "ok");
        // If KG JSON was loaded, fn_insight should be non-empty
        if crate::knowledge::search::load_cwe_knowledge_graph().is_some() {
            assert!(
                result.get("fn_insight").is_some(),
                "fn_insight should be present when KG is loaded"
            );
            let insight = result["fn_insight"].as_str().unwrap();
            assert!(!insight.is_empty(), "fn_insight should be non-empty");
        }
    }
}
