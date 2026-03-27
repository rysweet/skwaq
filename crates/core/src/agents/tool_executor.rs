//! Tool execution: dispatches tool calls against the real graph database.
//!
//! Every tool queries or mutates the actual database via LadybugDB Cypher.
//! No SQL fallback paths remain — all queries go through LadybugDB.

use super::tool_translate::{sanitize_cypher_param, translate_to_cypher};
use crate::graph::{GraphDb, LadybugGraphDb};
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

/// Execute a Cypher query against LadybugDB.
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

    // Try direct Cypher execution first (query may already be valid Cypher)
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
            // Empty result — try translating the pattern
        }
        Err(_) => {
            // Not valid Cypher — translate the pattern
        }
    }

    // Translate the query pattern to Cypher
    let cypher = match translate_to_cypher(query, investigation_id) {
        Ok(c) => c,
        Err(msg) => {
            tracing::warn!("query_graph unsupported pattern: {msg}");
            return Ok(serde_json::json!({
                "status": "error",
                "query": query,
                "error": msg
            }));
        }
    };

    match db.cypher_query(&cypher) {
        Ok(rows) => {
            let json_rows: Vec<Vec<String>> = rows
                .iter()
                .map(|row| row.iter().map(|v| format!("{v}")).collect())
                .collect();
            Ok(serde_json::json!({
                "status": "ok",
                "query": query,
                "translated_cypher": cypher,
                "backend": "ladybugdb",
                "rows": json_rows,
                "row_count": json_rows.len()
            }))
        }
        Err(e) => {
            tracing::warn!("query_graph error: {e}");
            Ok(serde_json::json!({
                "status": "error",
                "query": query,
                "error": "Query execution failed"
            }))
        }
    }
}

/// Read the decompiled code of a function by name via Cypher.
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

    let safe_name = sanitize_cypher_param(func_name);
    let safe_inv_id = sanitize_cypher_param(investigation_id);

    // Try by name, then by address
    for field in ["name", "address"] {
        let cypher = format!(
            "MATCH (f:Function) WHERE f.{field} = '{safe_name}' AND f.investigation_id = '{safe_inv_id}' \
             RETURN f.id, f.name, f.address, f.decompiled, f.confidence LIMIT 1"
        );

        let rows = db.cypher_query(&cypher)?;
        if let Some(row) = rows.first() {
            let id = LadybugGraphDb::as_str(&row[0]).unwrap_or("").to_string();
            let name = LadybugGraphDb::as_str(&row[1]).unwrap_or("").to_string();
            let address = LadybugGraphDb::as_str(&row[2]).unwrap_or("").to_string();
            let decompiled = LadybugGraphDb::as_str(&row[3]).unwrap_or("").to_string();
            let confidence = LadybugGraphDb::as_f64(&row[4]).unwrap_or(0.0);
            return Ok(serde_json::json!({
                "status": "ok",
                "function_id": id,
                "function": name,
                "address": address,
                "decompiled": format!("<code_data>\n{}\n</code_data>", decompiled),
                "confidence": confidence
            }));
        }
    }

    Ok(serde_json::json!({
        "status": "not_found",
        "function": func_name,
        "error": format!("Function '{}' not found in investigation", func_name)
    }))
}

/// Get all callers of a function via Cypher.
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

    let safe_name = sanitize_cypher_param(func_name);
    let safe_inv_id = sanitize_cypher_param(investigation_id);

    let cypher = format!(
        "MATCH (caller:Function)-[:CALLS]->(callee:Function {{name: '{safe_name}'}}) \
         WHERE caller.investigation_id = '{safe_inv_id}' \
         RETURN caller.name, caller.address"
    );

    let rows = db.cypher_query(&cypher)?;
    let callers: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|r| {
            let name = LadybugGraphDb::as_str(&r[0])?;
            let addr = LadybugGraphDb::as_str(&r[1]).unwrap_or("");
            Some(serde_json::json!({"name": name, "address": addr}))
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "function": func_name,
        "callers": callers,
        "count": callers.len(),
        "backend": "ladybugdb"
    }))
}

/// Get all callees of a function via Cypher.
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

    let safe_name = sanitize_cypher_param(func_name);
    let safe_inv_id = sanitize_cypher_param(investigation_id);

    let cypher = format!(
        "MATCH (caller:Function {{name: '{safe_name}'}})-[:CALLS]->(callee:Function) \
         WHERE caller.investigation_id = '{safe_inv_id}' \
         RETURN callee.name, callee.address"
    );

    let rows = db.cypher_query(&cypher)?;
    let callees: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|r| {
            let name = LadybugGraphDb::as_str(&r[0])?;
            let addr = LadybugGraphDb::as_str(&r[1]).unwrap_or("");
            Some(serde_json::json!({"name": name, "address": addr}))
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "function": func_name,
        "callees": callees,
        "count": callees.len(),
        "backend": "ladybugdb"
    }))
}

/// Look up a CWE entry by ID via Cypher.
fn execute_lookup_cwe(db: &GraphDb, args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let cwe_id = args
        .get("cwe_id")
        .and_then(|v| v.as_str())
        .unwrap_or("CWE-0");
    tracing::info!("Tool lookup_cwe: {cwe_id}");

    let safe_cwe_id = sanitize_cypher_param(cwe_id);
    let cypher = format!(
        "MATCH (c:Cwe) WHERE c.cwe_id = '{safe_cwe_id}' \
         RETURN c.id, c.cwe_id, c.name, c.description LIMIT 1"
    );

    let rows = db.cypher_query(&cypher)?;
    if let Some(row) = rows.first() {
        let cwe_id_val = LadybugGraphDb::as_str(&row[1]).unwrap_or("").to_string();
        let name = LadybugGraphDb::as_str(&row[2]).unwrap_or("").to_string();
        let description = LadybugGraphDb::as_str(&row[3]).unwrap_or("").to_string();
        Ok(serde_json::json!({
            "status": "ok",
            "cwe_id": cwe_id_val,
            "name": name,
            "description": description
        }))
    } else {
        Ok(serde_json::json!({
            "status": "not_found",
            "cwe_id": cwe_id,
            "error": format!("CWE '{}' not found in knowledge base. Run `skwaq kb init` to populate.", cwe_id)
        }))
    }
}

/// Look up vulnerability analysis knowledge from the knowledge pack.
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

/// Update a function's decompiled code with renamed variables via Cypher.
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

    let safe_code = sanitize_cypher_param(renamed_code);
    let safe_name = sanitize_cypher_param(func_name);
    let safe_inv_id = sanitize_cypher_param(investigation_id);

    // Try update by name
    let cypher = format!(
        "MATCH (f:Function) WHERE f.name = '{safe_name}' AND f.investigation_id = '{safe_inv_id}' \
         SET f.decompiled = '{safe_code}' RETURN f.id"
    );
    let rows = db.cypher_query(&cypher)?;

    if rows.is_empty() {
        // Try by address
        let cypher = format!(
            "MATCH (f:Function) WHERE f.address = '{safe_name}' AND f.investigation_id = '{safe_inv_id}' \
             SET f.decompiled = '{safe_code}' RETURN f.id"
        );
        let rows = db.cypher_query(&cypher)?;
        if rows.is_empty() {
            return Ok(serde_json::json!({
                "status": "not_found",
                "function": func_name,
                "error": format!("Function '{}' not found in investigation", func_name)
            }));
        }
    }

    // Store annotations as an Annotation node if provided
    if !annotations.is_empty() {
        let ann_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let safe_ann_id = sanitize_cypher_param(&ann_id);
        let safe_content =
            sanitize_cypher_param(&format!("Type annotations for {}: {}", func_name, annotations));
        let safe_timestamp = sanitize_cypher_param(&now);

        let cypher = format!(
            "CREATE (a:Annotation {{id: '{safe_ann_id}', content: '{safe_content}', \
             agent: 'decompile-renamer', timestamp: '{safe_timestamp}', \
             investigation_id: '{safe_inv_id}'}})"
        );
        let _ = db.cypher_execute(&cypher);
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

/// Look up the file prefix (portion before ':') from a function's address.
fn lookup_file_prefix(
    db: &GraphDb,
    safe_inv_id: &str,
    safe_func: &str,
) -> anyhow::Result<Option<String>> {
    let cypher = format!(
        "MATCH (f:Function) WHERE f.investigation_id = '{safe_inv_id}' AND f.name = '{safe_func}' \
         RETURN f.address LIMIT 1"
    );
    let rows = db.cypher_query(&cypher)?;
    Ok(rows
        .first()
        .and_then(|r| LadybugGraphDb::as_str(&r[0]))
        .and_then(|addr| {
            addr.split(':')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        }))
}

/// Get taint flow paths involving a specific function via Cypher.
fn execute_get_taint_paths(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
    let function: String = function.chars().take(256).collect();
    tracing::info!("Tool get_taint_paths: {function}");

    let safe_inv_id = sanitize_cypher_param(investigation_id);
    let safe_func = sanitize_cypher_param(&function);

    let file_prefix = lookup_file_prefix(db, &safe_inv_id, &safe_func)?;

    let cypher = if let Some(ref prefix) = file_prefix {
        let safe_prefix = sanitize_cypher_param(prefix);
        format!(
            "MATCH (ds:DataSource)-[tf:TAINT_FLOW]->(dk:DataSink) \
             WHERE ds.investigation_id = '{safe_inv_id}' \
             AND (ds.location CONTAINS '{safe_prefix}' OR dk.location CONTAINS '{safe_prefix}') \
             RETURN ds.name, dk.name, tf.path LIMIT 50"
        )
    } else {
        format!(
            "MATCH (ds:DataSource)-[tf:TAINT_FLOW]->(dk:DataSink) \
             WHERE ds.investigation_id = '{safe_inv_id}' \
             RETURN ds.name, dk.name, tf.path LIMIT 50"
        )
    };

    let rows = db.cypher_query(&cypher)?;
    let paths: Vec<serde_json::Value> = rows
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
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "function": function,
        "taint_paths": paths,
        "count": paths.len()
    }))
}

/// Get cross-file call relationships for a function via Cypher.
fn execute_get_cross_file_calls(
    db: &GraphDb,
    investigation_id: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
    let function: String = function.chars().take(256).collect();
    tracing::info!("Tool get_cross_file_calls: {function}");

    let safe_inv_id = sanitize_cypher_param(investigation_id);
    let safe_func = sanitize_cypher_param(&function);

    let file_prefix = lookup_file_prefix(db, &safe_inv_id, &safe_func)?;

    let mut results = Vec::new();

    if let Some(ref prefix) = file_prefix {
        // Get callees
        let cypher = format!(
            "MATCH (f1:Function {{name: '{safe_func}'}})-[:CALLS]->(f2:Function) \
             WHERE f1.investigation_id = '{safe_inv_id}' \
             RETURN f2.name, f2.address LIMIT 50"
        );
        let rows = db.cypher_query(&cypher)?;
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

        // Get callers
        let cypher = format!(
            "MATCH (f1:Function)-[:CALLS]->(f2:Function {{name: '{safe_func}'}}) \
             WHERE f2.investigation_id = '{safe_inv_id}' \
             RETURN f1.name, f1.address LIMIT 50"
        );
        let rows = db.cypher_query(&cypher)?;
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

    Ok(serde_json::json!({
        "status": "ok",
        "function": function,
        "cross_file_calls": results,
        "count": results.len()
    }))
}

/// Get all data sources for an investigation via Cypher.
fn execute_get_data_sources(
    db: &GraphDb,
    investigation_id: &str,
    _args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    tracing::info!("Tool get_data_sources for investigation {investigation_id}");

    let safe_inv_id = sanitize_cypher_param(investigation_id);
    let cypher = format!(
        "MATCH (s:DataSource) WHERE s.investigation_id = '{safe_inv_id}' \
         RETURN s.name, s.source_type, s.location LIMIT 100"
    );

    let rows = db.cypher_query(&cypher)?;
    let sources: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|r| {
            let name = LadybugGraphDb::as_str(&r[0])?;
            let src_type = LadybugGraphDb::as_str(&r[1]).unwrap_or("");
            let location = LadybugGraphDb::as_str(&r[2]).unwrap_or("");
            Some(serde_json::json!({"name": name, "source_type": src_type, "location": location}))
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "data_sources": sources,
        "count": sources.len(),
        "backend": "ladybugdb"
    }))
}

/// Get all import symbols for an investigation via Cypher.
fn execute_get_imports(
    db: &GraphDb,
    investigation_id: &str,
    _args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    tracing::info!("Tool get_imports for investigation {investigation_id}");

    let safe_inv_id = sanitize_cypher_param(investigation_id);
    let cypher = format!(
        "MATCH (s:Symbol) WHERE s.investigation_id = '{safe_inv_id}' AND s.symbol_type = 'import' \
         RETURN s.name, s.symbol_type LIMIT 100"
    );

    let rows = db.cypher_query(&cypher)?;
    let imports: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|r| {
            let name = LadybugGraphDb::as_str(&r[0])?;
            let sym_type = LadybugGraphDb::as_str(&r[1]).unwrap_or("");
            Some(serde_json::json!({"name": name, "symbol_type": sym_type}))
        })
        .collect();

    Ok(serde_json::json!({
        "status": "ok",
        "imports": imports,
        "count": imports.len(),
        "backend": "ladybugdb"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_tool_read_function() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'vulnerable_func', address: '0x401000', \
             decompiled: 'void vulnerable_func(char *input) {{ char buf[32]; strcpy(buf, input); }}', \
             confidence: 0.9, investigation_id: '{inv_id}'}})"
        ))
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

        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'main', address: '0x401000', investigation_id: '{inv_id}'}})"
        ))
        .unwrap();
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f2', name: 'strcpy', address: '0x402000', investigation_id: '{inv_id}'}})"
        ))
        .unwrap();
        db.cypher_execute(
            "MATCH (a:Function {id: 'f1'}), (b:Function {id: 'f2'}) CREATE (a)-[:CALLS]->(b)",
        )
        .unwrap();

        let args = serde_json::json!({"function": "strcpy"});
        let result = execute_tool(&db, inv_id, "get_callers", &args).unwrap();
        assert_eq!(result["status"], "ok");
        let callers = result["callers"].as_array().unwrap();
        assert!(!callers.is_empty());
        assert_eq!(callers[0]["name"], "main");
    }

    #[test]
    fn test_execute_tool_get_callees() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'main', address: '0x401000', investigation_id: '{inv_id}'}})"
        ))
        .unwrap();
        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f2', name: 'helper', address: '0x402000', investigation_id: '{inv_id}'}})"
        ))
        .unwrap();
        db.cypher_execute(
            "MATCH (a:Function {id: 'f1'}), (b:Function {id: 'f2'}) CREATE (a)-[:CALLS]->(b)",
        )
        .unwrap();

        let args = serde_json::json!({"function": "main"});
        let result = execute_tool(&db, inv_id, "get_callees", &args).unwrap();
        assert_eq!(result["status"], "ok");
        let callees = result["callees"].as_array().unwrap();
        assert!(!callees.is_empty());
        assert_eq!(callees[0]["name"], "helper");
    }

    #[test]
    fn test_execute_tool_lookup_cwe() {
        let db = GraphDb::in_memory().unwrap();

        db.cypher_execute(
            "CREATE (c:Cwe {id: 'cwe1', cwe_id: 'CWE-120', name: 'Buffer Copy without Checking Size', \
             description: 'Classic buffer overflow'})",
        )
        .unwrap();

        let args = serde_json::json!({"cwe_id": "CWE-120"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["cwe_id"], "CWE-120");
        assert_eq!(result["name"], "Buffer Copy without Checking Size");
    }

    #[test]
    fn test_execute_tool_lookup_cwe_not_found() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"cwe_id": "CWE-99999"});
        let result = execute_tool(&db, "inv1", "lookup_cwe", &args).unwrap();
        assert_eq!(result["status"], "not_found");
    }

    #[test]
    fn test_execute_tool_unknown() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({});
        let result = execute_tool(&db, "inv1", "nonexistent_tool", &args).unwrap();
        assert!(result["error"].as_str().unwrap().contains("Unknown tool"));
    }

    #[test]
    fn test_query_graph_empty() {
        let db = GraphDb::in_memory().unwrap();
        let args = serde_json::json!({"cypher": ""});
        let result = execute_tool(&db, "inv1", "query_graph", &args).unwrap();
        assert_eq!(result["status"], "error");
    }

    #[test]
    fn test_query_graph_cypher() {
        let db = GraphDb::in_memory().unwrap();

        db.cypher_execute(
            "CREATE (f:Function {id: 'f1', name: 'main', address: '0x1000', investigation_id: 'inv1'})",
        )
        .unwrap();

        let args = serde_json::json!({"cypher": "MATCH (f:Function) RETURN f.name"});
        let result = execute_tool(&db, "inv1", "query_graph", &args).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["backend"], "ladybugdb");
    }

    #[test]
    fn test_rename_function_cypher() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.cypher_execute(&format!(
            "CREATE (f:Function {{id: 'f1', name: 'func_0x401000', address: '0x401000', \
             decompiled: 'void func_0x401000() {{}}', investigation_id: '{inv_id}'}})"
        ))
        .unwrap();

        let args = serde_json::json!({
            "function": "func_0x401000",
            "renamed_code": "void process_input(char *buf) { validate(buf); }",
            "annotations": "buf: user input buffer"
        });
        let result = execute_tool(&db, inv_id, "rename_function", &args).unwrap();
        assert_eq!(result["status"], "ok");

        // Verify the update in LadybugDB
        let rows = db
            .cypher_query("MATCH (f:Function {id: 'f1'}) RETURN f.decompiled")
            .unwrap();
        assert!(!rows.is_empty());
        let decompiled = LadybugGraphDb::as_str(&rows[0][0]).unwrap();
        assert!(decompiled.contains("process_input"));

        // Verify annotation was created
        let ann_rows = db
            .cypher_query(&format!(
                "MATCH (a:Annotation) WHERE a.investigation_id = '{inv_id}' RETURN a.content"
            ))
            .unwrap();
        assert!(!ann_rows.is_empty());
    }

    #[test]
    fn test_get_data_sources_cypher() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.cypher_execute(&format!(
            "CREATE (s:DataSource {{id: 's1', name: 'recv', source_type: 'network', \
             location: 'net.c:42', investigation_id: '{inv_id}'}})"
        ))
        .unwrap();

        let args = serde_json::json!({});
        let result = execute_tool(&db, inv_id, "get_data_sources", &args).unwrap();
        assert_eq!(result["status"], "ok");
        let sources = result["data_sources"].as_array().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0]["name"], "recv");
    }

    #[test]
    fn test_get_imports_cypher() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = "test-inv";

        db.cypher_execute(&format!(
            "CREATE (s:Symbol {{id: 's1', name: 'printf', symbol_type: 'import', \
             investigation_id: '{inv_id}'}})"
        ))
        .unwrap();

        let args = serde_json::json!({});
        let result = execute_tool(&db, inv_id, "get_imports", &args).unwrap();
        assert_eq!(result["status"], "ok");
        let imports = result["imports"].as_array().unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0]["name"], "printf");
    }
}
