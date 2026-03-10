//! VulnHunterAgent: the primary vulnerability discovery agent.
//!
//! Drives an LLM tool loop to find security issues in code by
//! querying the graph database, reading decompiled functions, and
//! creating findings.

use std::path::PathBuf;
use std::sync::Arc;

use skwaq_core::graph::GraphDb;
use skwaq_core::llm::{execute_with_tools, LlmClient, TokenBudget};

use crate::tools::agent_tools;

/// Default system prompt bundled with the binary.
const BUNDLED_PROMPT: &str = "\
You are VulnHunter, an expert vulnerability researcher. You have access to a \
code property graph containing functions, call relationships, data flows, and \
CWE entries. Your goal is to find real, exploitable vulnerabilities by \
systematically examining the attack surface.\n\n\
Start by querying for dangerous API usage, then trace data flows from sources \
to sinks, and validate each potential finding before reporting it.\n\n\
Be precise. Avoid false positives. Explain your reasoning for each finding.";

/// The vulnerability hunting agent.
pub struct VulnHunterAgent {
    /// LLM client for reasoning.
    pub llm: Arc<dyn LlmClient>,
    /// Token budget for this analysis run.
    pub budget: TokenBudget,
    /// System prompt (loaded from file or bundled).
    system_prompt: String,
    /// Model name to use.
    model: String,
}

impl VulnHunterAgent {
    /// Create a new VulnHunterAgent.
    ///
    /// Attempts to load the system prompt from `~/.skwaq/prompts/vuln_hunter.md`,
    /// falling back to the bundled default.
    pub fn new(llm: Arc<dyn LlmClient>, budget: TokenBudget) -> Self {
        let system_prompt = load_prompt("vuln_hunter");
        Self {
            llm,
            budget,
            system_prompt,
            model: "gpt-4o".into(),
        }
    }

    /// Set the model name to use for LLM calls.
    pub fn with_model(mut self, model: &str) -> Self {
        self.model = model.to_string();
        self
    }

    /// Run vulnerability analysis on a target binary/investigation.
    ///
    /// Builds context from the graph database (functions, imports, taint paths)
    /// and drives the LLM tool loop until completion or budget exhaustion.
    pub async fn analyze(&mut self, target: &str, db: &GraphDb) -> anyhow::Result<String> {
        let user_prompt = build_analysis_prompt(target, db);
        let tools = agent_tools();

        let result = execute_with_tools(
            self.llm.as_ref(),
            &self.model,
            &self.system_prompt,
            &user_prompt,
            &tools,
            |tool_name, args| async move { execute_tool(&tool_name, &args).await },
            &mut self.budget,
        )
        .await?;

        Ok(result)
    }

    /// Return the system prompt in use.
    pub fn system_prompt(&self) -> &str {
        &self.system_prompt
    }
}

/// Build the initial user prompt with context from the graph database.
fn build_analysis_prompt(target: &str, db: &GraphDb) -> String {
    let mut parts = vec![format!(
        "Analyze the binary target: {target}\n\nHere is what we know from the graph database:\n"
    )];

    // Summarize functions
    if let Ok(mut stmt) =
        db.conn()
            .prepare("SELECT name, address FROM functions ORDER BY name LIMIT 50")
    {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        }) {
            let funcs: Vec<(String, String)> = rows.filter_map(|r| r.ok()).collect();
            if !funcs.is_empty() {
                parts.push(format!("\n## Functions ({} shown):\n", funcs.len()));
                for (name, addr) in &funcs {
                    parts.push(format!("- {name} @ {addr}"));
                }
            }
        }
    }

    // Summarize taint flows
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0 LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            let flows: Vec<(String, String, String)> = rows.filter_map(|r| r.ok()).collect();
            if !flows.is_empty() {
                parts.push(format!("\n## Unsanitized taint flows ({}):\n", flows.len()));
                for (src, sink, path) in &flows {
                    parts.push(format!("- {src} -> {sink}: {path}"));
                }
            }
        }
    }

    // Summarize dangerous API calls
    let dangerous = [
        "strcpy", "strcat", "sprintf", "gets", "scanf", "system", "exec",
        "popen", "memcpy", "memmove", "recv", "read",
    ];
    let placeholders: String = dangerous
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name IN ({placeholders}) LIMIT 30"
    );
    if let Ok(mut stmt) = db.conn().prepare(&sql) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        }) {
            let calls: Vec<(String, String)> = rows.filter_map(|r| r.ok()).collect();
            if !calls.is_empty() {
                parts.push(format!("\n## Dangerous API calls ({}):\n", calls.len()));
                for (caller, callee) in &calls {
                    parts.push(format!("- {caller} -> {callee}"));
                }
            }
        }
    }

    parts.push(
        "\n\nStart your analysis. Use the tools to dig deeper, then create findings for \
         each confirmed vulnerability."
            .into(),
    );

    parts.join("\n")
}

/// Execute a single tool call.
///
/// In a full deployment this would query the real graph database.
/// For now, tool calls return structured placeholder data to allow
/// the agent loop to function end-to-end.
async fn execute_tool(
    name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    match name {
        "query_graph" => {
            let cypher = args
                .get("cypher")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            tracing::info!("Tool query_graph: {cypher}");
            Ok(serde_json::json!({
                "status": "ok",
                "query": cypher,
                "rows": [],
                "note": "Graph query executed (no live DB in this context)"
            }))
        }
        "read_function" => {
            let func = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            tracing::info!("Tool read_function: {func}");
            Ok(serde_json::json!({
                "status": "ok",
                "function": func,
                "decompiled": format!("// Decompiled code for {func} not available in this context")
            }))
        }
        "get_callers" | "get_callees" => {
            let func = args
                .get("function")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            tracing::info!("Tool {name}: {func}");
            Ok(serde_json::json!({
                "status": "ok",
                "function": func,
                "results": []
            }))
        }
        "lookup_cwe" => {
            let cwe_id = args
                .get("cwe_id")
                .and_then(|v| v.as_str())
                .unwrap_or("CWE-0");
            tracing::info!("Tool lookup_cwe: {cwe_id}");
            Ok(serde_json::json!({
                "status": "ok",
                "cwe_id": cwe_id,
                "name": format!("CWE entry for {cwe_id}"),
                "description": "See https://cwe.mitre.org for details."
            }))
        }
        "create_finding" => {
            let title = args
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled");
            let severity = args
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium");
            tracing::info!("Tool create_finding: {title} [{severity}]");
            let finding_id = uuid::Uuid::new_v4().to_string();
            Ok(serde_json::json!({
                "status": "created",
                "finding_id": finding_id,
                "title": title,
                "severity": severity
            }))
        }
        "search_similar" => {
            let code = args
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            tracing::info!("Tool search_similar: {}...", &code[..code.len().min(40)]);
            Ok(serde_json::json!({
                "status": "ok",
                "results": []
            }))
        }
        _ => {
            tracing::warn!("Unknown tool: {name}");
            Ok(serde_json::json!({
                "error": format!("Unknown tool: {name}")
            }))
        }
    }
}

/// Load a prompt from `~/.skwaq/prompts/{name}.md`, falling back to the
/// bundled default.
fn load_prompt(name: &str) -> String {
    // Try project-local prompts directory first
    let local_path = PathBuf::from("prompts").join(format!("{name}.md"));
    if let Ok(content) = std::fs::read_to_string(&local_path) {
        tracing::info!("Loaded prompt from {}", local_path.display());
        return content;
    }

    // Then try ~/.skwaq/prompts/
    let home_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".skwaq")
        .join("prompts")
        .join(format!("{name}.md"));
    match std::fs::read_to_string(&home_path) {
        Ok(content) => {
            tracing::info!("Loaded custom prompt from {}", home_path.display());
            content
        }
        Err(_) => {
            tracing::debug!(
                "No custom prompt at {}, using bundled default",
                home_path.display()
            );
            BUNDLED_PROMPT.to_string()
        }
    }
}
