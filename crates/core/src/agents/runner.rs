//! Agent runner: execute any agent definition against the graph database.
//!
//! The runner loads the agent's system prompt, filters available tools,
//! builds context, and drives the LLM tool loop via RustyClawd's Client.

use crate::graph::GraphDb;
use crate::llm::{execute_with_tools, Client, TokenBudget};
use crate::memory::MemoryStore;

use super::definition::AgentDefinition;
use super::tool_definitions::{agent_tools, filter_tools};
use super::tool_executor::{execute_tool, execute_tool_with_memory};

/// Result from running an agent.
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// The agent's name.
    pub agent_name: String,
    /// The final text output from the LLM.
    pub output: String,
    /// Tokens used during this agent's run.
    pub tokens_used: u64,
}

/// Runs any agent definition against the graph database.
pub struct AgentRunner {
    client: Client,
}

impl AgentRunner {
    /// Create a new runner with the given RustyClawd client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Run an agent with access to the graph database for tool execution.
    ///
    /// This is the primary entry point for running agents. The database
    /// reference is captured by the tool executor closure.
    pub async fn run_agent_with_db(
        &self,
        agent: &AgentDefinition,
        investigation_id: &str,
        context: &str,
        db: &GraphDb,
        budget: &mut TokenBudget,
    ) -> anyhow::Result<AgentResult> {
        let all_tools = agent_tools();
        let tools = filter_tools(&all_tools, &agent.tools);
        let model = &agent.model;
        let system_prompt = &agent.system_prompt;

        let tokens_before = budget.used;
        let inv_id = investigation_id.to_string();

        let output = execute_with_tools(
            &self.client,
            model,
            system_prompt,
            context,
            &tools,
            |tool_name, args| {
                let inv = inv_id.clone();
                let result = execute_tool(db, &inv, &tool_name, &args);
                async move { result }
            },
            budget,
        )
        .await?;

        let tokens_used = budget.used - tokens_before;

        Ok(AgentResult {
            agent_name: agent.name.clone(),
            output,
            tokens_used,
        })
    }

    /// Run an agent with access to both the graph database and durable memory.
    ///
    /// Agents can use `store_memory` and `recall_memory` tools to persist
    /// and recall experiences across runs.
    pub async fn run_agent_with_db_and_memory(
        &self,
        agent: &AgentDefinition,
        investigation_id: &str,
        context: &str,
        db: &GraphDb,
        memory: &MemoryStore,
        budget: &mut TokenBudget,
    ) -> anyhow::Result<AgentResult> {
        let all_tools = agent_tools();
        let tools = filter_tools(&all_tools, &agent.tools);
        let model = &agent.model;
        let system_prompt = &agent.system_prompt;

        let tokens_before = budget.used;
        let inv_id = investigation_id.to_string();
        let agent_name_str = agent.name.clone();

        let output = execute_with_tools(
            &self.client,
            model,
            system_prompt,
            context,
            &tools,
            |tool_name, args| {
                let inv = inv_id.clone();
                let name = agent_name_str.clone();
                let result = execute_tool_with_memory(
                    db,
                    &inv,
                    &tool_name,
                    &args,
                    Some(memory),
                    Some(&name),
                );
                async move { result }
            },
            budget,
        )
        .await?;

        let tokens_used = budget.used - tokens_before;

        Ok(AgentResult {
            agent_name: agent.name.clone(),
            output,
            tokens_used,
        })
    }
}

/// Maximum characters for the analysis context sent to the LLM.
///
/// GitHub Models gpt-4o-mini has an ~8000 token request limit.  We keep the
/// context small (~750 tokens) to leave room for system prompt + tool
/// definitions.
const DEFAULT_MAX_CONTEXT_CHARS: usize = 3000;

/// Build context for the analysis from the graph database.
///
/// This summarizes the investigation data to give the agent a starting
/// point for its analysis.  The total output is truncated to
/// `max_context_chars` to stay within LLM token limits.
pub fn build_analysis_context(target: &str, investigation_id: &str, db: &GraphDb) -> String {
    build_analysis_context_with_limit(target, investigation_id, db, DEFAULT_MAX_CONTEXT_CHARS)
}

/// Build context with an explicit character limit.
pub fn build_analysis_context_with_limit(
    target: &str,
    investigation_id: &str,
    db: &GraphDb,
    max_context_chars: usize,
) -> String {
    let mut parts = vec![format!("Analyze target: {target}\n\nGraph DB summary:\n")];

    // Summarize functions with confidence indicators
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT name, address, confidence FROM functions WHERE investigation_id = ?1 ORDER BY name LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2).unwrap_or(0.0),
            ))
        }) {
            let funcs: Vec<(String, String, f64)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !funcs.is_empty() {
                parts.push(format!("\n## Functions ({} shown):\n", funcs.len()));
                let mut low_confidence_count = 0;
                for (name, addr, confidence) in &funcs {
                    if *confidence > 0.0 && *confidence < 0.5 {
                        parts.push(format!(
                            "- {name} @ {addr} [WARNING: LOW CONFIDENCE {:.0}% — decompiled output may be unreliable]",
                            confidence * 100.0
                        ));
                        low_confidence_count += 1;
                    } else if *confidence > 0.0 {
                        parts.push(format!("- {name} @ {addr} [confidence: {:.0}%]", confidence * 100.0));
                    } else {
                        parts.push(format!("- {name} @ {addr}"));
                    }
                }
                if low_confidence_count > 0 {
                    parts.push(format!(
                        "\n⚠ {} function(s) have low decompilation confidence. \
                         Treat findings in these functions with extra skepticism.",
                        low_confidence_count
                    ));
                }
            }
        }
    }

    // Summarize taint flows
    if let Ok(mut stmt) = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0 AND s.investigation_id = ?1 LIMIT 10",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            let flows: Vec<(String, String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !flows.is_empty() {
                parts.push(format!("\n## Unsanitized taint flows ({}):\n", flows.len()));
                for (src, sink, path) in &flows {
                    parts.push(format!("- {src} -> {sink}: {path}"));
                }
            }
        }
    }

    // Summarize dangerous API calls
    let dangerous: Vec<&str> = vec![
        "strcpy", "strcat", "sprintf", "gets", "scanf", "system", "exec", "popen", "memcpy",
        "memmove", "recv", "read",
    ];
    let param_placeholders: String = (0..dangerous.len())
        .map(|i| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let inv_param = format!("?{}", dangerous.len() + 1);
    let sql = format!(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name IN ({param_placeholders}) AND f1.investigation_id = {inv_param} LIMIT 15"
    );
    if let Ok(mut stmt) = db.conn().prepare(&sql) {
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = dangerous
            .iter()
            .map(|n| Box::new(n.to_string()) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        params.push(Box::new(investigation_id.to_string()) as Box<dyn rusqlite::types::ToSql>);
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        if let Ok(rows) = stmt.query_map(params_refs.as_slice(), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            let calls: Vec<(String, String)> =
                rows.collect::<Result<Vec<_>, _>>().unwrap_or_default();
            if !calls.is_empty() {
                parts.push(format!("\n## Dangerous API calls ({}):\n", calls.len()));
                for (caller, callee) in &calls {
                    parts.push(format!("- {caller} -> {callee}"));
                }
            }
        }
    }

    parts.push(
        "\n\nYou have access to durable memory (store_memory/recall_memory tools). \
         Use recall_memory to check for relevant past experiences before starting your analysis. \
         Use store_memory to record significant findings and lessons learned. \
         Keep stored memories generalized — avoid target-specific addresses or paths.\n\n\
         Start your analysis. Use the tools to dig deeper, then create findings for \
         each confirmed vulnerability."
            .into(),
    );

    let full = parts.join("\n");

    // Truncate to stay within LLM token limits (char-boundary safe).
    if full.len() > max_context_chars {
        let mut boundary = max_context_chars;
        while boundary > 0 && !full.is_char_boundary(boundary) {
            boundary -= 1;
        }
        let mut truncated = full[..boundary].to_string();
        truncated.push_str("\n...[truncated]");
        truncated
    } else {
        full
    }
}
