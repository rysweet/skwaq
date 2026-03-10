//! VulnHunterAgent: the primary vulnerability discovery agent.
//!
//! Drives an LLM tool loop to find security issues in code by
//! querying the graph database, reading decompiled functions, and
//! creating findings. All tool calls execute against the real database.

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
Be precise. Avoid false positives. Explain your reasoning for each finding.\n\n\
When you find a vulnerability, use create_finding to record it. Include the \
function name, severity, CWE ID, and a clear description of the issue.";

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
        let system_prompt = crate::prompts::load_prompt("vuln_hunter", BUNDLED_PROMPT);
        Self {
            llm,
            budget,
            system_prompt,
            model: "openai/gpt-4o-mini".into(),
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
    /// All tool calls query the real database.
    pub async fn analyze(
        &mut self,
        target: &str,
        investigation_id: &str,
        db: &GraphDb,
    ) -> anyhow::Result<String> {
        let user_prompt = build_analysis_prompt(target, investigation_id, db);
        let tools = agent_tools();

        let inv_id = investigation_id.to_string();

        let result = execute_with_tools(
            self.llm.as_ref(),
            &self.model,
            &self.system_prompt,
            &user_prompt,
            &tools,
            |tool_name, args| {
                let inv = inv_id.clone();
                // Execute the tool synchronously against the real database.
                // This is safe because execute_with_tools awaits the future
                // directly (no spawn), and GraphDb is valid for the duration.
                let result = crate::tool_executor::execute_tool(db, &inv, &tool_name, &args);
                async move { result }
            },
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
fn build_analysis_prompt(target: &str, investigation_id: &str, db: &GraphDb) -> String {
    let mut parts = vec![format!(
        "Analyze the binary target: {target}\n\nHere is what we know from the graph database:\n"
    )];

    // Summarize functions
    if let Ok(mut stmt) =
        db.conn()
            .prepare("SELECT name, address FROM functions WHERE investigation_id = ?1 ORDER BY name LIMIT 50")
    {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        }) {
            let funcs: Vec<(String, String)> = rows
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default();
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
         WHERE tf.sanitized = 0 AND s.investigation_id = ?1 LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([investigation_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            let flows: Vec<(String, String, String)> = rows
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default();
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
        "strcpy", "strcat", "sprintf", "gets", "scanf", "system", "exec",
        "popen", "memcpy", "memmove", "recv", "read",
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
         WHERE f2.name IN ({param_placeholders}) AND f1.investigation_id = {inv_param} LIMIT 30"
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
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        }) {
            let calls: Vec<(String, String)> = rows
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default();
            if !calls.is_empty() {
                parts.push(format!("\n## Dangerous API calls ({}):\n", calls.len()));
                for (caller, callee) in &calls {
                    parts.push(format!("- {caller} -> {callee}"));
                }
            }
        }
    }

    // Summarize hardening status
    parts.push(
        "\n\nStart your analysis. Use the tools to dig deeper, then create findings for \
         each confirmed vulnerability."
            .into(),
    );

    parts.join("\n")
}
