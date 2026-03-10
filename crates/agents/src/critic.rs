//! CriticAgent: validates and refines vulnerability findings.
//!
//! After VulnHunter produces candidate findings, the Critic reviews each
//! one for accuracy, severity calibration, and false-positive likelihood.

use std::sync::Arc;

use skwaq_core::llm::{execute_with_tools, LlmClient, TokenBudget};

use crate::tools::agent_tools;

/// Default system prompt bundled with the binary.
const BUNDLED_PROMPT: &str = "\
You are the Critic, a senior security auditor reviewing vulnerability findings. \
For each finding, verify that:\n\
1. The vulnerability is real and exploitable (not a false positive)\n\
2. The severity rating is accurate\n\
3. The CWE classification is correct\n\
4. The description clearly explains the impact\n\n\
Use the available tools to re-examine the code and validate claims. \
Downgrade or reject findings that don't hold up to scrutiny.";

/// The finding validation agent.
pub struct CriticAgent {
    /// LLM client for reasoning.
    pub llm: Arc<dyn LlmClient>,
    /// Token budget for this validation run.
    pub budget: TokenBudget,
    /// System prompt (loaded from file or bundled).
    system_prompt: String,
    /// Model name.
    model: String,
}

impl CriticAgent {
    /// Create a new CriticAgent.
    ///
    /// Attempts to load the system prompt from `~/.skwaq/prompts/critic.md`,
    /// falling back to the bundled default.
    pub fn new(llm: Arc<dyn LlmClient>, budget: TokenBudget) -> Self {
        let system_prompt = crate::prompts::load_prompt("critic", BUNDLED_PROMPT);
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

    /// Validate a set of findings by driving the LLM tool loop.
    ///
    /// `findings_json` should be the JSON output from VulnHunter.
    pub async fn validate(&mut self, findings_json: &str) -> anyhow::Result<String> {
        let user_prompt = format!(
            "Review the following vulnerability findings and validate each one. \
             For each finding, determine if it is a true positive or false positive, \
             and adjust severity if needed.\n\n\
             ## Findings to review:\n\n{findings_json}"
        );

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

/// Execute a single tool call for the critic agent.
async fn execute_tool(
    name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    // Critic uses the same tools as VulnHunter for re-examination.
    match name {
        "query_graph" => {
            let cypher = args
                .get("cypher")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            tracing::info!("Critic query_graph: {cypher}");
            Ok(serde_json::json!({
                "status": "ok",
                "warning": "Tool not connected to live database in current agent context",
                "query": cypher,
                "rows": []
            }))
        }
        "read_function" => {
            let func = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(serde_json::json!({
                "status": "ok",
                "warning": "Tool not connected to live database in current agent context",
                "function": func,
                "decompiled": format!("// Decompiled code for {func}")
            }))
        }
        "get_callers" | "get_callees" => {
            let func = args
                .get("function")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(serde_json::json!({
                "status": "ok",
                "warning": "Tool not connected to live database in current agent context",
                "function": func,
                "results": []
            }))
        }
        "lookup_cwe" => {
            let cwe_id = args
                .get("cwe_id")
                .and_then(|v| v.as_str())
                .unwrap_or("CWE-0");
            Ok(serde_json::json!({
                "status": "ok",
                "warning": "Tool not connected to live database in current agent context",
                "cwe_id": cwe_id,
                "name": format!("CWE entry for {cwe_id}"),
                "description": "See https://cwe.mitre.org for details."
            }))
        }
        "create_finding" => {
            let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled");
            let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");
            let finding_id = uuid::Uuid::new_v4().to_string();
            Ok(serde_json::json!({
                "status": "ok",
                "warning": "Tool not connected to live database in current agent context",
                "finding_id": finding_id,
                "title": title,
                "severity": severity
            }))
        }
        "search_similar" => {
            Ok(serde_json::json!({
                "status": "ok",
                "warning": "Tool not connected to live database in current agent context",
                "results": []
            }))
        }
        _ => Ok(serde_json::json!({
            "error": format!("Unknown tool: {name}")
        })),
    }
}

