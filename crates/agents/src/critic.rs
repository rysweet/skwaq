//! CriticAgent: validates and refines vulnerability findings.
//!
//! After VulnHunter produces candidate findings, the Critic reviews each
//! one for accuracy, severity calibration, and false-positive likelihood.
//! All tool calls execute against the real database.

use std::sync::Arc;

use skwaq_core::graph::GraphDb;
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
            model: "openai/gpt-4o-mini".into(),
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
    /// All tool calls hit the real database for re-examination.
    pub async fn validate(
        &mut self,
        findings_json: &str,
        investigation_id: &str,
        db: &GraphDb,
    ) -> anyhow::Result<String> {
        let user_prompt = format!(
            "Review the following vulnerability findings and validate each one. \
             For each finding, determine if it is a true positive or false positive, \
             and adjust severity if needed.\n\n\
             ## Findings to review:\n\n{findings_json}"
        );

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
