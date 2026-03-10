//! VulnHunterAgent: the primary vulnerability discovery agent.
//!
//! Drives an LLM tool loop to find security issues in code by
//! querying the graph database, reading decompiled functions, and
//! creating findings.

use std::path::PathBuf;
use std::sync::Arc;

use skwaq_core::llm::{LlmClient, TokenBudget};

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
        }
    }

    /// Run vulnerability analysis. Currently a placeholder.
    pub async fn analyze(&mut self, _target: &str) -> anyhow::Result<String> {
        todo!("VulnHunterAgent::analyze not yet implemented")
    }

    /// Return the system prompt in use.
    pub fn system_prompt(&self) -> &str {
        &self.system_prompt
    }
}

/// Load a prompt from `~/.skwaq/prompts/{name}.md`, falling back to the
/// bundled default.
fn load_prompt(name: &str) -> String {
    let path = prompt_path(name);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            tracing::info!("Loaded custom prompt from {}", path.display());
            content
        }
        Err(_) => {
            tracing::debug!(
                "No custom prompt at {}, using bundled default",
                path.display()
            );
            BUNDLED_PROMPT.to_string()
        }
    }
}

fn prompt_path(name: &str) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".skwaq")
        .join("prompts")
        .join(format!("{name}.md"))
}
