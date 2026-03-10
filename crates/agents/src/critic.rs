//! CriticAgent: validates and refines vulnerability findings.
//!
//! After VulnHunter produces candidate findings, the Critic reviews each
//! one for accuracy, severity calibration, and false-positive likelihood.

use std::path::PathBuf;
use std::sync::Arc;

use skwaq_core::llm::{LlmClient, TokenBudget};

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
}

impl CriticAgent {
    /// Create a new CriticAgent.
    ///
    /// Attempts to load the system prompt from `~/.skwaq/prompts/critic.md`,
    /// falling back to the bundled default.
    pub fn new(llm: Arc<dyn LlmClient>, budget: TokenBudget) -> Self {
        let system_prompt = load_prompt("critic");
        Self {
            llm,
            budget,
            system_prompt,
        }
    }

    /// Validate a set of findings. Currently a placeholder.
    pub async fn validate(&mut self, _findings_json: &str) -> anyhow::Result<String> {
        todo!("CriticAgent::validate not yet implemented")
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
