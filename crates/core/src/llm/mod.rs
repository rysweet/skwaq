//! LLM client layer: traits, backends, and the agentic tool loop.

pub mod copilot;
pub mod copilot_auth;
pub mod copilot_client;
pub mod ollama;
pub mod traits;

pub use copilot_client::CopilotClient;
pub use traits::*;

use crate::config::LlmConfig;

/// Create an LLM client from configuration.
///
/// Examines `config.reasoning` to decide which backend to use:
/// - `"copilot"` (default) -> GitHub Copilot
/// - `"ollama"` -> local Ollama server
pub fn create_llm_client(config: &LlmConfig) -> Box<dyn LlmClient> {
    match config.reasoning.as_str() {
        "ollama" => Box::new(ollama::OllamaClient::new(&config.ollama.host)),
        _ => Box::new(CopilotClient::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LlmConfig;

    #[test]
    fn test_create_ollama_client() {
        let config = LlmConfig {
            reasoning: "ollama".into(),
            ..Default::default()
        };
        let client = create_llm_client(&config);
        assert_eq!(client.provider_name(), "ollama");
    }

    #[test]
    fn test_create_copilot_client_default() {
        let config = LlmConfig::default();
        let client = create_llm_client(&config);
        assert_eq!(client.provider_name(), "copilot");
    }

    #[test]
    fn test_create_copilot_client_explicit() {
        let config = LlmConfig {
            reasoning: "copilot".into(),
            ..Default::default()
        };
        let client = create_llm_client(&config);
        assert_eq!(client.provider_name(), "copilot");
    }
}
