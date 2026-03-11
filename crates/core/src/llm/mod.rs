//! LLM client layer: traits, backends, and the agentic tool loop.

pub mod anthropic;
pub mod copilot;
pub mod copilot_auth;
pub mod copilot_client;
pub mod ollama;
pub mod traits;

pub use copilot_client::CopilotClient;
pub use traits::*;

use crate::config::LlmConfig;
use std::sync::Arc;

/// Create an LLM client from configuration.
///
/// Examines `config.reasoning` to decide which backend to use:
/// - `"anthropic"` (default) -> Anthropic Claude API
/// - `"copilot"` -> GitHub Copilot
/// - `"ollama"` -> local Ollama server
///
/// Auto-detection: if no explicit backend is configured and `ANTHROPIC_API_KEY`
/// is set, the Anthropic backend is preferred.
pub fn create_llm_client(config: &LlmConfig) -> Arc<dyn LlmClient> {
    match config.reasoning.as_str() {
        "anthropic" => match anthropic::AnthropicClient::new() {
            Ok(client) => Arc::new(client),
            Err(e) => {
                tracing::warn!("Anthropic client init failed ({e}), falling back to copilot");
                Arc::new(CopilotClient::new())
            }
        },
        "ollama" => Arc::new(ollama::OllamaClient::new(&config.ollama.host)),
        "copilot" => Arc::new(CopilotClient::new()),
        other => {
            // Auto-detect: try Anthropic if ANTHROPIC_API_KEY is set
            if std::env::var("ANTHROPIC_API_KEY").is_ok() {
                tracing::info!(
                    "Unknown backend '{other}', but ANTHROPIC_API_KEY set; using Anthropic"
                );
                match anthropic::AnthropicClient::new() {
                    Ok(client) => Arc::new(client),
                    Err(_) => Arc::new(CopilotClient::new()),
                }
            } else {
                tracing::info!("Unknown backend '{other}', falling back to copilot");
                Arc::new(CopilotClient::new())
            }
        }
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
    fn test_create_copilot_client_explicit() {
        let config = LlmConfig {
            reasoning: "copilot".into(),
            ..Default::default()
        };
        let client = create_llm_client(&config);
        assert_eq!(client.provider_name(), "copilot");
    }

    #[test]
    fn test_create_anthropic_client_with_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "test-key");

        let config = LlmConfig {
            reasoning: "anthropic".into(),
            ..Default::default()
        };
        let client = create_llm_client(&config);
        assert_eq!(client.provider_name(), "anthropic");

        match original {
            Some(key) => std::env::set_var("ANTHROPIC_API_KEY", key),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
    }

    #[test]
    fn test_create_anthropic_client_falls_back_without_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::remove_var("ANTHROPIC_API_KEY");

        let config = LlmConfig {
            reasoning: "anthropic".into(),
            ..Default::default()
        };
        let client = create_llm_client(&config);
        // Falls back to copilot when key is missing
        assert_eq!(client.provider_name(), "copilot");

        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }

    #[test]
    fn test_default_config_creates_anthropic_with_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "test-key");

        let config = LlmConfig::default();
        let client = create_llm_client(&config);
        assert_eq!(client.provider_name(), "anthropic");

        match original {
            Some(key) => std::env::set_var("ANTHROPIC_API_KEY", key),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
    }
}
