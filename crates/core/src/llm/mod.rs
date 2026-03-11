//! LLM layer: delegates to RustyClawd's Client for all LLM operations.
//!
//! All Anthropic and Copilot protocol handling (message format, auth,
//! tool-loop, streaming, retries) lives in `rustyclawd_core::client`.
//! This module provides:
//!
//! - [`create_client`] -- build a `rustyclawd_core::client::Client` from
//!   skwaq's [`LlmConfig`](crate::config::LlmConfig).
//! - [`TokenBudget`] -- lightweight token accounting for agent cost control.
//! - [`execute_with_tools`] -- budget-aware wrapper around RustyClawd's
//!   built-in tool loop.
//! - Re-exports of the RustyClawd types used by agents, skills, and the CLI.

pub mod traits;
pub use traits::*;

// Re-export the RustyClawd types that the rest of the crate uses directly.
pub use rustyclawd_core::client::{
    Client, ClientError, ClientResult, ContentBlock, CreateMessageRequest, Message, MessageContent,
    MessageResponse, Role, ToolDefinition, Usage,
};

use crate::config::LlmConfig;

/// Create a RustyClawd [`Client`] from skwaq's LLM configuration.
///
/// Backend selection:
/// - `"copilot"` -- GitHub Copilot (async token discovery + Models API fallback).
/// - `"anthropic"` (default) -- Anthropic Messages API (`ANTHROPIC_API_KEY`).
/// - anything else -- auto-detect: try Anthropic if the env var is set,
///   otherwise fall back to Copilot.
pub async fn create_client(config: &LlmConfig) -> anyhow::Result<Client> {
    match config.reasoning.as_str() {
        "copilot" => {
            let client = Client::new_copilot()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create Copilot client: {e}"))?;
            Ok(client)
        }
        "anthropic" => create_anthropic_client(config),
        other => {
            // Auto-detect: try Anthropic if ANTHROPIC_API_KEY is set
            if std::env::var("ANTHROPIC_API_KEY").is_ok() {
                tracing::info!(
                    "Unknown backend '{other}', but ANTHROPIC_API_KEY set; using Anthropic"
                );
                match create_anthropic_client(config) {
                    Ok(client) => Ok(client),
                    Err(e) => {
                        tracing::warn!(
                            "Anthropic client init failed ({e}), falling back to copilot"
                        );
                        Client::new_copilot()
                            .await
                            .map_err(|e| anyhow::anyhow!("Copilot fallback also failed: {e}"))
                    }
                }
            } else {
                tracing::info!("Unknown backend '{other}', falling back to copilot");
                Client::new_copilot()
                    .await
                    .map_err(|e| anyhow::anyhow!("Copilot client creation failed: {e}"))
            }
        }
    }
}

/// Build an Anthropic-backend client from the environment key.
fn create_anthropic_client(_config: &LlmConfig) -> anyhow::Result<Client> {
    use rustyclawd_core::client::{ApiKey, Config as RcConfig};

    let raw_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY not set"))?;
    let api_key =
        ApiKey::new(raw_key).map_err(|e| anyhow::anyhow!("Invalid ANTHROPIC_API_KEY: {e}"))?;
    let rc_config = RcConfig::new(api_key);
    let client = Client::new(rc_config)
        .map_err(|e| anyhow::anyhow!("Failed to create Anthropic client: {e}"))?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LlmConfig;

    #[test]
    fn test_create_anthropic_client_with_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-test-key-123");

        let config = LlmConfig {
            reasoning: "anthropic".into(),
            ..Default::default()
        };
        let result = create_anthropic_client(&config);
        assert!(result.is_ok());

        match original {
            Some(key) => std::env::set_var("ANTHROPIC_API_KEY", key),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
    }

    #[test]
    fn test_create_anthropic_client_without_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::remove_var("ANTHROPIC_API_KEY");

        let config = LlmConfig::default();
        let result = create_anthropic_client(&config);
        assert!(result.is_err());

        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }
}
