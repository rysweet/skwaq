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
use anyhow::Context;

/// Create a RustyClawd [`Client`] from skwaq's LLM configuration.
///
/// Backend selection is explicit:
/// - `"copilot"` -- GitHub Copilot via `api.githubcopilot.com`.
/// - `"anthropic"` -- Anthropic Messages API (`ANTHROPIC_API_KEY`).
///
/// Any other value is rejected. skwaq does not silently switch providers.
pub async fn create_client(config: &LlmConfig) -> anyhow::Result<Client> {
    validate_backend_selection(config)?;
    match normalized_backend(config).as_str() {
        "copilot" => {
            let client = Client::new_copilot()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create Copilot client: {e}"))?;
            Ok(client)
        }
        "anthropic" => create_anthropic_client(config),
        _ => unreachable!("validate_backend_selection rejected unsupported backends"),
    }
}

pub fn validate_benchmark_copilot_config(config: &LlmConfig) -> anyhow::Result<()> {
    validate_backend_selection(config)?;

    let backend = normalized_backend(config);
    if backend != "copilot" {
        anyhow::bail!(
            "Hybrid benchmark runs require [llm].reasoning = \"copilot\", found {:?}",
            config.reasoning
        );
    }

    let decompilation = config.decompilation.trim().to_ascii_lowercase();
    if decompilation != "copilot" {
        anyhow::bail!(
            "Hybrid benchmark runs require [llm].decompilation = \"copilot\", found {:?}",
            config.decompilation
        );
    }

    let model = config.copilot.model.trim();
    if model.is_empty() || !model.to_ascii_lowercase().contains("opus") {
        anyhow::bail!(
            "Hybrid benchmark runs require an Opus-class Copilot model, found {:?}. \
             Set [llm.copilot].model = \"claude-opus-4.6\".",
            config.copilot.model
        );
    }

    Ok(())
}

pub async fn ensure_benchmark_copilot_ready(config: &LlmConfig) -> anyhow::Result<()> {
    validate_benchmark_copilot_config(config)?;
    create_client(config)
        .await
        .map(|_| ())
        .context(
            "Hybrid benchmark runs require working GitHub Copilot authentication. \
             Run `gh auth login` / `gh auth refresh --scopes copilot`, or set GH_TOKEN/GITHUB_TOKEN with Copilot access.",
        )
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

fn validate_backend_selection(config: &LlmConfig) -> anyhow::Result<()> {
    match normalized_backend(config).as_str() {
        "copilot" | "anthropic" => Ok(()),
        other => anyhow::bail!(
            "Unsupported llm.reasoning backend {:?}. Set [llm].reasoning explicitly to \"copilot\" or \"anthropic\"; hidden fallback is disabled.",
            if other.is_empty() { "<empty>" } else { other }
        ),
    }
}

fn normalized_backend(config: &LlmConfig) -> String {
    config.reasoning.trim().to_ascii_lowercase()
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

    #[test]
    fn test_validate_backend_selection_rejects_unknown_backend() {
        let config = LlmConfig {
            reasoning: "auto".into(),
            ..Default::default()
        };

        let err = validate_backend_selection(&config).unwrap_err();
        assert!(err
            .to_string()
            .contains("Unsupported llm.reasoning backend"));
        assert!(err.to_string().contains("hidden fallback is disabled"));
    }

    #[test]
    fn test_validate_benchmark_copilot_config_requires_copilot() {
        let config = LlmConfig {
            reasoning: "anthropic".into(),
            ..Default::default()
        };

        let err = validate_benchmark_copilot_config(&config).unwrap_err();
        assert!(err
            .to_string()
            .contains("require [llm].reasoning = \"copilot\""));
    }

    #[test]
    fn test_validate_benchmark_copilot_config_requires_opus_model() {
        let mut config = LlmConfig::default();
        config.copilot.model = "gpt-4o".into();

        let err = validate_benchmark_copilot_config(&config).unwrap_err();
        assert!(err.to_string().contains("Opus-class Copilot model"));
    }

    #[test]
    fn test_validate_benchmark_copilot_config_requires_copilot_decompilation() {
        let config = LlmConfig {
            decompilation: "anthropic".into(),
            ..Default::default()
        };

        let err = validate_benchmark_copilot_config(&config).unwrap_err();
        assert!(err
            .to_string()
            .contains("require [llm].decompilation = \"copilot\""));
    }
}
