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
/// - `"azure"` -- Azure AI Foundry via `DefaultAzureCredential`.
///
/// Any other value is rejected. skwaq does not silently switch providers.
pub async fn create_client(config: &LlmConfig) -> anyhow::Result<Client> {
    create_reasoning_client(config).await
}

/// Create a client for reasoning stages using `[llm].reasoning`.
pub async fn create_reasoning_client(config: &LlmConfig) -> anyhow::Result<Client> {
    create_client_for_backend(config, config.reasoning.trim(), "llm.reasoning").await
}

/// Create a client for decompilation stages using `[llm].decompilation`.
pub async fn create_decompilation_client(config: &LlmConfig) -> anyhow::Result<Client> {
    create_client_for_backend(config, config.decompilation.trim(), "llm.decompilation").await
}

/// Create the clients needed by the agent pipeline.
///
/// When reasoning and decompilation use the same backend, the client is created
/// once and cloned so the pipeline reuses the same authenticated session.
pub async fn create_pipeline_clients(
    config: &LlmConfig,
    require_reasoning: bool,
    require_decompilation: bool,
) -> anyhow::Result<(Option<Client>, Option<Client>)> {
    if !require_reasoning && !require_decompilation {
        return Ok((None, None));
    }

    let reasoning_backend = if require_reasoning {
        Some(validate_backend_name(
            config.reasoning.trim(),
            "llm.reasoning",
        )?)
    } else {
        None
    };
    let decompilation_backend = if require_decompilation {
        Some(validate_backend_name(
            config.decompilation.trim(),
            "llm.decompilation",
        )?)
    } else {
        None
    };

    if let (Some(reasoning_backend), Some(decompilation_backend)) =
        (&reasoning_backend, &decompilation_backend)
    {
        if reasoning_backend == decompilation_backend {
            let client =
                create_client_for_backend_name(config, reasoning_backend, "llm.reasoning").await?;
            return Ok((Some(client.clone()), Some(client)));
        }
    }

    let reasoning = match reasoning_backend {
        Some(backend) => {
            Some(create_client_for_backend_name(config, &backend, "llm.reasoning").await?)
        }
        None => None,
    };
    let decompilation = match decompilation_backend {
        Some(backend) => {
            Some(create_client_for_backend_name(config, &backend, "llm.decompilation").await?)
        }
        None => None,
    };

    Ok((reasoning, decompilation))
}

async fn create_client_for_backend(
    config: &LlmConfig,
    raw_backend: &str,
    field_name: &str,
) -> anyhow::Result<Client> {
    let backend = validate_backend_name(raw_backend, field_name)?;
    create_client_for_backend_name(config, &backend, field_name).await
}

async fn create_client_for_backend_name(
    config: &LlmConfig,
    backend: &str,
    field_name: &str,
) -> anyhow::Result<Client> {
    match backend {
        "copilot" => {
            let client = Client::new_copilot().await.map_err(|e| {
                anyhow::anyhow!("Failed to create Copilot client for {field_name}: {e}")
            })?;
            Ok(client)
        }
        "anthropic" => create_anthropic_client(),
        "azure" => {
            let azure = &config.azure;
            anyhow::ensure!(
                !azure.endpoint.is_empty(),
                "Azure backend selected for {field_name} but [llm.azure] endpoint is not set"
            );
            anyhow::ensure!(
                !azure.deployment.is_empty(),
                "Azure backend selected for {field_name} but [llm.azure] deployment is not set"
            );
            // If api_key is set in config, inject it as env var for RustyClawd's AzureAuth
            if let Some(ref key) = azure.api_key {
                std::env::set_var("AZURE_OPENAI_API_KEY", key);
            }
            let client =
                Client::new_azure_foundry(&azure.endpoint, &azure.deployment, &azure.api_version)
                    .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to create Azure AI Foundry client for {field_name}: {e}"
                    )
                })?;
            Ok(client)
        }
        _ => unreachable!("validate_backend_name rejected unsupported backends"),
    }
}

pub fn validate_benchmark_copilot_config(config: &LlmConfig) -> anyhow::Result<()> {
    validate_benchmark_copilot_config_for_pipeline(config, true, true)
}

pub async fn ensure_benchmark_copilot_ready(config: &LlmConfig) -> anyhow::Result<()> {
    ensure_benchmark_copilot_ready_for_pipeline(config, true, true).await
}

pub fn validate_benchmark_copilot_config_for_pipeline(
    config: &LlmConfig,
    require_reasoning: bool,
    require_decompilation: bool,
) -> anyhow::Result<()> {
    let allowed = ["copilot", "azure"];
    if require_reasoning {
        let backend = validate_backend_name(config.reasoning.trim(), "llm.reasoning")?;
        if !allowed.contains(&backend.as_str()) {
            anyhow::bail!(
                "Benchmark runs require [llm].reasoning = \"copilot\" or \"azure\", found {:?}",
                config.reasoning
            );
        }
    }

    if require_decompilation {
        let decompilation =
            validate_backend_name(config.decompilation.trim(), "llm.decompilation")?;
        if !allowed.contains(&decompilation.as_str()) {
            anyhow::bail!(
                "Benchmark runs require [llm].decompilation = \"copilot\" or \"azure\", found {:?}",
                config.decompilation
            );
        }
    }

    // Model validation only applies to copilot backend
    let reasoning_backend =
        validate_backend_name(config.reasoning.trim(), "llm.reasoning").unwrap_or_default();
    if reasoning_backend == "copilot" && (require_reasoning || require_decompilation) {
        let model = config.copilot.model.trim();
        if model.is_empty() || !model.to_ascii_lowercase().contains("opus") {
            anyhow::bail!(
                "Copilot benchmark runs require an Opus-class model, found {:?}. \
                 Set [llm.copilot].model = \"claude-opus-4.6\".",
                config.copilot.model
            );
        }
    }

    Ok(())
}

pub async fn ensure_benchmark_copilot_ready_for_pipeline(
    config: &LlmConfig,
    require_reasoning: bool,
    require_decompilation: bool,
) -> anyhow::Result<()> {
    validate_benchmark_copilot_config_for_pipeline(
        config,
        require_reasoning,
        require_decompilation,
    )?;
    let _ = create_pipeline_clients(config, require_reasoning, require_decompilation)
        .await
        .context(
            "Benchmark runs require working LLM authentication. \
         For copilot: `gh auth login` / `gh auth refresh --scopes copilot`. \
         For azure: set AZURE_OPENAI_API_KEY or run `az login`.",
        )?;
    Ok(())
}

/// Build an Anthropic-backend client from the environment key.
fn create_anthropic_client() -> anyhow::Result<Client> {
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

fn validate_backend_name(raw_backend: &str, field_name: &str) -> anyhow::Result<String> {
    let backend = raw_backend.trim().to_ascii_lowercase();
    if !matches!(backend.as_str(), "copilot" | "anthropic" | "azure") {
        let display = if backend.is_empty() {
            "<empty>"
        } else {
            backend.as_str()
        };
        anyhow::bail!(
            "Unsupported {} backend {:?}. Set {} explicitly to \"copilot\", \"anthropic\", or \"azure\"; hidden fallback is disabled.",
            field_name,
            display,
            field_name
        );
    }
    Ok(backend)
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
        let _ = config;
        let result = create_anthropic_client();
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

        let result = create_anthropic_client();
        assert!(result.is_err());

        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }

    #[test]
    fn test_validate_backend_selection_rejects_unknown_backend() {
        let err = validate_backend_name("auto", "llm.reasoning").unwrap_err();
        assert!(err
            .to_string()
            .contains("Unsupported llm.reasoning backend"));
        assert!(err.to_string().contains("hidden fallback is disabled"));
    }

    #[test]
    fn test_validate_backend_name_rejects_unknown_decompilation_backend() {
        let err = validate_backend_name("auto", "llm.decompilation").unwrap_err();
        assert!(err
            .to_string()
            .contains("Unsupported llm.decompilation backend"));
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
            .contains("require [llm].reasoning = \"copilot\" or \"azure\""));
    }

    #[test]
    fn test_validate_benchmark_copilot_config_requires_opus_model() {
        let mut config = LlmConfig::default();
        config.copilot.model = "gpt-4o".into();

        let err = validate_benchmark_copilot_config(&config).unwrap_err();
        assert!(err.to_string().contains("Opus-class model"));
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
            .contains("require [llm].decompilation = \"copilot\" or \"azure\""));
    }

    #[tokio::test]
    async fn test_create_pipeline_clients_rejects_invalid_decompilation_backend() {
        let config = LlmConfig {
            decompilation: "auto".into(),
            ..Default::default()
        };

        let err = create_pipeline_clients(&config, false, true)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("Unsupported llm.decompilation backend"));
    }

    #[tokio::test]
    async fn test_create_pipeline_clients_allows_reasoning_only_pipelines() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-test-key-123");

        let config = LlmConfig {
            reasoning: "anthropic".into(),
            decompilation: "auto".into(),
            ..Default::default()
        };

        let (reasoning, decompilation) = create_pipeline_clients(&config, true, false)
            .await
            .expect("reasoning-only pipelines should not validate llm.decompilation");
        assert!(reasoning.is_some());
        assert!(decompilation.is_none());

        match original {
            Some(key) => std::env::set_var("ANTHROPIC_API_KEY", key),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
    }
}
