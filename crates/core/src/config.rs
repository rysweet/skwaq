use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub binary: BinaryConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_database_path")]
    pub database_path: String,
    #[serde(default = "default_cache_path")]
    pub cache_path: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    #[serde(default = "default_llm_backend")]
    pub reasoning: String,
    #[serde(default = "default_llm_backend")]
    pub decompilation: String,
    #[serde(default = "default_ollama")]
    pub embeddings: String,
    #[serde(default)]
    pub copilot: CopilotConfig,
    #[serde(default)]
    pub ollama: OllamaConfig,
    #[serde(default)]
    pub azure: AzureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotConfig {
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            model: default_model(),
            endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    #[serde(default = "default_ollama_host")]
    pub host: String,
    #[serde(default = "default_ollama_model")]
    pub model: String,
    #[serde(default = "default_embedding_model")]
    pub embedding_model: String,
}

/// Azure OpenAI configuration for Azure AI Foundry deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    /// Azure AI Services endpoint (e.g. "https://xxx.cognitiveservices.azure.com/")
    #[serde(default)]
    pub endpoint: String,
    /// Model deployment name(s). Comma-separated for round-robin load balancing
    /// across multiple deployments (e.g. "gpt-54-skwaq,gpt-54-skwaq-2,gpt-54-skwaq-3").
    #[serde(default)]
    pub deployment: String,
    /// Azure OpenAI API version
    #[serde(default = "default_azure_api_version")]
    pub api_version: String,
    /// API key (optional; if unset, uses AZURE_OPENAI_API_KEY env or bearer token)
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for AzureConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            deployment: String::new(),
            api_version: default_azure_api_version(),
            api_key: None,
        }
    }
}

fn default_azure_api_version() -> String {
    "2024-10-21".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryConfig {
    #[serde(default)]
    pub ghidra_path: String,
    #[serde(default = "default_timeout")]
    pub default_timeout: u64,
    #[serde(default = "default_true")]
    pub enable_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    #[serde(default = "default_taint_depth")]
    pub max_taint_depth: u32,
    #[serde(default = "default_fp_target")]
    pub false_positive_target: f64,
    #[serde(default = "default_token_budget")]
    pub default_token_budget: u64,
    /// Confidence threshold below which findings are rejected (0-100).
    /// Findings with confidence < this value are dropped entirely.
    #[serde(default = "default_confidence_reject_threshold")]
    pub confidence_reject_threshold: u8,
    /// Confidence threshold below which finding severity is downgraded (0-100).
    /// Findings with confidence >= reject but < this value have severity reduced.
    #[serde(default = "default_confidence_downgrade_threshold")]
    pub confidence_downgrade_threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub default_format: String,
}

fn default_database_path() -> String {
    ".skwaq/graph".into()
}
fn default_cache_path() -> String {
    ".skwaq/cache".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_llm_backend() -> String {
    "copilot".into()
}
fn default_ollama() -> String {
    "ollama".into()
}
fn default_model() -> String {
    "claude-opus-4.6".into()
}
fn default_ollama_host() -> String {
    "http://localhost:11434".into()
}
fn default_ollama_model() -> String {
    "llama3.1".into()
}
fn default_embedding_model() -> String {
    "nomic-embed-text".into()
}
fn default_timeout() -> u64 {
    600
}
fn default_true() -> bool {
    true
}
fn default_taint_depth() -> u32 {
    15
}
fn default_fp_target() -> f64 {
    0.15
}
fn default_token_budget() -> u64 {
    250_000
}
fn default_confidence_reject_threshold() -> u8 {
    25
}
fn default_confidence_downgrade_threshold() -> u8 {
    55
}
fn default_format() -> String {
    "text".into()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            database_path: default_database_path(),
            cache_path: default_cache_path(),
            log_level: default_log_level(),
        }
    }
}

impl LlmConfig {
    /// Replace this LLM config with the overlay's values.
    ///
    /// Used by the profile system to apply a profile's [llm] section
    /// over the base config. All fields are replaced wholesale.
    pub fn merge_overlay(&mut self, overlay: LlmConfig) {
        *self = overlay;
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            reasoning: default_llm_backend(),
            decompilation: default_llm_backend(),
            embeddings: default_ollama(),
            copilot: CopilotConfig::default(),
            ollama: OllamaConfig::default(),
            azure: AzureConfig::default(),
        }
    }
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            host: default_ollama_host(),
            model: default_ollama_model(),
            embedding_model: default_embedding_model(),
        }
    }
}

impl Default for BinaryConfig {
    fn default() -> Self {
        Self {
            ghidra_path: String::new(),
            default_timeout: default_timeout(),
            enable_cache: true,
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_taint_depth: default_taint_depth(),
            false_positive_target: default_fp_target(),
            default_token_budget: default_token_budget(),
            confidence_reject_threshold: default_confidence_reject_threshold(),
            confidence_downgrade_threshold: default_confidence_downgrade_threshold(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            default_format: default_format(),
        }
    }
}

/// Observability configuration for OpenTelemetry export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// OTLP gRPC endpoint (e.g. "http://localhost:4317"). When set, spans are
    /// exported via OTLP in addition to the local JSONL file.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Azure Monitor connection string. When set, spans are exported to
    /// Application Insights.
    #[serde(default)]
    pub azure_monitor_connection_string: Option<String>,
    /// Local telemetry directory. Defaults to ~/.skwaq/telemetry.
    #[serde(default = "default_telemetry_dir")]
    pub telemetry_dir: String,
}

fn default_telemetry_dir() -> String {
    "~/.skwaq/telemetry".into()
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            azure_monitor_connection_string: None,
            telemetry_dir: default_telemetry_dir(),
        }
    }
}

// Config derives Default since all fields implement Default.

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_dir(PathBuf::from("."))
    }

    pub fn load_from_dir(dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let config_path = Self::find_config_file_from(dir.into());
        match config_path {
            Some(path) => {
                let content = std::fs::read_to_string(&path)?;
                let config: Config = toml::from_str(&content)?;
                Ok(config)
            }
            None => Ok(Config::default()),
        }
    }

    fn find_config_file_from(dir: PathBuf) -> Option<PathBuf> {
        // Check the requested directory first, then home.
        let candidates = [
            dir.join("skwaq.toml"),
            dir.join(".skwaq/config.toml"),
            dirs::home_dir()?.join(".skwaq/config.toml"),
        ];
        candidates.into_iter().find(|p| p.exists())
    }

    pub fn database_path(&self) -> PathBuf {
        PathBuf::from(&self.general.database_path)
    }

    pub fn cache_path(&self) -> PathBuf {
        PathBuf::from(&self.general.cache_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_llm_backend_stays_copilot_even_with_anthropic_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-test-key-123");

        assert_eq!(default_llm_backend(), "copilot");
        let config = LlmConfig::default();
        assert_eq!(config.reasoning, "copilot");
        assert_eq!(config.decompilation, "copilot");

        match original {
            Some(key) => std::env::set_var("ANTHROPIC_API_KEY", key),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
    }

    #[test]
    fn test_load_from_dir_reads_requested_root_config() {
        let temp = tempdir().unwrap();
        let repo = temp.path().join("repo");
        let nested = repo.join("nested");
        std::fs::create_dir_all(&nested).unwrap();

        std::fs::write(
            repo.join("skwaq.toml"),
            r#"
[general]
log_level = "warn"

[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = "https://example.cognitiveservices.azure.com/"
deployment = "gpt-54"
"#,
        )
        .unwrap();

        std::fs::write(
            nested.join("skwaq.toml"),
            r#"
[general]
log_level = "debug"
"#,
        )
        .unwrap();

        let config = Config::load_from_dir(&repo).unwrap();
        assert_eq!(config.general.log_level, "warn");
        assert_eq!(config.llm.reasoning, "azure");

        let nested_config = Config::load_from_dir(&nested).unwrap();
        assert_eq!(nested_config.general.log_level, "debug");
    }
}
