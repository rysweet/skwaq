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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotConfig {
    #[serde(default = "default_model")]
    pub model: String,
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            model: default_model(),
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

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            reasoning: default_llm_backend(),
            decompilation: default_llm_backend(),
            embeddings: default_ollama(),
            copilot: CopilotConfig::default(),
            ollama: OllamaConfig::default(),
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

// Config derives Default since all fields implement Default.

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = Self::find_config_file();
        match config_path {
            Some(path) => {
                let content = std::fs::read_to_string(&path)?;
                let config: Config = toml::from_str(&content)?;
                Ok(config)
            }
            None => Ok(Config::default()),
        }
    }

    fn find_config_file() -> Option<PathBuf> {
        // Check current directory first, then home
        let candidates = [
            PathBuf::from("skwaq.toml"),
            PathBuf::from(".skwaq/config.toml"),
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
}
