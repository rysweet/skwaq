use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum SkwaqError {
    #[error("{tool} not found. {install_hint}")]
    ToolNotFound { tool: String, install_hint: String },

    #[error("{tool} timed out after {timeout:?}")]
    ToolTimeout { tool: String, timeout: Duration },

    #[error("{tool} failed: {message}")]
    ToolFailed { tool: String, message: String },

    #[error("LLM error ({provider}): {message}")]
    LlmError { provider: String, message: String },

    #[error("Token budget exhausted ({used}/{limit} tokens)")]
    BudgetExhausted { used: u64, limit: u64 },

    #[error("Graph error: {0}")]
    GraphError(String),

    #[error("Binary parse error: {0}")]
    BinaryError(String),

    #[error("Investigation not found: {0}")]
    InvestigationNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}
