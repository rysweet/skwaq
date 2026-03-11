//! GitHub Copilot / Models API LLM backend using RustyClawd for token discovery.
//!
//! Split into submodules:
//! - `copilot_auth`: authentication state, endpoint probing, token caching
//! - `copilot_client`: CopilotClient struct and LlmClient implementation

pub(crate) const COPILOT_MODELS_URL: &str = "https://api.githubcopilot.com/models";
pub(crate) const COPILOT_CHAT_URL: &str = "https://api.githubcopilot.com/chat/completions";
pub(crate) const GITHUB_MODELS_CHAT_URL: &str =
    "https://models.github.ai/inference/chat/completions";
pub(crate) const GITHUB_MODELS_PREFIX: &str = "openai/";
