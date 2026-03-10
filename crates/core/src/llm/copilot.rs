//! GitHub Copilot / Models API LLM backend using RustyClawd for token discovery.
//!
//! Uses `rustyclawd_core::client::copilot::get_github_token()` to find a
//! GitHub token from multiple sources (env var, gh CLI, config files), then
//! negotiates the endpoint (Copilot API with GitHub Models API fallback)
//! and sends OpenAI-compatible chat completion requests.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use super::traits::{LlmClient, LlmResponse, Message, ToolCall, ToolDefinition, TokenUsage};

const COPILOT_MODELS_URL: &str = "https://api.githubcopilot.com/models";
const COPILOT_CHAT_URL: &str = "https://api.githubcopilot.com/chat/completions";
// Kept for potential future use in model listing
#[allow(dead_code)]
const GITHUB_MODELS_LIST_URL: &str = "https://models.github.ai/inference/models";
const GITHUB_MODELS_CHAT_URL: &str = "https://models.github.ai/inference/chat/completions";
const GITHUB_MODELS_PREFIX: &str = "openai/";

/// Which API endpoint is active.
#[derive(Debug, Clone, Copy)]
enum Endpoint {
    Copilot,
    GitHubModels,
}

/// Cached auth state: token + validated endpoint.
struct AuthState {
    token: String,
    endpoint: Endpoint,
}

impl AuthState {
    fn chat_url(&self) -> &str {
        match self.endpoint {
            Endpoint::Copilot => COPILOT_CHAT_URL,
            Endpoint::GitHubModels => GITHUB_MODELS_CHAT_URL,
        }
    }

    fn qualify_model(&self, model: &str) -> String {
        match self.endpoint {
            Endpoint::Copilot => {
                // Copilot API wants bare model names (e.g., "gpt-4o-mini")
                model
                    .strip_prefix(GITHUB_MODELS_PREFIX)
                    .unwrap_or(model)
                    .to_string()
            }
            Endpoint::GitHubModels => {
                // GitHub Models API wants prefixed names (e.g., "openai/gpt-4o-mini")
                if model.contains('/') {
                    model.to_string()
                } else {
                    format!("{GITHUB_MODELS_PREFIX}{model}")
                }
            }
        }
    }
}

/// GitHub Copilot / Models API chat completions client.
///
/// On first use, discovers a GitHub token via RustyClawd and validates
/// against the Copilot API (falling back to GitHub Models API).
pub struct CopilotClient {
    http: reqwest::Client,
    auth: OnceCell<AuthState>,
}

// ── request types (OpenAI-compatible) ────────────────────────────

#[derive(Serialize)]
struct CompletionsRequest {
    model: String,
    messages: Vec<CompletionsMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<CompletionsTool>,
}

#[derive(Serialize)]
struct CompletionsMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<CompletionsToolCall>>,
}

/// Tool call as sent in assistant messages.
#[derive(Serialize)]
struct CompletionsToolCall {
    id: String,
    r#type: String,
    function: CompletionsToolCallFunction,
}

#[derive(Serialize)]
struct CompletionsToolCallFunction {
    name: String,
    arguments: String,
}

#[derive(Serialize)]
struct CompletionsTool {
    r#type: String,
    function: CompletionsFunction,
}

#[derive(Serialize)]
struct CompletionsFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

// ── response types ───────────────────────────────────────────────

#[derive(Deserialize)]
struct CompletionsResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<UsageInfo>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ResponseToolCall>,
}

#[derive(Deserialize)]
struct ResponseToolCall {
    id: String,
    function: ResponseFunction,
}

#[derive(Deserialize)]
struct ResponseFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct UsageInfo {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

// ── implementation ───────────────────────────────────────────────

impl Default for CopilotClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CopilotClient {
    /// Create a new CopilotClient.
    ///
    /// Authentication and endpoint negotiation are deferred to the first call.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            auth: OnceCell::new(),
        }
    }

    /// Lazily discover and validate auth.
    ///
    /// Uses RustyClawd's `get_github_token()` to find a token, then validates
    /// with a minimal chat request to the GitHub Models API. Falls back to
    /// the Copilot API if the Models API is unavailable.
    async fn ensure_auth(&self) -> anyhow::Result<&AuthState> {
        self.auth
            .get_or_try_init(|| async {
                // Use RustyClawd to discover the GitHub token
                let token = rustyclawd_core::client::copilot::get_github_token()
                    .await
                    .map_err(|e| anyhow::anyhow!("GitHub token discovery failed: {e}"))?;

                // Validate with a minimal chat request to GitHub Models API.
                // The models list endpoint may return 404 even when chat works,
                // so we probe the chat endpoint directly.
                let probe_body = serde_json::json!({
                    "model": "openai/gpt-4o-mini",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 1
                });

                let models_resp = self
                    .http
                    .post(GITHUB_MODELS_CHAT_URL)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .json(&probe_body)
                    .send()
                    .await;

                let models_ok = models_resp
                    .as_ref()
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);

                if models_ok {
                    tracing::info!("Authenticated via GitHub Models API");
                    return Ok(AuthState {
                        token,
                        endpoint: Endpoint::GitHubModels,
                    });
                }

                // Log the failure details
                if let Ok(resp) = models_resp {
                    let status = resp.status();
                    tracing::debug!(
                        "GitHub Models API probe returned {status}, trying Copilot API"
                    );
                }

                // Fall back: check Copilot API models list
                let copilot_ok = self
                    .http
                    .get(COPILOT_MODELS_URL)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Accept", "application/json")
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);

                if copilot_ok {
                    tracing::info!("Authenticated via Copilot API");
                    return Ok(AuthState {
                        token,
                        endpoint: Endpoint::Copilot,
                    });
                }

                anyhow::bail!(
                    "Neither GitHub Models API nor Copilot API accepted the token. \
                     Ensure you have access and run: gh auth login"
                );
            })
            .await
    }
}

#[async_trait]
impl LlmClient for CopilotClient {
    async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        model: &str,
    ) -> anyhow::Result<LlmResponse> {
        let auth = self.ensure_auth().await?;
        let chat_url = auth.chat_url();
        let qualified_model = auth.qualify_model(model);

        let chat_messages: Vec<CompletionsMessage> = messages
            .iter()
            .map(|m| {
                // Convert tool_calls from our ToolCall format to the API format
                let api_tool_calls = m.tool_calls.as_ref().map(|calls| {
                    calls
                        .iter()
                        .map(|tc| CompletionsToolCall {
                            id: tc.id.clone(),
                            r#type: "function".into(),
                            function: CompletionsToolCallFunction {
                                name: tc.name.clone(),
                                arguments: tc.arguments.to_string(),
                            },
                        })
                        .collect()
                });

                // For assistant messages with tool_calls, content should be
                // null (not empty string) per OpenAI API spec
                let content = if m.role == "assistant" && api_tool_calls.is_some() && m.content.is_empty() {
                    None
                } else {
                    Some(m.content.clone())
                };

                CompletionsMessage {
                    role: m.role.clone(),
                    content,
                    tool_call_id: m.tool_call_id.clone(),
                    tool_calls: api_tool_calls,
                }
            })
            .collect();

        let copilot_tools: Vec<CompletionsTool> = tools
            .iter()
            .map(|t| CompletionsTool {
                r#type: "function".into(),
                function: CompletionsFunction {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    parameters: t.parameters.clone(),
                },
            })
            .collect();

        let body = CompletionsRequest {
            model: qualified_model.clone(),
            messages: chat_messages,
            tools: copilot_tools,
        };

        tracing::debug!("Copilot request -> {chat_url} model={qualified_model}");

        let resp = self
            .http
            .post(chat_url)
            .header("Authorization", format!("Bearer {}", auth.token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Copilot API request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let mut text = resp.text().await.unwrap_or_default();
            text.truncate(500);
            anyhow::bail!("Copilot API returned {status}: {text}");
        }

        let comp_resp: CompletionsResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse Copilot API response: {e}"))?;

        let choice = comp_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Copilot API returned no choices"))?;

        let tool_calls: Vec<ToolCall> = choice
            .message
            .tool_calls
            .into_iter()
            .map(|tc| {
                let arguments: serde_json::Value =
                    serde_json::from_str(&tc.function.arguments)
                        .unwrap_or(serde_json::Value::Null);
                ToolCall {
                    id: tc.id,
                    name: tc.function.name,
                    arguments,
                }
            })
            .collect();

        let usage = comp_resp.usage.as_ref();
        Ok(LlmResponse {
            content: choice.message.content,
            tool_calls,
            usage: TokenUsage {
                input_tokens: usage.map_or(0, |u| u.prompt_tokens),
                output_tokens: usage.map_or(0, |u| u.completion_tokens),
            },
        })
    }

    fn provider_name(&self) -> &str {
        "copilot"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copilot_client_creation() {
        let client = CopilotClient::new();
        assert_eq!(client.provider_name(), "copilot");
    }

    #[test]
    fn test_parse_completions_response() {
        let json = r#"{
            "choices": [{
                "message": {
                    "content": "Found a buffer overflow in parse_header.",
                    "tool_calls": []
                }
            }],
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 120
            }
        }"#;

        let resp: CompletionsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.choices.len(), 1);
        assert_eq!(
            resp.choices[0].message.content.as_deref(),
            Some("Found a buffer overflow in parse_header.")
        );
        assert_eq!(resp.usage.as_ref().unwrap().prompt_tokens, 500);
    }

    #[test]
    fn test_parse_response_with_tool_calls() {
        let json = r#"{
            "choices": [{
                "message": {
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_abc123",
                            "function": {
                                "name": "read_function",
                                "arguments": "{\"name\": \"parse_header\"}"
                            }
                        }
                    ]
                }
            }],
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 50
            }
        }"#;

        let resp: CompletionsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.choices[0].message.tool_calls.len(), 1);
        assert_eq!(resp.choices[0].message.tool_calls[0].id, "call_abc123");
        assert_eq!(
            resp.choices[0].message.tool_calls[0].function.name,
            "read_function"
        );
    }

    #[test]
    fn test_auth_state_qualify_model_copilot() {
        let auth = AuthState {
            token: "test".into(),
            endpoint: Endpoint::Copilot,
        };
        assert_eq!(auth.qualify_model("gpt-4o"), "gpt-4o");
        // Copilot strips the openai/ prefix
        assert_eq!(auth.qualify_model("openai/gpt-4o"), "gpt-4o");
    }

    #[test]
    fn test_auth_state_qualify_model_github_models() {
        let auth = AuthState {
            token: "test".into(),
            endpoint: Endpoint::GitHubModels,
        };
        assert_eq!(auth.qualify_model("gpt-4o"), "openai/gpt-4o");
        assert_eq!(auth.qualify_model("openai/gpt-4o"), "openai/gpt-4o");
    }
}
