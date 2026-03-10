//! GitHub Copilot LLM backend.
//!
//! Authenticates via `gh auth token` (or GITHUB_TOKEN env var), exchanges
//! the GitHub token for a Copilot session token, then calls the
//! OpenAI-compatible chat completions endpoint at api.githubcopilot.com.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use super::traits::{LlmClient, LlmResponse, Message, ToolCall, ToolDefinition, TokenUsage};

/// GitHub Copilot chat completions client.
pub struct CopilotClient {
    http: reqwest::Client,
    /// Cached Copilot token + expiry.
    token_cache: Mutex<Option<CopilotToken>>,
}

#[derive(Clone)]
struct CopilotToken {
    token: String,
    expires_at: i64,
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
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
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

/// Token exchange response from GitHub.
#[derive(Deserialize)]
struct TokenExchangeResponse {
    token: String,
    expires_at: i64,
}

// ── implementation ───────────────────────────────────────────────

impl Default for CopilotClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CopilotClient {
    /// Create a new Copilot client.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            token_cache: Mutex::new(None),
        }
    }

    /// Obtain a GitHub personal access token from the environment or `gh` CLI.
    fn github_token() -> anyhow::Result<String> {
        // Try GITHUB_TOKEN env var first
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if !token.is_empty() {
                return Ok(token);
            }
        }

        // Fall back to `gh auth token`
        let output = std::process::Command::new("gh")
            .args(["auth", "token"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run `gh auth token`: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "gh auth token failed (exit {}): {stderr}",
                output.status.code().unwrap_or(-1)
            );
        }

        let token = String::from_utf8(output.stdout)
            .map_err(|_| anyhow::anyhow!("gh auth token returned non-UTF-8"))?
            .trim()
            .to_string();

        if token.is_empty() {
            anyhow::bail!("No GitHub token available. Set GITHUB_TOKEN or run `gh auth login`.");
        }

        Ok(token)
    }

    /// Exchange a GitHub PAT for a Copilot session token.
    async fn exchange_token(&self) -> anyhow::Result<CopilotToken> {
        // Return cached token if still valid
        if let Ok(guard) = self.token_cache.lock() {
            if let Some(ref cached) = *guard {
                let now = chrono::Utc::now().timestamp();
                if cached.expires_at > now + 60 {
                    return Ok(cached.clone());
                }
            }
        }

        let gh_token = Self::github_token()?;

        let resp = self
            .http
            .get("https://api.github.com/copilot_internal/v2/token")
            .header("Authorization", format!("token {gh_token}"))
            .header("User-Agent", "skwaq/0.1")
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Copilot token exchange failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let mut text = resp.text().await.unwrap_or_default();
            text.truncate(200);
            anyhow::bail!("Copilot token exchange returned {status}: {text}");
        }

        let exchange: TokenExchangeResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse token exchange response: {e}"))?;

        let copilot_token = CopilotToken {
            token: exchange.token,
            expires_at: exchange.expires_at,
        };

        // Cache it
        if let Ok(mut guard) = self.token_cache.lock() {
            *guard = Some(copilot_token.clone());
        }

        Ok(copilot_token)
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
        let copilot_token = self.exchange_token().await?;

        let chat_messages: Vec<CompletionsMessage> = messages
            .iter()
            .map(|m| CompletionsMessage {
                role: m.role.clone(),
                content: m.content.clone(),
                tool_call_id: m.tool_call_id.clone(),
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
            model: model.to_string(),
            messages: chat_messages,
            tools: copilot_tools,
        };

        tracing::debug!("Copilot request -> chat/completions model={model}");

        let resp = self
            .http
            .post("https://api.githubcopilot.com/chat/completions")
            .header("Authorization", format!("Bearer {}", copilot_token.token))
            .header("Content-Type", "application/json")
            .header("Editor-Version", "skwaq/0.1")
            .header("Copilot-Integration-Id", "skwaq")
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Copilot chat request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let mut text = resp.text().await.unwrap_or_default();
            text.truncate(200);
            anyhow::bail!("Copilot chat returned {status}: {text}");
        }

        let comp_resp: CompletionsResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse Copilot response: {e}"))?;

        let choice = comp_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Copilot returned no choices"))?;

        let tool_calls: Vec<ToolCall> = choice
            .message
            .tool_calls
            .into_iter()
            .map(|tc| {
                let arguments: serde_json::Value =
                    serde_json::from_str(&tc.function.arguments).unwrap_or(serde_json::Value::Null);
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
}
