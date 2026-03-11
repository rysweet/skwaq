//! Ollama LLM backend.
//!
//! Calls the local Ollama server at `/api/chat` with optional tool-calling
//! support. Streaming is disabled (`stream: false`) so we collect the full
//! response in one shot.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::traits::{LlmClient, LlmResponse, Message, TokenUsage, ToolCall, ToolDefinition};

/// Ollama chat API client.
pub struct OllamaClient {
    base_url: String,
    http: reqwest::Client,
}

// ── request types ────────────────────────────────────────────────

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OllamaTool>,
    stream: bool,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
struct OllamaTool {
    r#type: String,
    function: OllamaFunction,
}

#[derive(Serialize)]
struct OllamaFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

// ── response types ───────────────────────────────────────────────

#[derive(Deserialize)]
struct ChatResponse {
    message: ResponseMessage,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
}

#[derive(Deserialize)]
struct ResponseMessage {
    #[serde(default)]
    content: String,
    #[serde(default)]
    tool_calls: Vec<ResponseToolCall>,
}

#[derive(Deserialize)]
struct ResponseToolCall {
    function: ResponseFunction,
}

#[derive(Deserialize)]
struct ResponseFunction {
    name: String,
    arguments: serde_json::Value,
}

// ── implementation ───────────────────────────────────────────────

impl OllamaClient {
    /// Create a new Ollama client.
    ///
    /// `base_url` should be something like `http://localhost:11434`.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        model: &str,
    ) -> anyhow::Result<LlmResponse> {
        let chat_messages: Vec<ChatMessage> = messages
            .iter()
            .map(|m| ChatMessage {
                role: m.role.clone(),
                content: m.content.clone(),
                tool_call_id: m.tool_call_id.clone(),
            })
            .collect();

        let ollama_tools: Vec<OllamaTool> = tools
            .iter()
            .map(|t| OllamaTool {
                r#type: "function".into(),
                function: OllamaFunction {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    parameters: t.parameters.clone(),
                },
            })
            .collect();

        let body = ChatRequest {
            model: model.to_string(),
            messages: chat_messages,
            tools: ollama_tools,
            stream: false,
        };

        let url = format!("{}/api/chat", self.base_url);
        tracing::debug!("Ollama request -> {url} model={model}");

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Ollama request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama returned {status}: {text}");
        }

        let chat_resp: ChatResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse Ollama response: {e}"))?;

        let tool_calls: Vec<ToolCall> = chat_resp
            .message
            .tool_calls
            .into_iter()
            .enumerate()
            .map(|(i, tc)| ToolCall {
                id: format!("call_{i}"),
                name: tc.function.name,
                arguments: tc.function.arguments,
            })
            .collect();

        let content = if chat_resp.message.content.is_empty() {
            None
        } else {
            Some(chat_resp.message.content)
        };

        Ok(LlmResponse {
            content,
            tool_calls,
            usage: TokenUsage {
                input_tokens: chat_resp.prompt_eval_count.unwrap_or(0),
                output_tokens: chat_resp.eval_count.unwrap_or(0),
            },
        })
    }

    fn provider_name(&self) -> &str {
        "ollama"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_client_creation() {
        let client = OllamaClient::new("http://localhost:11434");
        assert_eq!(client.base_url, "http://localhost:11434");
        assert_eq!(client.provider_name(), "ollama");
    }

    #[test]
    fn test_trailing_slash_stripped() {
        let client = OllamaClient::new("http://localhost:11434/");
        assert_eq!(client.base_url, "http://localhost:11434");
    }

    #[test]
    fn test_parse_response_with_tool_calls() {
        let json = r#"{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "query_graph",
                            "arguments": {"cypher": "MATCH (f:Function) RETURN f.name LIMIT 5"}
                        }
                    }
                ]
            },
            "prompt_eval_count": 100,
            "eval_count": 50
        }"#;

        let resp: ChatResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.message.tool_calls.len(), 1);
        assert_eq!(resp.message.tool_calls[0].function.name, "query_graph");
        assert_eq!(resp.prompt_eval_count, Some(100));
        assert_eq!(resp.eval_count, Some(50));
    }

    #[test]
    fn test_parse_response_text_only() {
        let json = r#"{
            "message": {
                "role": "assistant",
                "content": "No vulnerabilities found."
            }
        }"#;

        let resp: ChatResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.message.content, "No vulnerabilities found.");
        assert!(resp.message.tool_calls.is_empty());
    }
}
