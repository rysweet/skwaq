//! Anthropic Claude API backend.
//!
//! Calls the Anthropic Messages API at `https://api.anthropic.com/v1/messages`.
//! Authentication uses the `x-api-key` header with `ANTHROPIC_API_KEY` env var.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::traits::{LlmClient, LlmResponse, Message, TokenUsage, ToolCall, ToolDefinition};

/// Anthropic Messages API client.
#[derive(Debug)]
pub struct AnthropicClient {
    api_key: String,
    http: reqwest::Client,
}

// ── request types (Anthropic format) ──────────────────────────────

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<AnthropicTool>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: AnthropicContent,
}

/// Anthropic messages can have either a plain string or an array of content blocks.
#[derive(Serialize)]
#[serde(untagged)]
enum AnthropicContent {
    Text(String),
    Blocks(Vec<AnthropicContentBlock>),
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum AnthropicContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

#[derive(Serialize)]
struct AnthropicTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

// ── response types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ResponseContentBlock>,
    #[serde(default)]
    usage: Option<ResponseUsage>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ResponseContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[derive(Deserialize)]
struct ResponseUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

// ── implementation ────────────────────────────────────────────────

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 4096;

impl AnthropicClient {
    /// Create a new Anthropic client.
    ///
    /// Reads `ANTHROPIC_API_KEY` from the environment.
    pub fn new() -> anyhow::Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY not set"))?;
        Ok(Self {
            api_key,
            http: reqwest::Client::new(),
        })
    }

    /// Convert our internal messages to Anthropic format.
    ///
    /// Anthropic has a separate `system` field (not a message role), and tool
    /// results must be sent as content blocks inside a `user` role message.
    fn convert_messages(messages: &[Message]) -> (Option<String>, Vec<AnthropicMessage>) {
        let mut system_prompt = None;
        let mut anthropic_msgs: Vec<AnthropicMessage> = Vec::new();

        for msg in messages {
            match msg.role.as_str() {
                "system" => {
                    // Anthropic uses a top-level system field, not a message
                    system_prompt = Some(msg.content.clone());
                }
                "assistant" => {
                    // If the assistant made tool calls, we need to include them
                    // as content blocks alongside any text.
                    if let Some(tool_calls) = &msg.tool_calls {
                        let mut blocks: Vec<AnthropicContentBlock> = Vec::new();
                        if !msg.content.is_empty() {
                            blocks.push(AnthropicContentBlock::Text {
                                text: msg.content.clone(),
                            });
                        }
                        for tc in tool_calls {
                            blocks.push(AnthropicContentBlock::ToolUse {
                                id: tc.id.clone(),
                                name: tc.name.clone(),
                                input: tc.arguments.clone(),
                            });
                        }
                        anthropic_msgs.push(AnthropicMessage {
                            role: "assistant".into(),
                            content: AnthropicContent::Blocks(blocks),
                        });
                    } else {
                        anthropic_msgs.push(AnthropicMessage {
                            role: "assistant".into(),
                            content: AnthropicContent::Text(msg.content.clone()),
                        });
                    }
                }
                "tool" => {
                    // Anthropic tool results are user-role messages with
                    // tool_result content blocks. We batch consecutive tool
                    // results into a single user message.
                    let block = AnthropicContentBlock::ToolResult {
                        tool_use_id: msg.tool_call_id.clone().unwrap_or_default(),
                        content: msg.content.clone(),
                    };

                    // Try to merge into the last message if it's already a
                    // user-role message with tool_result blocks.
                    if let Some(last) = anthropic_msgs.last_mut() {
                        if last.role == "user" {
                            if let AnthropicContent::Blocks(ref mut blocks) = last.content {
                                if blocks
                                    .iter()
                                    .all(|b| matches!(b, AnthropicContentBlock::ToolResult { .. }))
                                {
                                    blocks.push(block);
                                    continue;
                                }
                            }
                        }
                    }
                    anthropic_msgs.push(AnthropicMessage {
                        role: "user".into(),
                        content: AnthropicContent::Blocks(vec![block]),
                    });
                }
                _ => {
                    // "user" and any other role
                    anthropic_msgs.push(AnthropicMessage {
                        role: msg.role.clone(),
                        content: AnthropicContent::Text(msg.content.clone()),
                    });
                }
            }
        }

        (system_prompt, anthropic_msgs)
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        model: &str,
    ) -> anyhow::Result<LlmResponse> {
        let (system_prompt, anthropic_messages) = Self::convert_messages(messages);

        let anthropic_tools: Vec<AnthropicTool> = tools
            .iter()
            .map(|t| AnthropicTool {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.parameters.clone(),
            })
            .collect();

        let body = MessagesRequest {
            model: model.to_string(),
            max_tokens: DEFAULT_MAX_TOKENS,
            system: system_prompt,
            messages: anthropic_messages,
            tools: anthropic_tools,
        };

        tracing::debug!("Anthropic request -> {ANTHROPIC_API_URL} model={model}");

        let resp = self
            .http
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Anthropic API request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let mut text = resp.text().await.unwrap_or_default();
            text.truncate(500);
            anyhow::bail!("Anthropic API returned {status}: {text}");
        }

        let msg_resp: MessagesResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse Anthropic response: {e}"))?;

        // Extract text content and tool_use blocks from the response
        let mut text_parts: Vec<String> = Vec::new();
        let mut tool_calls: Vec<ToolCall> = Vec::new();

        for block in msg_resp.content {
            match block {
                ResponseContentBlock::Text { text } => {
                    text_parts.push(text);
                }
                ResponseContentBlock::ToolUse { id, name, input } => {
                    tool_calls.push(ToolCall {
                        id,
                        name,
                        arguments: input,
                    });
                }
            }
        }

        let content = if text_parts.is_empty() {
            None
        } else {
            Some(text_parts.join(""))
        };

        let usage = msg_resp.usage.as_ref();
        Ok(LlmResponse {
            content,
            tool_calls,
            usage: TokenUsage {
                input_tokens: usage.map_or(0, |u| u.input_tokens),
                output_tokens: usage.map_or(0, |u| u.output_tokens),
            },
        })
    }

    fn provider_name(&self) -> &str {
        "anthropic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_client_creation_without_env() {
        // Remove the key if set, to test the error path
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::remove_var("ANTHROPIC_API_KEY");

        let result = AnthropicClient::new();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ANTHROPIC_API_KEY not set"));

        // Restore
        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }

    #[test]
    fn test_anthropic_client_creation_with_env() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "test-key-123");

        let client = AnthropicClient::new().unwrap();
        assert_eq!(client.provider_name(), "anthropic");
        assert_eq!(client.api_key, "test-key-123");

        // Restore
        match original {
            Some(key) => std::env::set_var("ANTHROPIC_API_KEY", key),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
    }

    #[test]
    fn test_convert_messages_extracts_system() {
        let messages = vec![
            Message::system("You are a security analyst."),
            Message::user("Find vulnerabilities."),
        ];

        let (system, msgs) = AnthropicClient::convert_messages(&messages);
        assert_eq!(system.as_deref(), Some("You are a security analyst."));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, "user");
    }

    #[test]
    fn test_convert_messages_tool_calls() {
        let tool_call = ToolCall {
            id: "call_1".into(),
            name: "query_graph".into(),
            arguments: serde_json::json!({"cypher": "MATCH (n) RETURN n"}),
        };
        let messages = vec![
            Message::system("System prompt"),
            Message::user("Analyze this"),
            Message::assistant_with_tool_calls(None, vec![tool_call]),
            Message::tool(r#"{"result": "ok"}"#, "call_1"),
        ];

        let (system, msgs) = AnthropicClient::convert_messages(&messages);
        assert!(system.is_some());
        // user + assistant + user(tool_result) = 3
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
        assert_eq!(msgs[2].role, "user"); // tool results become user role
    }

    #[test]
    fn test_convert_messages_consecutive_tool_results_merged() {
        let tc1 = ToolCall {
            id: "call_1".into(),
            name: "read_function".into(),
            arguments: serde_json::json!({"name": "main"}),
        };
        let tc2 = ToolCall {
            id: "call_2".into(),
            name: "get_callees".into(),
            arguments: serde_json::json!({"name": "main"}),
        };
        let messages = vec![
            Message::user("Do analysis"),
            Message::assistant_with_tool_calls(None, vec![tc1, tc2]),
            Message::tool("result1", "call_1"),
            Message::tool("result2", "call_2"),
        ];

        let (_system, msgs) = AnthropicClient::convert_messages(&messages);
        // user + assistant + user(with 2 tool_result blocks merged) = 3
        assert_eq!(msgs.len(), 3);
        // The last message should have 2 blocks
        if let AnthropicContent::Blocks(ref blocks) = msgs[2].content {
            assert_eq!(blocks.len(), 2);
        } else {
            panic!("Expected Blocks content for merged tool results");
        }
    }

    #[test]
    fn test_parse_text_response() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "No vulnerabilities found."}
            ],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 20
            }
        }"#;

        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ResponseContentBlock::Text { text } => {
                assert_eq!(text, "No vulnerabilities found.");
            }
            _ => panic!("Expected text block"),
        }
        assert_eq!(resp.usage.as_ref().unwrap().input_tokens, 100);
        assert_eq!(resp.usage.as_ref().unwrap().output_tokens, 20);
    }

    #[test]
    fn test_parse_tool_use_response() {
        let json = r#"{
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_abc123",
                    "name": "query_graph",
                    "input": {"cypher": "MATCH (f:Function) RETURN f.name LIMIT 5"}
                }
            ],
            "usage": {
                "input_tokens": 200,
                "output_tokens": 50
            }
        }"#;

        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ResponseContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_abc123");
                assert_eq!(name, "query_graph");
                assert!(input.get("cypher").is_some());
            }
            _ => panic!("Expected tool_use block"),
        }
    }

    #[test]
    fn test_parse_mixed_response() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "I'll query the graph."},
                {
                    "type": "tool_use",
                    "id": "toolu_xyz",
                    "name": "read_function",
                    "input": {"name": "parse_header"}
                }
            ],
            "usage": {
                "input_tokens": 150,
                "output_tokens": 40
            }
        }"#;

        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content.len(), 2);
    }

    #[test]
    fn test_tool_definition_conversion() {
        let tool = ToolDefinition {
            name: "query_graph".into(),
            description: "Run a Cypher query".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "cypher": {"type": "string"}
                },
                "required": ["cypher"]
            }),
        };

        let anthropic_tool = AnthropicTool {
            name: tool.name.clone(),
            description: tool.description.clone(),
            input_schema: tool.parameters.clone(),
        };

        let json = serde_json::to_value(&anthropic_tool).unwrap();
        assert!(json.get("input_schema").is_some());
        assert!(json.get("parameters").is_none()); // Should NOT have parameters key
        assert_eq!(json["name"], "query_graph");
    }

    #[test]
    fn test_request_serialization() {
        let req = MessagesRequest {
            model: "claude-opus-4-6".into(),
            max_tokens: 4096,
            system: Some("You are helpful.".into()),
            messages: vec![AnthropicMessage {
                role: "user".into(),
                content: AnthropicContent::Text("Hello".into()),
            }],
            tools: vec![],
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "claude-opus-4-6");
        assert_eq!(json["max_tokens"], 4096);
        assert_eq!(json["system"], "You are helpful.");
        assert!(json.get("tools").is_none()); // Empty tools should be skipped
    }
}
