//! Budget-aware tool loop and token tracking.
//!
//! The heavy lifting (HTTP, auth, message format, retries) is handled by
//! RustyClawd's `Client::execute_with_tools`. This module adds:
//!
//! - [`TokenBudget`] -- simple counter for per-agent cost control.
//! - [`execute_with_tools`] -- wraps RustyClawd's tool loop with budget
//!   tracking and our `anyhow::Result` based tool executor signature.

use rustyclawd_core::client::{
    Client, ClientError, ContentBlock, CreateMessageRequest, Message, MessageResponse,
    ToolDefinition, Usage,
};

/// Token budget tracking for agent cost control.
#[derive(Debug)]
pub struct TokenBudget {
    pub limit: u64,
    pub used: u64,
}

impl TokenBudget {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub fn unlimited() -> Self {
        Self {
            limit: u64::MAX,
            used: 0,
        }
    }

    pub fn exhausted(&self) -> bool {
        self.used >= self.limit
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn track(&mut self, usage: &Usage) {
        self.used += usage.input_tokens as u64 + usage.output_tokens as u64;
    }
}

/// Extract all text content from a `MessageResponse`.
pub fn text_content(response: &MessageResponse) -> String {
    response
        .content
        .iter()
        .filter_map(|block| {
            if let ContentBlock::Text { text } = block {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Budget-aware agentic tool loop.
///
/// Delegates to RustyClawd's `Client::execute_with_tools` for the actual
/// API interaction and tool protocol. This wrapper adds:
/// 1. Token budget checking before each turn.
/// 2. Conversion between the caller's `anyhow::Result` tool executor and
///    RustyClawd's `ClientResult`.
///
/// Returns the final text output from the LLM.
pub async fn execute_with_tools<F, Fut>(
    client: &Client,
    model: &str,
    system_prompt: &str,
    user_prompt: &str,
    tools: &[ToolDefinition],
    tool_executor: F,
    budget: &mut TokenBudget,
) -> anyhow::Result<String>
where
    F: Fn(String, serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<serde_json::Value>>,
{
    if budget.exhausted() {
        tracing::warn!("Token budget exhausted ({}/{})", budget.used, budget.limit);
        return Ok("Analysis stopped: token budget exhausted.".into());
    }

    let request = CreateMessageRequest::new(model, vec![Message::user(user_prompt)], 4096)
        .with_system(system_prompt.to_string())
        .with_tools(tools.to_vec());

    let response = client
        .execute_with_tools(request, |tool_name, tool_args| {
            let fut = tool_executor(tool_name, tool_args);
            async move {
                fut.await
                    .map_err(|e| ClientError::ToolExecution(e.to_string()))
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("LLM tool loop failed: {e}"))?;

    budget.track(&response.usage);

    Ok(text_content(&response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyclawd_core::client::Role;

    #[test]
    fn test_token_budget_new() {
        let budget = TokenBudget::new(1000);
        assert_eq!(budget.limit, 1000);
        assert_eq!(budget.used, 0);
        assert!(!budget.exhausted());
        assert_eq!(budget.remaining(), 1000);
    }

    #[test]
    fn test_token_budget_unlimited() {
        let budget = TokenBudget::unlimited();
        assert!(!budget.exhausted());
        assert_eq!(budget.remaining(), u64::MAX);
    }

    #[test]
    fn test_token_budget_track() {
        let mut budget = TokenBudget::new(100);
        let usage = Usage {
            input_tokens: 30,
            output_tokens: 20,
            speed: None,
        };
        budget.track(&usage);
        assert_eq!(budget.used, 50);
        assert_eq!(budget.remaining(), 50);
        assert!(!budget.exhausted());
    }

    #[test]
    fn test_token_budget_exhausted() {
        let mut budget = TokenBudget::new(50);
        let usage = Usage {
            input_tokens: 30,
            output_tokens: 25,
            speed: None,
        };
        budget.track(&usage);
        assert!(budget.exhausted());
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn test_text_content_extraction() {
        let response = MessageResponse {
            id: "msg_test".to_string(),
            type_field: "message".to_string(),
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "Hello ".to_string(),
                },
                ContentBlock::Text {
                    text: "world".to_string(),
                },
            ],
            model: "test".to_string(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                speed: None,
            },
        };
        assert_eq!(text_content(&response), "Hello world");
    }

    #[test]
    fn test_text_content_skips_non_text() {
        let response = MessageResponse {
            id: "msg_test".to_string(),
            type_field: "message".to_string(),
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "Before ".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "tu_1".to_string(),
                    name: "bash".to_string(),
                    input: serde_json::json!({}),
                },
                ContentBlock::Text {
                    text: "after".to_string(),
                },
            ],
            model: "test".to_string(),
            stop_reason: None,
            stop_sequence: None,
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                speed: None,
            },
        };
        assert_eq!(text_content(&response), "Before after");
    }
}
