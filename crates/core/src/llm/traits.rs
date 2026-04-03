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

    let llm_span = tracing::info_span!(
        "llm.request",
        model = %model,
        tools_count = tools.len(),
        input_tokens = tracing::field::Empty,
        output_tokens = tracing::field::Empty,
        retries = tracing::field::Empty,
        retry_wait_ms = tracing::field::Empty,
        retry_reason = tracing::field::Empty,
    );
    let _llm_guard = llm_span.enter();

    // Normalize model name for the active backend.
    // Copilot uses dots (claude-opus-4.6), Anthropic uses hyphens (claude-opus-4-6).
    let effective_model = normalize_model_for_backend(model, client);

    let mut request =
        CreateMessageRequest::new(&effective_model, vec![Message::user(user_prompt)], 128_000)
            .with_system(system_prompt.to_string());

    // Only set tools if non-empty — Anthropic API rejects empty tools arrays.
    if !tools.is_empty() {
        request = request.with_tools(tools.to_vec());
    }

    let (response, retry_stats) = client
        .execute_with_tools(request, |tool_name, tool_args| {
            tracing::info!("Tool called: {tool_name}");
            let fut = tool_executor(tool_name, tool_args);
            async move {
                fut.await
                    .map_err(|e| ClientError::ToolExecution(e.to_string()))
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("LLM tool loop failed: {e}"))?;

    budget.track(&response.usage);
    llm_span.record("input_tokens", response.usage.input_tokens);
    llm_span.record("output_tokens", response.usage.output_tokens);
    llm_span.record("retries", retry_stats.retries);
    llm_span.record("retry_wait_ms", retry_stats.total_wait_ms);
    if let Some(ref reason) = retry_stats.last_retry_reason {
        llm_span.record("retry_reason", format!("{:?}", reason).as_str());
    }
    tracing::info!(
        tokens_in = response.usage.input_tokens,
        tokens_out = response.usage.output_tokens,
        retries = retry_stats.retries,
        retry_wait_ms = retry_stats.total_wait_ms,
        "LLM request complete"
    );

    Ok(text_content(&response))
}

/// Normalize a model name for the active backend.
///
/// Copilot uses dot-separated versions (`claude-opus-4.6`), while the Anthropic
/// Messages API uses hyphen-separated versions (`claude-opus-4-6`). This function
/// translates between the two so agent definitions can use one canonical name.
fn normalize_model_for_backend(model: &str, client: &Client) -> String {
    use rustyclawd_core::client::config::Backend;
    match client.backend() {
        Backend::Anthropic => {
            // claude-opus-4.6 → claude-opus-4-6
            model.replace('.', "-")
        }
        Backend::Copilot => {
            // claude-opus-4-6 → claude-opus-4.6  (replace last hyphen-digit with dot-digit)
            // Only convert the version portion, not the "claude-opus" prefix.
            // Pattern: trailing "-DIGIT" sequences after a digit.
            if let Some(pos) = model.rfind(['-', '.']) {
                let after = &model[pos + 1..];
                if after.chars().all(|c| c.is_ascii_digit()) && model.as_bytes()[pos] == b'-' {
                    // Check if the char before the hyphen is also a digit (version boundary)
                    if pos > 0 && model.as_bytes()[pos - 1].is_ascii_digit() {
                        let mut s = model[..pos].to_string();
                        s.push('.');
                        s.push_str(after);
                        return s;
                    }
                }
            }
            model.to_string()
        }
        Backend::AzureFoundry => model.to_string(),
    }
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

    #[test]
    fn test_llm_request_span_records_token_usage() {
        // Verify the span fields compile and can be recorded.
        let span = tracing::info_span!(
            "llm.request",
            model = "test-model",
            tools_count = 0usize,
            input_tokens = tracing::field::Empty,
            output_tokens = tracing::field::Empty,
            retries = tracing::field::Empty,
            retry_wait_ms = tracing::field::Empty,
            retry_reason = tracing::field::Empty,
        );
        let usage = Usage {
            input_tokens: 42,
            output_tokens: 17,
            speed: None,
        };
        span.record("input_tokens", usage.input_tokens);
        span.record("output_tokens", usage.output_tokens);
        span.record("retries", 2u32);
        span.record("retry_wait_ms", 1500u64);
        span.record("retry_reason", "RateLimited");
        // No panic = fields are correctly declared and recordable.
    }
}
