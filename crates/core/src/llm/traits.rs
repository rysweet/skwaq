use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(content: &str) -> Self {
        Self { role: "system".into(), content: content.into(), tool_call_id: None }
    }
    pub fn user(content: &str) -> Self {
        Self { role: "user".into(), content: content.into(), tool_call_id: None }
    }
    pub fn tool(content: &str, tool_call_id: &str) -> Self {
        Self { role: "tool".into(), content: content.into(), tool_call_id: Some(tool_call_id.into()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug)]
pub struct LlmResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

#[derive(Debug, Default, Clone)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn chat(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        model: &str,
    ) -> anyhow::Result<LlmResponse>;

    fn provider_name(&self) -> &str;
}

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
        Self { limit: u64::MAX, used: 0 }
    }

    pub fn exhausted(&self) -> bool {
        self.used >= self.limit
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn track(&mut self, usage: &TokenUsage) {
        self.used += usage.input_tokens + usage.output_tokens;
    }
}

/// The core agentic tool loop.
///
/// LLM requests tool calls -> we execute them -> feed results back -> repeat
/// until LLM returns a text response or budget is exhausted.
pub async fn execute_with_tools<F, Fut>(
    client: &dyn LlmClient,
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
    let mut messages = vec![
        Message::system(system_prompt),
        Message::user(user_prompt),
    ];

    let max_turns = 50; // Safety limit
    for _ in 0..max_turns {
        if budget.exhausted() {
            tracing::warn!("Token budget exhausted ({}/{})", budget.used, budget.limit);
            return Ok("Analysis stopped: token budget exhausted.".into());
        }

        let response = client.chat(&messages, tools, model).await?;
        budget.track(&response.usage);

        if response.tool_calls.is_empty() {
            return Ok(response.content.unwrap_or_default());
        }

        // Record assistant message
        messages.push(Message {
            role: "assistant".into(),
            content: response.content.clone().unwrap_or_default(),
            tool_call_id: None,
        });

        // Execute each tool call
        for call in &response.tool_calls {
            tracing::debug!("Tool call: {} args={}", call.name, call.arguments);
            let result = tool_executor(call.name.clone(), call.arguments.clone()).await?;
            messages.push(Message::tool(
                &serde_json::to_string(&result)?,
                &call.id,
            ));
        }
    }

    Ok("Analysis stopped: maximum turns reached.".into())
}
