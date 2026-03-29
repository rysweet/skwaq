//! Cost estimation for LLM API usage based on model-specific token pricing.

/// Per-token pricing for a known model (USD per token).
struct ModelPricing {
    input_per_token: f64,
    output_per_token: f64,
}

/// Estimate the cost in USD for a given model and token counts.
///
/// Returns 0.0 for unknown models.
pub fn estimate_cost(model: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    let pricing = match model_pricing(model) {
        Some(p) => p,
        None => return 0.0,
    };
    prompt_tokens as f64 * pricing.input_per_token
        + completion_tokens as f64 * pricing.output_per_token
}

/// Format a USD cost for display. Shows 4 decimal places for sub-dollar amounts.
pub fn format_cost(usd: f64) -> String {
    if usd < 0.01 {
        format!("${:.4}", usd)
    } else if usd < 1.0 {
        format!("${:.3}", usd)
    } else {
        format!("${:.2}", usd)
    }
}

fn model_pricing(model: &str) -> Option<ModelPricing> {
    let m = model.to_lowercase();
    // Anthropic models
    if m.contains("opus") {
        return Some(ModelPricing {
            input_per_token: 15.0 / 1_000_000.0,
            output_per_token: 75.0 / 1_000_000.0,
        });
    }
    if m.contains("sonnet") {
        return Some(ModelPricing {
            input_per_token: 3.0 / 1_000_000.0,
            output_per_token: 15.0 / 1_000_000.0,
        });
    }
    if m.contains("haiku") {
        return Some(ModelPricing {
            input_per_token: 0.25 / 1_000_000.0,
            output_per_token: 1.25 / 1_000_000.0,
        });
    }
    // OpenAI / Azure models
    if m.contains("gpt-5.4") || m.contains("gpt-54") || m.contains("gpt-4o") {
        return Some(ModelPricing {
            input_per_token: 2.50 / 1_000_000.0,
            output_per_token: 10.0 / 1_000_000.0,
        });
    }
    if m.contains("gpt-5.1") || m.contains("gpt-51") || m.contains("gpt-4o-mini") {
        return Some(ModelPricing {
            input_per_token: 0.15 / 1_000_000.0,
            output_per_token: 0.60 / 1_000_000.0,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_cost_opus() {
        let cost = estimate_cost("claude-opus-4.6", 1_000_000, 1_000_000);
        assert!((cost - 90.0).abs() < 0.01, "opus cost: {cost}");
    }

    #[test]
    fn test_estimate_cost_sonnet() {
        let cost = estimate_cost("claude-sonnet-4.6", 1_000_000, 1_000_000);
        assert!((cost - 18.0).abs() < 0.01, "sonnet cost: {cost}");
    }

    #[test]
    fn test_estimate_cost_gpt54() {
        let cost = estimate_cost("gpt-5.4", 1_000_000, 1_000_000);
        assert!((cost - 12.5).abs() < 0.01, "gpt-5.4 cost: {cost}");
    }

    #[test]
    fn test_estimate_cost_unknown() {
        assert_eq!(estimate_cost("unknown-model", 1000, 1000), 0.0);
    }

    #[test]
    fn test_format_cost() {
        assert_eq!(format_cost(0.001), "$0.0010");
        assert_eq!(format_cost(0.05), "$0.050");
        assert_eq!(format_cost(1.5), "$1.50");
    }
}
