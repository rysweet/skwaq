//! Authentication and endpoint negotiation for GitHub Copilot / Models API.

use super::copilot::{
    COPILOT_CHAT_URL, COPILOT_MODELS_URL, GITHUB_MODELS_CHAT_URL, GITHUB_MODELS_PREFIX,
};

/// Which API endpoint is active.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Endpoint {
    Copilot,
    GitHubModels,
}

/// Cached auth state: token + validated endpoint.
pub(crate) struct AuthState {
    pub token: String,
    pub endpoint: Endpoint,
}

impl AuthState {
    pub fn chat_url(&self) -> &str {
        match self.endpoint {
            Endpoint::Copilot => COPILOT_CHAT_URL,
            Endpoint::GitHubModels => GITHUB_MODELS_CHAT_URL,
        }
    }

    pub fn qualify_model(&self, model: &str) -> String {
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

/// Discover and validate auth. Uses RustyClawd's `get_github_token()` to find
/// a token, then validates with a minimal chat request to the GitHub Models API.
/// Falls back to the Copilot API if the Models API is unavailable.
pub(crate) async fn ensure_auth(http: &reqwest::Client) -> anyhow::Result<AuthState> {
    // Use RustyClawd to discover the GitHub token
    let token = rustyclawd_core::client::copilot::get_github_token()
        .await
        .map_err(|e| anyhow::anyhow!("GitHub token discovery failed: {e}"))?;

    // Validate with a minimal chat request to GitHub Models API.
    let probe_body = serde_json::json!({
        "model": "openai/gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1
    });

    let models_resp = http
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
        tracing::debug!("GitHub Models API probe returned {status}, trying Copilot API");
    }

    // Fall back: check Copilot API models list
    let copilot_ok = http
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
