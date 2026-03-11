//! Semgrep integration for static analysis rule scanning.
//!
//! `SemgrepRunner` implements [`SubprocessTool`] so it can be
//! health-checked and executed with standard timeout handling.

use async_trait::async_trait;
use std::time::Duration;

use crate::binary::subprocess::{command_exists, get_version, SubprocessTool, ToolHealth};

/// Runs Semgrep static analysis as a subprocess.
pub struct SemgrepRunner {
    timeout: Duration,
}

impl Default for SemgrepRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SemgrepRunner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300),
        }
    }
}

#[async_trait]
impl SubprocessTool for SemgrepRunner {
    fn name(&self) -> &str {
        "semgrep"
    }

    async fn health_check(&self) -> ToolHealth {
        let path = command_exists("semgrep").await;
        let version = get_version("semgrep", &["--version"]).await;
        ToolHealth {
            available: path.is_some(),
            version,
            path,
            error: None,
        }
    }

    fn default_timeout(&self) -> Duration {
        self.timeout
    }

    fn install_hint(&self) -> &str {
        "Install Semgrep: pip install semgrep  (or see https://semgrep.dev)"
    }
}
