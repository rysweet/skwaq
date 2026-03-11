//! SubprocessTool trait and helper for running external tools with
//! health checks, timeouts, and cleanup.

use async_trait::async_trait;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Every external tool (Ghidra, angr, Semgrep) implements this trait.
#[async_trait]
pub trait SubprocessTool: Send + Sync {
    fn name(&self) -> &str;
    async fn health_check(&self) -> ToolHealth;
    fn min_version(&self) -> Option<&str> {
        None
    }
    fn default_timeout(&self) -> Duration;
    fn install_hint(&self) -> &str;
}

/// Result of a health check on an external tool.
#[derive(Debug, Clone)]
pub struct ToolHealth {
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub error: Option<String>,
}

/// Output from a subprocess execution.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Run a subprocess with timeout, output capture, and cleanup.
pub async fn run_tool(
    cmd: &mut Command,
    tool_name: &str,
    timeout_duration: Duration,
    temp_dir: Option<&Path>,
) -> anyhow::Result<ToolOutput> {
    let result = timeout(timeout_duration, cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                Ok(ToolOutput {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                })
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("{tool_name} failed (exit {}): {stderr}", output.status)
            }
        }
        Ok(Err(e)) => {
            anyhow::bail!("{tool_name} not found or failed to start: {e}")
        }
        Err(_) => {
            if let Some(dir) = temp_dir {
                let _ = tokio::fs::remove_dir_all(dir).await;
            }
            anyhow::bail!("{tool_name} timed out after {timeout_duration:?}")
        }
    }
}

/// Check if a command exists on PATH.
///
/// Returns the canonicalized absolute path to the command if found.
/// The result is resolved via `canonicalize` to prevent symlink-based
/// PATH hijacking - the caller can verify the resolved path is in
/// an expected location (e.g. /usr/bin, /usr/local/bin).
pub async fn command_exists(cmd: &str) -> Option<String> {
    let result = Command::new("which").arg(cmd).output().await.ok()?;

    if result.status.success() {
        let raw_path = String::from_utf8_lossy(&result.stdout).trim().to_string();
        // Canonicalize to resolve symlinks and detect PATH manipulation.
        match std::fs::canonicalize(&raw_path) {
            Ok(canonical) => Some(canonical.to_string_lossy().to_string()),
            Err(_) => {
                // If canonicalize fails, return the raw path but log a warning.
                tracing::warn!(
                    "Could not canonicalize path for '{}': {}. \
                     Verify the tool is installed in a trusted location.",
                    cmd,
                    raw_path,
                );
                Some(raw_path)
            }
        }
    } else {
        None
    }
}

/// Get version string from a command.
pub async fn get_version(cmd: &str, args: &[&str]) -> Option<String> {
    let result = Command::new(cmd).args(args).output().await.ok()?;

    if result.status.success() {
        let output = String::from_utf8_lossy(&result.stdout);
        // Take first line, trim
        Some(output.lines().next().unwrap_or("").trim().to_string())
    } else {
        None
    }
}
