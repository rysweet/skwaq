//! SubprocessTool trait and helper for running external tools with
//! health checks, timeouts, and cleanup.

use async_trait::async_trait;
#[cfg(target_os = "linux")]
use std::collections::{HashSet, VecDeque};
#[cfg(not(unix))]
use std::io;
#[cfg(unix)]
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
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
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.kill_on_drop(true);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("{tool_name} not found or failed to start: {e}"))?;
    let child_pid = child.id();

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("{tool_name} stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("{tool_name} stderr was not captured"))?;

    let stdout_task = tokio::spawn(read_stream(stdout));
    let stderr_task = tokio::spawn(read_stream(stderr));

    match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            let stdout = stdout_task.await??;
            let stderr = stderr_task.await??;
            if status.success() {
                Ok(ToolOutput {
                    stdout: String::from_utf8_lossy(&stdout).to_string(),
                    stderr: String::from_utf8_lossy(&stderr).to_string(),
                })
            } else {
                let stderr = String::from_utf8_lossy(&stderr);
                anyhow::bail!("{tool_name} failed (exit {status}): {stderr}")
            }
        }
        Ok(Err(e)) => {
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            anyhow::bail!("{tool_name} execution failed: {e}")
        }
        Err(_) => {
            if let Some(pid) = child_pid {
                kill_process(pid, &mut child).await;
            } else {
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            if let Some(dir) = temp_dir {
                let _ = tokio::fs::remove_dir_all(dir).await;
            }
            anyhow::bail!("{tool_name} timed out after {timeout_duration:?}")
        }
    }
}

async fn read_stream<R>(mut reader: R) -> io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    Ok(buf)
}

#[cfg(unix)]
async fn kill_process(pid: u32, child: &mut tokio::process::Child) {
    let pid = pid as i32;
    #[cfg(target_os = "linux")]
    let descendants = descendant_pids(pid);
    let pgid = -pid;
    // SAFETY: `kill` is called with a PID/PGID from a child process we spawned.
    unsafe {
        libc::kill(pgid, libc::SIGKILL);
    }
    #[cfg(target_os = "linux")]
    for descendant in descendants {
        // SAFETY: descendants are discovered from the spawned child's `/proc`
        // process tree immediately before termination.
        unsafe {
            libc::kill(descendant, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[cfg(not(unix))]
async fn kill_process(_pid: u32, child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
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

#[cfg(target_os = "linux")]
fn descendant_pids(root_pid: i32) -> Vec<i32> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root_pid]);
    let mut descendants = Vec::new();

    while let Some(pid) = queue.pop_front() {
        let children_path = format!("/proc/{pid}/task/{pid}/children");
        let Ok(children) = std::fs::read_to_string(children_path) else {
            continue;
        };
        for child_pid in children
            .split_whitespace()
            .filter_map(|entry| entry.parse::<i32>().ok())
        {
            if seen.insert(child_pid) {
                descendants.push(child_pid);
                queue.push_back(child_pid);
            }
        }
    }

    descendants
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_run_tool_timeout_kills_process_group() {
        let temp = tempdir().unwrap();
        let child_survived_file = temp.path().join("child-survived");

        let mut cmd = Command::new("bash");
        cmd.arg("-lc").arg(format!(
            "(sleep 1; echo survived > '{}') & wait",
            child_survived_file.display()
        ));

        let err = run_tool(&mut cmd, "timeout-test", Duration::from_millis(500), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"));

        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !child_survived_file.exists(),
            "timed-out child process should not still be running long enough to write output"
        );
    }
}
