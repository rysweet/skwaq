//! MCP (Model Context Protocol) client for connecting AI agents to external
//! tool servers like GhidraMCP.
//!
//! MCP servers expose tools via JSON-RPC over stdio. This module provides
//! the types and connection logic for agents to call MCP tools alongside
//! built-in tools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

/// An MCP tool definition received from a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// An active connection to an MCP server process.
pub struct McpConnection {
    child: Option<Child>,
    reader: Option<BufReader<tokio::process::ChildStdout>>,
    request_id: u64,
}

impl McpConnection {
    /// Start an MCP server process and establish connection.
    ///
    /// The server is expected to communicate via JSON-RPC over stdin/stdout.
    pub async fn start(command: &str, args: &[&str]) -> anyhow::Result<Self> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to start MCP server '{}': {}. \
                     Ensure the server is installed and in PATH.",
                    command,
                    e
                )
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("MCP server stdout not available"))?;
        let reader = BufReader::new(stdout);

        let mut conn = Self {
            child: Some(child),
            reader: Some(reader),
            request_id: 0,
        };

        // Initialize the MCP connection
        conn.send_request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "skwaq",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
        .await?;

        // Send initialized notification
        conn.send_notification("notifications/initialized", serde_json::json!({}))
            .await?;

        Ok(conn)
    }

    /// List available tools from the server.
    pub async fn list_tools(&mut self) -> anyhow::Result<Vec<McpToolDef>> {
        let response = self
            .send_request("tools/list", serde_json::json!({}))
            .await?;

        let tools = response
            .get("tools")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| {
                        Some(McpToolDef {
                            name: t.get("name")?.as_str()?.to_string(),
                            description: t
                                .get("description")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            input_schema: t
                                .get("inputSchema")
                                .cloned()
                                .unwrap_or(serde_json::json!({})),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(tools)
    }

    /// Call a tool on the MCP server.
    pub async fn call_tool(
        &mut self,
        name: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self
            .send_request(
                "tools/call",
                serde_json::json!({
                    "name": name,
                    "arguments": args
                }),
            )
            .await?;

        // Extract content from MCP response
        if let Some(content) = response.get("content") {
            if let Some(arr) = content.as_array() {
                let text: Vec<&str> = arr
                    .iter()
                    .filter_map(|c| c.get("text").and_then(|v| v.as_str()))
                    .collect();
                return Ok(serde_json::json!({
                    "status": "ok",
                    "result": text.join("\n")
                }));
            }
        }

        Ok(response)
    }

    /// Send a JSON-RPC request and wait for response.
    async fn send_request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.request_id += 1;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        });

        let child = self
            .child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MCP server not running"))?;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MCP server stdin not available"))?;

        let msg = serde_json::to_string(&request)?;
        stdin.write_all(msg.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;

        // Read response from stored reader (preserves buffer across calls)
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MCP server stdout not available"))?;
        let mut line = String::new();

        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            reader.read_line(&mut line),
        )
        .await
        {
            Ok(Ok(0)) => anyhow::bail!("MCP server closed connection"),
            Ok(Ok(_)) => {
                let response: serde_json::Value = serde_json::from_str(line.trim())?;
                if let Some(error) = response.get("error") {
                    anyhow::bail!("MCP error: {}", error);
                }
                Ok(response
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::json!({})))
            }
            Ok(Err(e)) => anyhow::bail!("Failed to read from MCP server: {}", e),
            Err(_) => anyhow::bail!("MCP server response timed out (30s)"),
        }
    }

    /// Send a JSON-RPC notification (no response expected).
    async fn send_notification(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<()> {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });

        if let Some(child) = self.child.as_mut() {
            if let Some(stdin) = child.stdin.as_mut() {
                let msg = serde_json::to_string(&notification)?;
                stdin.write_all(msg.as_bytes()).await?;
                stdin.write_all(b"\n").await?;
                stdin.flush().await?;
            }
        }

        Ok(())
    }

    /// Shut down the MCP server.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        let _ = self.send_request("shutdown", serde_json::json!({})).await;
        if let Some(mut child) = self.child.take() {
            child.kill().await.ok();
        }
        Ok(())
    }
}

impl Drop for McpConnection {
    fn drop(&mut self) {
        // Best-effort kill on drop — take() avoids needing a placeholder
        if let Some(mut child) = self.child.take() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    child.kill().await.ok();
                });
            }
        }
    }
}

/// Registry of known MCP servers and how to start them.
pub struct McpServerRegistry {
    servers: HashMap<String, McpServerConfig>,
}

/// Configuration for starting an MCP server.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    /// Display name.
    pub name: String,
    /// Command to start the server.
    pub command: String,
    /// Arguments to the command.
    pub args: Vec<String>,
    /// Tools this server provides.
    pub tools: Vec<String>,
}

impl Default for McpServerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl McpServerRegistry {
    pub fn new() -> Self {
        let mut servers = HashMap::new();

        // GhidraMCP - the primary reverse engineering MCP server
        servers.insert(
            "ghidra".to_string(),
            McpServerConfig {
                name: "GhidraMCP".to_string(),
                command: "ghidra-mcp-server".to_string(),
                args: vec![],
                tools: vec![
                    "ghidra_decompile".to_string(),
                    "ghidra_rename".to_string(),
                    "ghidra_set_type".to_string(),
                    "ghidra_get_xrefs".to_string(),
                    "ghidra_search_strings".to_string(),
                    "ghidra_get_segments".to_string(),
                ],
            },
        );

        Self { servers }
    }

    /// Check if a tool name belongs to an MCP server.
    pub fn find_server_for_tool(&self, tool_name: &str) -> Option<&McpServerConfig> {
        self.servers
            .values()
            .find(|s| s.tools.contains(&tool_name.to_string()))
    }

    /// Check if a named server is available (command exists on PATH).
    pub fn is_server_available(&self, server_name: &str) -> bool {
        if let Some(config) = self.servers.get(server_name) {
            std::process::Command::new("which")
                .arg(&config.command)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Get all registered servers.
    pub fn all_servers(&self) -> impl Iterator<Item = (&String, &McpServerConfig)> {
        self.servers.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_server_registry_default() {
        let registry = McpServerRegistry::new();
        assert!(registry.servers.contains_key("ghidra"));
    }

    #[test]
    fn test_find_server_for_tool() {
        let registry = McpServerRegistry::new();
        let server = registry.find_server_for_tool("ghidra_decompile");
        assert!(server.is_some());
        assert_eq!(server.unwrap().name, "GhidraMCP");
    }

    #[test]
    fn test_find_server_for_unknown_tool() {
        let registry = McpServerRegistry::new();
        assert!(registry.find_server_for_tool("unknown_tool").is_none());
    }
}
