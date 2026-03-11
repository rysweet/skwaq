//! Agent discovery: find all available agent definition files.

use std::collections::HashMap;
use std::path::PathBuf;

use super::definition::{parse_agent_markdown, AgentDefinition};

/// Discover all available agent definitions.
///
/// Searches these directories (later entries override earlier ones for
/// agents with the same name):
/// 1. `agents/` (bundled defaults)
/// 2. `~/.skwaq/agents/` (user-global)
/// 3. `.skwaq/agents/` (project-local)
pub fn discover_agents() -> Vec<AgentDefinition> {
    let mut agents: HashMap<String, AgentDefinition> = HashMap::new();

    let mut dirs: Vec<PathBuf> = vec![PathBuf::from("agents")];
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join(".skwaq/agents"));
    }
    dirs.push(PathBuf::from(".skwaq/agents"));

    for dir in &dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to read agent file {}: {e}", path.display());
                    continue;
                }
            };
            match parse_agent_markdown(&content) {
                Ok(mut def) => {
                    def.source_path = Some(path);
                    agents.insert(def.name.clone(), def);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse agent file {}: {e}", entry.path().display());
                }
            }
        }
    }

    let mut result: Vec<AgentDefinition> = agents.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_returns_sorted() {
        // discover_agents should not panic even when directories don't exist
        let agents = discover_agents();
        // Verify sorting
        for w in agents.windows(2) {
            assert!(w[0].name <= w[1].name);
        }
    }
}
