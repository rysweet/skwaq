//! Agent definition parsing: load agent markdown files with YAML frontmatter.

use std::path::PathBuf;

use serde::Deserialize;

/// An agent definition loaded from a markdown file.
#[derive(Debug, Clone)]
pub struct AgentDefinition {
    /// Unique agent name (matches the filename without `.md`).
    pub name: String,
    /// Human-readable description of what this agent does.
    pub description: String,
    /// LLM model identifier (e.g. `claude-opus-4.6`).
    pub model: String,
    /// List of tool names this agent is allowed to call.
    pub tools: Vec<String>,
    /// Maximum number of LLM turns before stopping.
    pub max_turns: u32,
    /// The system prompt (markdown body after the frontmatter).
    pub system_prompt: String,
    /// Path the definition was loaded from (for diagnostics).
    pub source_path: Option<PathBuf>,
}

/// YAML frontmatter structure inside agent markdown files.
#[derive(Debug, Deserialize)]
struct AgentFrontmatter {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_model")]
    model: String,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default = "default_max_turns")]
    max_turns: u32,
}

fn default_model() -> String {
    "claude-opus-4.6".into()
}

fn default_max_turns() -> u32 {
    30
}

/// Load an agent definition by name.
///
/// Search order:
/// 1. `.skwaq/agents/{name}.md` (project-local)
/// 2. `~/.skwaq/agents/{name}.md` (user-global)
/// 3. `agents/{name}.md` (bundled defaults in repo root)
pub fn load_agent(name: &str) -> anyhow::Result<AgentDefinition> {
    let filename = format!("{name}.md");

    let candidates: Vec<PathBuf> = {
        let mut c = vec![
            PathBuf::from(".skwaq/agents").join(&filename),
            PathBuf::from("agents").join(&filename),
        ];
        if let Some(home) = dirs::home_dir() {
            // Insert home path between project-local and bundled
            c.insert(1, home.join(".skwaq/agents").join(&filename));
        }
        c
    };

    for path in &candidates {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let mut def = parse_agent_markdown(&content)?;
            def.source_path = Some(path.clone());
            return Ok(def);
        }
    }

    anyhow::bail!(
        "Agent '{}' not found. Searched:\n{}",
        name,
        candidates
            .iter()
            .map(|p| format!("  - {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Parse a markdown file with YAML frontmatter into an AgentDefinition.
///
/// Expected format:
/// ```text
/// ---
/// name: agent-name
/// description: What this agent does
/// model: claude-opus-4.6
/// tools:
///   - tool_a
///   - tool_b
/// max_turns: 30
/// ---
///
/// System prompt body here...
/// ```
pub fn parse_agent_markdown(content: &str) -> anyhow::Result<AgentDefinition> {
    let content = content.trim();

    if !content.starts_with("---") {
        anyhow::bail!("Agent markdown must start with YAML frontmatter (---)");
    }

    // Find the closing --- delimiter
    let rest = &content[3..];
    let end = rest
        .find("\n---")
        .ok_or_else(|| anyhow::anyhow!("Missing closing --- in YAML frontmatter"))?;

    let yaml_str = &rest[..end];
    let body = rest[end + 4..].trim();

    let fm: AgentFrontmatter = serde_yaml_ng::from_str(yaml_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse agent frontmatter: {e}"))?;

    Ok(AgentDefinition {
        name: fm.name,
        description: fm.description,
        model: fm.model,
        tools: fm.tools,
        max_turns: fm.max_turns,
        system_prompt: body.to_string(),
        source_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_agent_markdown() {
        let md = r#"---
name: test-agent
description: A test agent
model: claude-opus-4.6
tools:
  - query_graph
  - read_function
max_turns: 10
---

You are a test agent. Do testing things."#;

        let def = parse_agent_markdown(md).unwrap();
        assert_eq!(def.name, "test-agent");
        assert_eq!(def.description, "A test agent");
        assert_eq!(def.model, "claude-opus-4.6");
        assert_eq!(def.tools, vec!["query_graph", "read_function"]);
        assert_eq!(def.max_turns, 10);
        assert!(def.system_prompt.contains("test agent"));
    }

    #[test]
    fn test_parse_missing_frontmatter() {
        let md = "Just some text without frontmatter";
        assert!(parse_agent_markdown(md).is_err());
    }

    #[test]
    fn test_parse_missing_closing_delimiter() {
        let md = "---\nname: broken\n\nNo closing delimiter";
        assert!(parse_agent_markdown(md).is_err());
    }

    #[test]
    fn test_parse_defaults() {
        let md = r#"---
name: minimal
---

Minimal agent."#;

        let def = parse_agent_markdown(md).unwrap();
        assert_eq!(def.name, "minimal");
        assert_eq!(def.model, "claude-opus-4.6");
        assert_eq!(def.max_turns, 30);
        assert!(def.tools.is_empty());
    }
}
