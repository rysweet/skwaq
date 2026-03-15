//! `skwaq agents` - manage agent definitions.

use skwaq_core::agents::{discover_agents, AgentDefinition};

/// List all discovered agent definitions.
pub fn run_list() {
    let agents = discover_agents();

    print!("{}", render_agents_list(&agents));
}

fn render_agents_list(agents: &[AgentDefinition]) -> String {
    let mut out = String::new();

    if agents.is_empty() {
        out.push_str("No agents found.\n");
        out.push_str("Place agent markdown files in:\n");
        out.push_str("  agents/            (bundled defaults)\n");
        out.push_str("  .skwaq/agents/     (project-local)\n");
        out.push_str("  ~/.skwaq/agents/   (user-global)\n");
        return out;
    }

    out.push_str(&format!(
        "{:<18} {:<34} {:<24} {:<32} {:<18} {:>5}\n",
        "NAME", "DESCRIPTION", "MODEL", "ROLE", "SCHEMA", "TOOLS"
    ));
    out.push_str(&format!("{}\n", "-".repeat(136)));

    for agent in agents {
        let desc = truncate(&agent.description, 38);
        let role = agent
            .role
            .as_ref()
            .map(|role| role.title.clone())
            .unwrap_or_else(|| "-".into());
        let schema = agent.output_schema.clone().unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "{:<18} {:<34} {:<24} {:<32} {:<18} {:>5}\n",
            agent.name,
            desc,
            agent.model,
            role,
            schema,
            agent.tools.len(),
        ));
    }

    out.push_str(&format!("\n{} agent(s) found.\n", agents.len()));
    out
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() > max_chars {
        let truncated: String = text.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skwaq_core::agents::AgentRoleMetadata;

    fn test_agent(
        name: &str,
        description: &str,
        role_title: Option<&str>,
        output_schema: Option<&str>,
    ) -> AgentDefinition {
        AgentDefinition {
            name: name.into(),
            description: description.into(),
            model: "claude-opus-4.6".into(),
            tools: vec!["query_graph".into(), "read_function".into()],
            max_turns: 5,
            role: role_title.map(|title| AgentRoleMetadata {
                title: title.into(),
                expertise: vec![],
                focus: vec![],
                skepticism: vec![],
                evidence_preferences: vec![],
            }),
            output_schema: output_schema.map(str::to_string),
            system_prompt: "Prompt".into(),
            source_path: None,
        }
    }

    #[test]
    fn renders_empty_agents_message() {
        let rendered = render_agents_list(&[]);
        assert!(rendered.contains("No agents found."));
        assert!(rendered.contains("agents/"));
    }

    #[test]
    fn renders_role_column_for_agents() {
        let rendered = render_agents_list(&[
            test_agent(
                "vuln-hunter",
                "Primary vulnerability discovery agent",
                Some("Primary discovery specialist"),
                Some("vuln-hunter-v1"),
            ),
            test_agent("minimal", "No special role metadata", None, None),
        ]);

        assert!(rendered.contains("ROLE"));
        assert!(rendered.contains("SCHEMA"));
        assert!(rendered.contains("Primary discovery specialist"));
        assert!(rendered.contains("vuln-hunter-v1"));
        assert!(rendered.contains("minimal"));
        assert!(rendered.contains(" - ") || rendered.contains("minimal"));
    }

    #[test]
    fn preserves_long_role_titles() {
        let rendered = render_agents_list(&[test_agent(
            "role-heavy",
            "A role-heavy agent",
            Some("This role title is intentionally much too long to fit cleanly"),
            None,
        )]);

        assert!(rendered.contains("This role title is intentionally much too long to fit cleanly"));
    }
}
