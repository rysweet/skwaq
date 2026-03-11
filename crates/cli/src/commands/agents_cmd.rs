//! `skwaq agents` - manage agent definitions.

use skwaq_core::agents::discover_agents;

/// List all discovered agent definitions.
pub fn run_list() {
    let agents = discover_agents();

    if agents.is_empty() {
        println!("No agents found.");
        println!("Place agent markdown files in:");
        println!("  agents/            (bundled defaults)");
        println!("  .skwaq/agents/     (project-local)");
        println!("  ~/.skwaq/agents/   (user-global)");
        return;
    }

    println!(
        "{:<18} {:<40} {:<20} {:>5}",
        "NAME", "DESCRIPTION", "MODEL", "TOOLS"
    );
    println!("{}", "-".repeat(87));

    for agent in &agents {
        let desc = if agent.description.len() > 38 {
            format!("{}...", &agent.description[..35])
        } else {
            agent.description.clone()
        };
        println!(
            "{:<18} {:<40} {:<20} {:>5}",
            agent.name,
            desc,
            agent.model,
            agent.tools.len(),
        );
    }

    println!("\n{} agent(s) found.", agents.len());
}
