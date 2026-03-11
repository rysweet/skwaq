//! `skwaq skills` - manage and execute security skills.

use std::sync::Arc;

use super::common::resolve_investigation;
use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;
use skwaq_core::skills::{discover_skills, load_skill, run_skill};

/// List all discovered skill definitions.
pub fn run_list() {
    let skills = discover_skills();

    if skills.is_empty() {
        println!("No skills found.");
        println!("Place skill directories in:");
        println!("  skills/<name>/SKILL.md       (bundled defaults)");
        println!("  .skwaq/skills/<name>/SKILL.md (project-local)");
        println!("  ~/.skwaq/skills/<name>/SKILL.md (user-global)");
        return;
    }

    println!("{:<22} {:<52} {:>6}", "NAME", "DESCRIPTION", "FLAGS");
    println!("{}", "-".repeat(82));

    for skill in &skills {
        let desc = if skill.description.chars().count() > 50 {
            let truncated: String = skill.description.chars().take(47).collect();
            format!("{truncated}...")
        } else {
            skill.description.clone()
        };
        let mut flags = Vec::new();
        if skill.user_invocable {
            flags.push("user");
        }
        if skill.disable_model_invocation {
            flags.push("noai");
        }
        let flags_str = flags.join(",");
        println!("{:<22} {:<52} {:>6}", skill.name, desc, flags_str,);
    }

    println!("\n{} skill(s) found.", skills.len());
}

/// Run a skill by name through the LLM agent system.
///
/// `args` are positional arguments that get substituted into the skill content
/// as `$ARGUMENTS` (all args joined), `$0`, `$1`, etc.
pub async fn run_run(name: &str, args: Vec<String>) -> anyhow::Result<()> {
    let skill = load_skill(name)?;

    println!("Running skill: {}", skill.name);
    if !skill.description.is_empty() {
        println!("  {}", skill.description);
    }
    if !args.is_empty() {
        println!("  Args: {}", args.join(" "));
    }
    println!();

    let config = Config::load()?;
    let db_path = config.database_path();

    // Try to find the most recent investigation to provide context
    let investigation_id = {
        let db = GraphDb::open(&db_path)?;
        match resolve_investigation(&db, None) {
            Ok(id) => Some(id),
            Err(_) => {
                println!("No investigation found. Running skill without investigation context.");
                None
            }
        }
    };

    println!();

    let llm_client: Arc<dyn skwaq_core::llm::LlmClient> =
        skwaq_core::llm::create_llm_client(&config.llm);

    let result = run_skill(
        &skill,
        &args,
        investigation_id.as_deref(),
        llm_client,
        &config,
    )
    .await?;

    println!("--- {} output ---\n", result.skill_name);
    println!("{}", result.output);
    println!();
    println!("Tokens used: {}", result.tokens_used);

    Ok(())
}
