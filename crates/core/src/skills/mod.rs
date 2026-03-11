//! Skill system: load and execute security-focused skill definitions.
//!
//! Skills follow the Agent Skills standard (agentskills.io / Claude Code skill format).
//! Each skill is a directory containing a `SKILL.md` entrypoint with YAML frontmatter.
//!
//! Directory layout:
//! ```text
//! skills/
//! +-- vuln-scan/
//! |   +-- SKILL.md
//! +-- binary-audit/
//! |   +-- SKILL.md
//! ```
//!
//! Search order for skill directories:
//! 1. `skills/` (bundled with the project)
//! 2. `.skwaq/skills/` (project-local overrides)
//! 3. `~/.skwaq/skills/` (user-global)

pub mod discovery;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::agents::tools::{agent_tools, execute_tool, filter_tools};
use crate::config::Config;
use crate::graph::GraphDb;
use crate::llm::{execute_with_tools, LlmClient, TokenBudget};

pub use discovery::{discover_skills, load_skill};

/// A skill definition loaded from a SKILL.md file in a skill directory.
#[derive(Debug, Clone)]
pub struct SkillDefinition {
    /// Skill name (from frontmatter or directory name).
    pub name: String,
    /// Human-readable description of what the skill does.
    pub description: String,
    /// Skill version string.
    pub version: String,
    /// The skill prompt content (markdown body after the frontmatter).
    pub content: String,
    /// Path the definition was loaded from (for diagnostics).
    pub path: PathBuf,
    /// Whether to disable automatic model invocation (user-only skills).
    pub disable_model_invocation: bool,
    /// Whether this skill can be invoked by users directly.
    pub user_invocable: bool,
    /// Tools the skill is allowed to use.
    pub allowed_tools: Vec<String>,
    /// Optional model override.
    pub model: Option<String>,
    /// Context mode ("fork" for subagent isolation).
    pub context: Option<String>,
    /// Subagent type when context is "fork".
    pub agent: Option<String>,
}

/// Result from running a skill.
#[derive(Debug, Clone)]
pub struct SkillResult {
    /// The skill's name.
    pub skill_name: String,
    /// The final text output from the LLM.
    pub output: String,
    /// Tokens used during this skill's run.
    pub tokens_used: u64,
}

/// Substitute `$ARGUMENTS`, `$0`, `$1`, etc. and `${CLAUDE_SKILL_DIR}` in skill content.
pub fn substitute_skill_args(content: &str, args: &[String], skill_dir: &Path) -> String {
    let full_args = args.join(" ");
    let skill_dir_str = skill_dir.to_string_lossy();

    let mut result = content.replace("$ARGUMENTS", &full_args);
    result = result.replace("${CLAUDE_SKILL_DIR}", &skill_dir_str);

    // Replace positional args $0, $1, ... $9 (highest first to avoid $1 matching in $10)
    for i in (0..10).rev() {
        let placeholder = format!("${i}");
        let value = args.get(i).map(|s| s.as_str()).unwrap_or("");
        result = result.replace(&placeholder, value);
    }

    result
}

/// Run a skill against the graph database using the LLM tool loop.
///
/// The skill content is used as the system prompt. The LLM is given access
/// to all agent tools (query_graph, read_function, etc.) and drives the
/// tool loop until it produces a final text response or the budget runs out.
///
/// `args` are substituted into the skill content for `$ARGUMENTS`, `$0`, `$1`, etc.
pub async fn run_skill(
    skill: &SkillDefinition,
    args: &[String],
    investigation_id: Option<&str>,
    llm: Arc<dyn LlmClient>,
    config: &Config,
) -> anyhow::Result<SkillResult> {
    let model = if let Some(ref m) = skill.model {
        m.clone()
    } else {
        config.llm.copilot.model.clone()
    };
    let budget_limit = config.analysis.default_token_budget;
    let mut budget = TokenBudget::new(budget_limit);

    let db_path = config.database_path();
    let db = GraphDb::open(&db_path)?;

    // Substitute arguments into skill content
    let skill_dir = skill.path.parent().unwrap_or_else(|| Path::new("."));
    let content = substitute_skill_args(&skill.content, args, skill_dir);

    // Build context prompt from the investigation if one exists
    let user_prompt = if let Some(inv_id) = investigation_id {
        crate::agents::runner::build_analysis_context("target", inv_id, &db)
    } else {
        "Execute this skill. Use the available tools to gather information and \
         produce a thorough analysis."
            .to_string()
    };

    let all_tools = agent_tools();
    // Filter tools to allowed set if specified, otherwise give access to all
    let tools = if skill.allowed_tools.is_empty() {
        let tool_names: Vec<String> = all_tools.iter().map(|t| t.name.clone()).collect();
        filter_tools(&all_tools, &tool_names)
    } else {
        let tool_names: Vec<String> = skill
            .allowed_tools
            .iter()
            .map(|t| t.to_string())
            .collect();
        filter_tools(&all_tools, &tool_names)
    };

    let tokens_before = budget.used;
    let inv_id = investigation_id.unwrap_or("").to_string();

    let output = execute_with_tools(
        llm.as_ref(),
        &model,
        &content,
        &user_prompt,
        &tools,
        |tool_name, args| {
            let inv = inv_id.clone();
            let result = execute_tool(&db, &inv, &tool_name, &args);
            async move { result }
        },
        &mut budget,
    )
    .await?;

    let tokens_used = budget.used - tokens_before;

    Ok(SkillResult {
        skill_name: skill.name.clone(),
        output,
        tokens_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_definition_fields() {
        let def = SkillDefinition {
            name: "test".into(),
            description: "A test skill".into(),
            version: "1.0.0".into(),
            content: "# Test\nDo things.".into(),
            path: PathBuf::from("skills/test/SKILL.md"),
            disable_model_invocation: false,
            user_invocable: false,
            allowed_tools: vec![],
            model: None,
            context: None,
            agent: None,
        };
        assert_eq!(def.name, "test");
        assert_eq!(def.version, "1.0.0");
    }

    #[test]
    fn test_substitute_skill_args() {
        let content = "Scan $ARGUMENTS\nFirst: $0\nSecond: $1";
        let args = vec!["foo.bin".to_string(), "bar.bin".to_string()];
        let result = substitute_skill_args(content, &args, Path::new("skills/test"));
        assert_eq!(result, "Scan foo.bin bar.bin\nFirst: foo.bin\nSecond: bar.bin");
    }

    #[test]
    fn test_substitute_skill_dir() {
        let content = "Dir: ${CLAUDE_SKILL_DIR}";
        let result = substitute_skill_args(content, &[], Path::new("skills/vuln-scan"));
        assert_eq!(result, "Dir: skills/vuln-scan");
    }

    #[test]
    fn test_substitute_missing_args() {
        let content = "Arg: $0 and $1";
        let args = vec!["only-one".to_string()];
        let result = substitute_skill_args(content, &args, Path::new("."));
        assert_eq!(result, "Arg: only-one and ");
    }
}
