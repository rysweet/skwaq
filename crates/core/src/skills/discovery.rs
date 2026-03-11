//! Skill discovery: find all available skill definition directories.
//!
//! Skills follow the Agent Skills standard (agentskills.io / Claude Code skill format).
//! Each skill is a directory containing a `SKILL.md` entrypoint with YAML frontmatter.
//!
//! Discovery searches these directories (later entries override earlier ones for
//! skills with the same name):
//! 1. `skills/` (bundled with the project)
//! 2. `~/.skwaq/skills/` (user-global)
//! 3. `.skwaq/skills/` (project-local)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::SkillDefinition;

/// YAML frontmatter structure inside SKILL.md files (Agent Skills standard).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct SkillFrontmatter {
    /// Skill name (lowercase, hyphens).
    #[serde(default)]
    name: String,

    /// Human-readable description.
    #[serde(default)]
    description: String,

    /// Skill version string.
    #[serde(default)]
    version: String,

    /// Whether to disable automatic model invocation (user-only skills).
    #[serde(default)]
    disable_model_invocation: bool,

    /// Whether this skill can be invoked by users directly.
    #[serde(default)]
    user_invocable: bool,

    /// Comma-separated list of tools the skill is allowed to use.
    #[serde(default)]
    allowed_tools: Option<String>,

    /// Optional model override.
    #[serde(default)]
    model: Option<String>,

    /// Context mode ("fork" for subagent isolation).
    #[serde(default)]
    context: Option<String>,

    /// Subagent type when context is "fork".
    #[serde(default)]
    agent: Option<String>,
}

/// Parse the `allowed-tools` frontmatter value into a list.
///
/// Handles both comma-separated (`"Bash(skwaq *), Read, Grep"`) and single values.
fn parse_allowed_tools(raw: Option<&str>) -> Vec<String> {
    match raw {
        Some(s) if !s.is_empty() => s.split(',').map(|t| t.trim().to_string()).collect(),
        _ => vec![],
    }
}

/// Discover all available skill definitions.
///
/// Searches these directories (later entries override earlier ones for
/// skills with the same name):
/// 1. `skills/` (bundled defaults)
/// 2. `~/.skwaq/skills/` (user-global)
/// 3. `.skwaq/skills/` (project-local)
pub fn discover_skills() -> Vec<SkillDefinition> {
    let mut skills: HashMap<String, SkillDefinition> = HashMap::new();

    let mut dirs: Vec<PathBuf> = vec![PathBuf::from("skills")];
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join(".skwaq/skills"));
    }
    dirs.push(PathBuf::from(".skwaq/skills"));

    for dir in &dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if !entry_path.is_dir() {
                continue;
            }
            let skill_file = entry_path.join("SKILL.md");
            if !skill_file.exists() {
                continue;
            }
            let content = match std::fs::read_to_string(&skill_file) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to read skill file {}: {e}", skill_file.display());
                    continue;
                }
            };
            match parse_skill_markdown(&content, &skill_file) {
                Ok(def) => {
                    skills.insert(def.name.clone(), def);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse skill file {}: {e}", skill_file.display());
                }
            }
        }
    }

    let mut result: Vec<SkillDefinition> = skills.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Load a single skill by name.
///
/// Search order (first match wins):
/// 1. `.skwaq/skills/{name}/SKILL.md` (project-local)
/// 2. `~/.skwaq/skills/{name}/SKILL.md` (user-global)
/// 3. `skills/{name}/SKILL.md` (bundled defaults)
pub fn load_skill(name: &str) -> anyhow::Result<SkillDefinition> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(".skwaq/skills").join(name).join("SKILL.md"),
    ];
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".skwaq/skills").join(name).join("SKILL.md"));
    }
    candidates.push(PathBuf::from("skills").join(name).join("SKILL.md"));

    for path in &candidates {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            return parse_skill_markdown(&content, path);
        }
    }

    anyhow::bail!(
        "Skill '{}' not found. Searched:\n{}",
        name,
        candidates
            .iter()
            .map(|p| format!("  - {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Parse a SKILL.md file with YAML frontmatter (Agent Skills standard).
///
/// Expected format:
/// ```text
/// ---
/// name: vuln-scan
/// description: Run a vulnerability scan
/// allowed-tools: Bash(skwaq *)
/// disable-model-invocation: true
/// ---
///
/// # Vulnerability Scan
///
/// Skill body here with $ARGUMENTS substitution...
/// ```
fn parse_skill_markdown(content: &str, path: &Path) -> anyhow::Result<SkillDefinition> {
    let content = content.trim();

    // Derive name from parent directory (skill directories use the dir name).
    let name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    if content.starts_with("---") {
        let rest = &content[3..];
        if let Some(end) = rest.find("\n---") {
            let yaml_str = &rest[..end];
            let body = rest[end + 4..].trim();

            let fm: SkillFrontmatter = serde_yaml_ng::from_str(yaml_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse skill frontmatter: {e}"))?;

            // Use frontmatter name if provided, otherwise use directory name.
            let skill_name = if fm.name.is_empty() {
                name
            } else {
                fm.name
            };

            return Ok(SkillDefinition {
                name: skill_name,
                description: fm.description,
                version: fm.version,
                content: body.to_string(),
                path: path.to_path_buf(),
                disable_model_invocation: fm.disable_model_invocation,
                user_invocable: fm.user_invocable,
                allowed_tools: parse_allowed_tools(fm.allowed_tools.as_deref()),
                model: fm.model,
                context: fm.context,
                agent: fm.agent,
            });
        }
    }

    // No frontmatter: use full content as body.
    Ok(SkillDefinition {
        name,
        description: String::new(),
        version: String::new(),
        content: content.to_string(),
        path: path.to_path_buf(),
        disable_model_invocation: false,
        user_invocable: false,
        allowed_tools: vec![],
        model: None,
        context: None,
        agent: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_skill_with_frontmatter() {
        let md = r#"---
name: vuln-scan
description: Run a vulnerability scan
allowed-tools: Bash(skwaq *), Read
disable-model-invocation: true
---

# Vulnerability Scan

Scan $ARGUMENTS for vulnerabilities."#;

        let path = Path::new("skills/vuln-scan/SKILL.md");
        let def = parse_skill_markdown(md, path).unwrap();
        assert_eq!(def.name, "vuln-scan");
        assert_eq!(def.description, "Run a vulnerability scan");
        assert!(def.content.contains("Vulnerability Scan"));
        assert!(def.content.contains("$ARGUMENTS"));
        assert!(!def.content.contains("---"));
        assert!(def.disable_model_invocation);
        assert!(!def.user_invocable);
        assert_eq!(def.allowed_tools, vec!["Bash(skwaq *)", "Read"]);
    }

    #[test]
    fn test_parse_skill_user_invocable() {
        let md = r#"---
name: explain-vuln
description: Explain a vulnerability
user-invocable: true
---

# Explainer

Explain $ARGUMENTS."#;

        let path = Path::new("skills/explain-vuln/SKILL.md");
        let def = parse_skill_markdown(md, path).unwrap();
        assert_eq!(def.name, "explain-vuln");
        assert!(def.user_invocable);
        assert!(!def.disable_model_invocation);
        assert!(def.allowed_tools.is_empty());
    }

    #[test]
    fn test_parse_skill_without_frontmatter() {
        let md = "# Just a skill\n\nNo frontmatter here.";
        let path = Path::new("skills/plain/SKILL.md");
        let def = parse_skill_markdown(md, path).unwrap();
        assert_eq!(def.name, "plain");
        assert!(def.description.is_empty());
        assert!(def.content.contains("Just a skill"));
    }

    #[test]
    fn test_parse_skill_name_from_directory() {
        let md = r#"---
description: A skill without a name field
---

# Content"#;

        let path = Path::new("skills/my-skill/SKILL.md");
        let def = parse_skill_markdown(md, path).unwrap();
        // Name derived from parent directory when not in frontmatter.
        assert_eq!(def.name, "my-skill");
    }

    #[test]
    fn test_parse_allowed_tools() {
        assert_eq!(
            parse_allowed_tools(Some("Bash(skwaq *), Read, Grep")),
            vec!["Bash(skwaq *)", "Read", "Grep"]
        );
        assert_eq!(
            parse_allowed_tools(Some("Bash")),
            vec!["Bash"]
        );
        assert!(parse_allowed_tools(None).is_empty());
        assert!(parse_allowed_tools(Some("")).is_empty());
    }

    #[test]
    fn test_parse_skill_with_model_and_context() {
        let md = r#"---
name: advanced-scan
description: Advanced scan
model: claude-opus-4-20250514
context: fork
agent: security-analyst
---

# Advanced

Content."#;

        let path = Path::new("skills/advanced-scan/SKILL.md");
        let def = parse_skill_markdown(md, path).unwrap();
        assert_eq!(def.model, Some("claude-opus-4-20250514".to_string()));
        assert_eq!(def.context, Some("fork".to_string()));
        assert_eq!(def.agent, Some("security-analyst".to_string()));
    }

    #[test]
    fn test_discover_returns_sorted() {
        let skills = discover_skills();
        for w in skills.windows(2) {
            assert!(w[0].name <= w[1].name);
        }
    }

    #[test]
    fn test_load_bundled_skill() {
        // This test works when run from the project root where skills/ exists.
        if Path::new("skills/source-audit/SKILL.md").exists() {
            let skill = load_skill("source-audit").unwrap();
            assert_eq!(skill.name, "source-audit");
            assert!(!skill.description.is_empty());
            assert!(skill.content.contains("Source Code Security Audit"));
        }
    }

    #[test]
    fn test_load_nonexistent_skill() {
        let result = load_skill("nonexistent-skill-xyz-12345");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }
}
