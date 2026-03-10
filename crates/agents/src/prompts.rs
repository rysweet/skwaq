//! Shared prompt loading logic for all agents.
//!
//! Looks for prompt files in three locations (in order):
//! 1. `prompts/{name}.md` (project-local)
//! 2. `~/.skwaq/prompts/{name}.md` (user-global)
//! 3. Falls back to the caller-provided bundled default.

use std::path::PathBuf;

/// Load a prompt by `name` from disk, falling back to `bundled_default`.
///
/// Search order:
/// 1. `./prompts/{name}.md`
/// 2. `~/.skwaq/prompts/{name}.md`
/// 3. `bundled_default`
pub fn load_prompt(name: &str, bundled_default: &str) -> String {
    // Try project-local prompts directory first
    let local_path = PathBuf::from("prompts").join(format!("{name}.md"));
    if let Ok(content) = std::fs::read_to_string(&local_path) {
        tracing::info!("Loaded prompt from {}", local_path.display());
        return content;
    }

    // Then try ~/.skwaq/prompts/
    let home_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".skwaq")
        .join("prompts")
        .join(format!("{name}.md"));
    match std::fs::read_to_string(&home_path) {
        Ok(content) => {
            tracing::info!("Loaded custom prompt from {}", home_path.display());
            content
        }
        Err(_) => {
            tracing::debug!(
                "No custom prompt at {}, using bundled default",
                home_path.display()
            );
            bundled_default.to_string()
        }
    }
}
