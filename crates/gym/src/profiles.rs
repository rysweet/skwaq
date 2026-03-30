//! Model profile management for reproducible multi-model evaluation.
//!
//! Each profile gets an isolated config overlay, history DB, and memory graph
//! while sharing the binary, agent prompts, ground truth, and benchmark cache.

use anyhow::{bail, Context};
use std::path::{Path, PathBuf};

/// A validated profile name safe for use as a directory name.
///
/// Must match `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`:
/// - Starts with alphanumeric
/// - Then alphanumeric, hyphens, or underscores
/// - 1–64 characters total
#[derive(Debug, Clone)]
pub struct ProfileName(String);

impl ProfileName {
    pub fn new(name: &str) -> anyhow::Result<Self> {
        if name.is_empty() {
            bail!("Profile name cannot be empty");
        }
        if name.len() > 64 {
            bail!("Profile name too long ({} chars, max 64)", name.len());
        }
        // Must start with alphanumeric
        let first = name.chars().next().unwrap();
        if !first.is_ascii_alphanumeric() {
            bail!(
                "Profile name must start with a letter or digit, got '{}'",
                first
            );
        }
        // Rest must be alphanumeric, hyphen, or underscore
        for ch in name.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                bail!(
                    "Profile name contains invalid character '{}'. \
                     Only letters, digits, hyphens, and underscores are allowed.",
                    ch
                );
            }
        }
        Ok(Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProfileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolved filesystem paths for a single profile.
pub struct ProfilePaths {
    base: PathBuf,
    name: String,
}

impl ProfilePaths {
    pub fn new(name: &ProfileName, base: &Path) -> Self {
        Self {
            base: base.to_path_buf(),
            name: name.as_str().to_string(),
        }
    }

    pub fn profile_dir(&self) -> PathBuf {
        self.base.join(&self.name)
    }

    pub fn config_path(&self) -> PathBuf {
        self.profile_dir().join("config.toml")
    }

    pub fn results_db_path(&self) -> PathBuf {
        self.profile_dir().join("results.db")
    }

    pub fn memory_graph_dir(&self) -> PathBuf {
        self.profile_dir().join("memory_graph")
    }

    pub fn telemetry_dir(&self) -> PathBuf {
        self.profile_dir().join("telemetry")
    }

    pub fn active_runs_path(&self) -> PathBuf {
        self.profile_dir().join("active_runs.jsonl")
    }

    /// Ensure the profile directory exists with proper permissions.
    ///
    /// Creates the directory and a default `config.toml` if they don't exist.
    /// Idempotent: will NOT overwrite an existing `config.toml`.
    /// Rejects symlinks at the profile directory path.
    pub fn ensure(&self) -> anyhow::Result<()> {
        let dir = self.profile_dir();

        // Reject symlinks — prevents symlink-based path traversal attacks
        if dir.exists() {
            let meta = std::fs::symlink_metadata(&dir)
                .with_context(|| format!("Failed to stat profile dir: {}", dir.display()))?;
            if meta.file_type().is_symlink() {
                bail!(
                    "Profile directory is a symlink, which is not allowed: {}",
                    dir.display()
                );
            }
        }

        // Create directory with restricted permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .with_context(|| format!("Failed to create profile dir: {}", dir.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create profile dir: {}", dir.display()))?;
        }

        // Write default config.toml only if it doesn't exist
        let config_path = self.config_path();
        if !config_path.exists() {
            let default_config = "[llm]\n# Profile LLM configuration overlay.\n# Only the [llm] section is used; all other sections are ignored.\n";
            std::fs::write(&config_path, default_config).with_context(|| {
                format!("Failed to write default config: {}", config_path.display())
            })?;
        }

        Ok(())
    }

    /// Load the profile's config.toml and merge its [llm] section over the base config.
    ///
    /// If config.toml doesn't exist, returns a clone of the base config.
    /// Only the [llm] section from the profile is applied; all other sections
    /// are taken from the base config.
    pub fn load_merged_config(
        &self,
        base: &skwaq_core::config::Config,
    ) -> anyhow::Result<skwaq_core::config::Config> {
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(base.clone());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read profile config: {}", config_path.display()))?;

        let profile_config: skwaq_core::config::Config =
            toml::from_str(&content).with_context(|| {
                format!("Failed to parse profile config: {}", config_path.display())
            })?;

        let mut merged = base.clone();
        merged.llm.merge_overlay(profile_config.llm);
        Ok(merged)
    }
}

/// List all profile names under the given base directory.
///
/// Returns an empty vec if the directory doesn't exist.
/// Only directories are considered profiles; regular files are ignored.
pub fn list_profiles(base: &Path) -> anyhow::Result<Vec<String>> {
    if !base.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in std::fs::read_dir(base)
        .with_context(|| format!("Failed to read profiles dir: {}", base.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                // Only include valid profile names
                if ProfileName::new(name).is_ok() {
                    names.push(name.to_string());
                }
            }
        }
    }

    names.sort();
    Ok(names)
}

/// Return the default profile templates shipped with skwaq gym.
///
/// Each entry is `(name, config_toml_content)`.
pub fn default_templates() -> Vec<(String, String)> {
    vec![
        (
            "opus".to_string(),
            r#"[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
"#
            .to_string(),
        ),
        (
            "gpt54".to_string(),
            r#"[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = ""
deployment = ""
"#
            .to_string(),
        ),
    ]
}

/// Return the default base directory for profiles: `~/.skwaq/profiles/`.
pub fn default_profiles_base() -> anyhow::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".skwaq").join("profiles"))
}
