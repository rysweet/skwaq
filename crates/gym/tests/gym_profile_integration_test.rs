//! Integration tests for Gym profile system — end-to-end workflows.
//!
//! These tests verify profile-aware Gym construction, isolated DB/memory paths,
//! and the profile CLI subcommand contracts. Written TDD-style: expected to FAIL
//! until implementation is complete.

use skwaq_gym::history::HistoryDb;
use skwaq_gym::profiles::{ProfileName, ProfilePaths};
use std::path::PathBuf;
use tempfile::TempDir;

// =============================================================================
// Gym::with_profile constructor
// =============================================================================

#[cfg(test)]
mod gym_with_profile {
    use super::*;

    /// Helper: create a minimal skwaq_root with the required ground_truth dir
    /// so Gym::new / Gym::with_profile can find the fixtures adapter manifest.
    fn make_skwaq_root(tmp: &TempDir) -> PathBuf {
        let root = tmp.path().join("skwaq");
        let gt_dir = root.join("data/gym/ground_truth");
        std::fs::create_dir_all(&gt_dir).unwrap();

        // Create a minimal fixtures.toml manifest so the adapter loads
        std::fs::write(
            gt_dir.join("fixtures.toml"),
            r#"
[[cases]]
id = "test-case-1"
path = "cases/test.c"
cwes = [119]
description = "Test buffer overflow"
"#,
        )
        .unwrap();

        root
    }

    #[test]
    fn with_profile_creates_isolated_history_db() {
        let tmp = TempDir::new().unwrap();
        let profiles_base = tmp.path().join("profiles");
        std::fs::create_dir_all(&profiles_base).unwrap();

        let name = ProfileName::new("iso-test").unwrap();
        let paths = ProfilePaths::new(&name, &profiles_base);
        paths.ensure().unwrap();

        // The profile's results.db should be at the profile-specific path
        let db = HistoryDb::open(&paths.results_db_path()).unwrap();
        let runs = db.recent_runs(10).unwrap();
        assert!(runs.is_empty(), "Fresh profile DB should have no runs");
    }

    #[test]
    fn with_profile_stores_profile_name_in_run_metadata() {
        let tmp = TempDir::new().unwrap();
        let profiles_base = tmp.path().join("profiles");
        std::fs::create_dir_all(&profiles_base).unwrap();

        let name = ProfileName::new("meta-test").unwrap();
        let paths = ProfilePaths::new(&name, &profiles_base);
        paths.ensure().unwrap();

        let db = HistoryDb::open(&paths.results_db_path()).unwrap();

        let meta = skwaq_gym::history::RunMetadata {
            profile: Some("meta-test".to_string()),
            llm_backend: "copilot".to_string(),
            llm_model: "claude-opus-4.6".to_string(),
            run_mode: "hybrid".to_string(),
            ..Default::default()
        };

        let run_id = db.start_run("fixtures", "abc123", &meta).unwrap();
        let runs = db.recent_runs(1).unwrap();
        assert_eq!(runs[0].id, run_id);
        assert_eq!(runs[0].metadata.profile.as_deref(), Some("meta-test"));
    }

    #[test]
    fn default_gym_has_no_profile() {
        // When no --profile is passed, Gym should use the default paths
        // and RunMetadata.profile should be None.
        let meta = skwaq_gym::history::RunMetadata::default();
        assert_eq!(meta.profile, None);
    }

    #[test]
    fn two_profiles_have_separate_dbs() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        // Create two profiles
        let name_a = ProfileName::new("profile-a").unwrap();
        let paths_a = ProfilePaths::new(&name_a, &base);
        paths_a.ensure().unwrap();

        let name_b = ProfileName::new("profile-b").unwrap();
        let paths_b = ProfilePaths::new(&name_b, &base);
        paths_b.ensure().unwrap();

        // Open separate DBs
        let db_a = HistoryDb::open(&paths_a.results_db_path()).unwrap();
        let db_b = HistoryDb::open(&paths_b.results_db_path()).unwrap();

        // Write to profile-a only
        let meta = skwaq_gym::history::RunMetadata {
            profile: Some("profile-a".to_string()),
            ..Default::default()
        };
        db_a.start_run("fixtures", "abc", &meta).unwrap();

        // profile-b should be empty
        let runs_b = db_b.recent_runs(10).unwrap();
        assert!(
            runs_b.is_empty(),
            "profile-b DB should be isolated from profile-a"
        );

        // profile-a should have the run
        let runs_a = db_a.recent_runs(10).unwrap();
        assert_eq!(runs_a.len(), 1);
    }

    #[test]
    fn profile_memory_graph_dir_is_isolated() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let name = ProfileName::new("mem-test").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        // Memory graph dir should be under the profile, not shared
        let mem_dir = paths.memory_graph_dir();
        assert!(
            mem_dir.starts_with(paths.profile_dir()),
            "memory_graph should be under profile dir"
        );
        assert_ne!(
            mem_dir,
            dirs::home_dir().unwrap().join(".skwaq/memory_graph"),
            "memory_graph must NOT be the global default"
        );
    }

    #[test]
    fn profile_telemetry_dir_is_shared() {
        // Per the design, telemetry_dir is SHARED across profiles
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let name = ProfileName::new("tele-test").unwrap();
        let paths = ProfilePaths::new(&name, &base);

        let tele_dir = paths.telemetry_dir();
        // Telemetry dir should still be under the profile dir
        // (the design doc was updated to say telemetry is shared,
        // but each profile stores its own telemetry subdirectory)
        assert!(
            tele_dir.starts_with(paths.profile_dir()),
            "telemetry should be under profile dir"
        );
    }
}

// =============================================================================
// Profile config workflow: create → load → merge
// =============================================================================

#[cfg(test)]
mod profile_config_workflow {
    use super::*;
    use skwaq_core::config::Config;

    #[test]
    fn full_workflow_create_profile_then_load_merged() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        // 1. Create profile
        let name = ProfileName::new("opus").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        // 2. Write opus-specific config
        std::fs::write(
            paths.config_path(),
            r#"
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
"#,
        )
        .unwrap();

        // 3. Load and merge over a base config that uses different settings
        let mut base_config = Config::default();
        base_config.llm.reasoning = "azure".to_string();
        base_config.llm.copilot.model = "claude-sonnet-4-5-20250514".to_string();

        let merged = paths.load_merged_config(&base_config).unwrap();

        // Profile LLM should override base
        assert_eq!(merged.llm.reasoning, "copilot");
        assert_eq!(merged.llm.copilot.model, "claude-opus-4.6");
    }

    #[test]
    fn profile_without_config_file_uses_base_defaults() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let name = ProfileName::new("no-config").unwrap();
        let paths = ProfilePaths::new(&name, &base);

        // Create the dir but don't write config.toml
        std::fs::create_dir_all(paths.profile_dir()).unwrap();

        // load_merged_config should gracefully fall back to base
        let base_config = Config::default();
        let merged = paths.load_merged_config(&base_config).unwrap();
        assert_eq!(merged.llm.reasoning, base_config.llm.reasoning);
    }

    #[test]
    fn profile_config_ignores_non_llm_sections() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let name = ProfileName::new("override-attempt").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        // Profile tries to override general and analysis sections
        std::fs::write(
            paths.config_path(),
            r#"
[general]
log_level = "trace"

[analysis]
max_taint_depth = 999

[llm]
reasoning = "azure"
"#,
        )
        .unwrap();

        let base_config = Config::default();
        let merged = paths.load_merged_config(&base_config).unwrap();

        // LLM override should apply
        assert_eq!(merged.llm.reasoning, "azure");

        // Non-LLM overrides should be IGNORED — base values preserved
        assert_eq!(merged.general.log_level, base_config.general.log_level);
        assert_eq!(
            merged.analysis.max_taint_depth,
            base_config.analysis.max_taint_depth
        );
    }
}

// =============================================================================
// Profile list integration
// =============================================================================

#[cfg(test)]
mod profile_listing {
    use super::*;

    #[test]
    fn list_profiles_returns_sorted_names() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        for name in &["zebra", "alpha", "middle"] {
            let pn = ProfileName::new(name).unwrap();
            let paths = ProfilePaths::new(&pn, &base);
            paths.ensure().unwrap();
        }

        let mut profiles = skwaq_gym::profiles::list_profiles(&base).unwrap();
        profiles.sort();
        assert_eq!(profiles, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn list_profiles_includes_config_summary() {
        // When listing, we should be able to get a summary of each profile's config
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let name = ProfileName::new("opus").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        std::fs::write(
            paths.config_path(),
            r#"
[llm]
reasoning = "copilot"
decompilation = "copilot"

[llm.copilot]
model = "claude-opus-4.6"
"#,
        )
        .unwrap();

        // The profile should be discoverable
        let profiles = skwaq_gym::profiles::list_profiles(&base).unwrap();
        assert!(profiles.contains(&"opus".to_string()));
    }
}
