//! TDD tests for the gym profile system.
//!
//! These tests define the contract for model profile management BEFORE implementation.
//! They are expected to FAIL until the profiles module is implemented.
//!
//! Test categories:
//!   1. ProfileName validation (filesystem-safe naming)
//!   2. ProfilePaths resolution (directory layout)
//!   3. Profile creation and listing
//!   4. Config merging (profile [llm] overlays base config)
//!   5. RunMetadata profile field (backward compatibility)
//!   6. Gym::with_profile constructor (isolated paths)
//!   7. Error handling and edge cases

// =============================================================================
// 1. ProfileName validation
// =============================================================================

#[cfg(test)]
mod profile_name_validation {
    use skwaq_gym::profiles::ProfileName;

    #[test]
    fn valid_simple_name() {
        let name = ProfileName::new("opus").unwrap();
        assert_eq!(name.as_str(), "opus");
    }

    #[test]
    fn valid_name_with_hyphens() {
        let name = ProfileName::new("gpt-54-turbo").unwrap();
        assert_eq!(name.as_str(), "gpt-54-turbo");
    }

    #[test]
    fn valid_name_with_underscores() {
        let name = ProfileName::new("claude_opus_4").unwrap();
        assert_eq!(name.as_str(), "claude_opus_4");
    }

    #[test]
    fn valid_name_with_digits() {
        let name = ProfileName::new("model42").unwrap();
        assert_eq!(name.as_str(), "model42");
    }

    #[test]
    fn valid_single_char_name() {
        let name = ProfileName::new("a").unwrap();
        assert_eq!(name.as_str(), "a");
    }

    #[test]
    fn valid_max_length_name() {
        let long_name = "a".repeat(64);
        let name = ProfileName::new(&long_name).unwrap();
        assert_eq!(name.as_str(), long_name);
    }

    #[test]
    fn reject_empty_name() {
        let result = ProfileName::new("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("empty") || err.contains("invalid"),
            "Error should mention empty/invalid: {err}"
        );
    }

    #[test]
    fn reject_name_over_64_chars() {
        let long_name = "a".repeat(65);
        let result = ProfileName::new(&long_name);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("64") || err.contains("long"),
            "Error should mention length limit: {err}"
        );
    }

    #[test]
    fn reject_leading_hyphen() {
        let result = ProfileName::new("-bad");
        assert!(result.is_err());
    }

    #[test]
    fn reject_leading_underscore() {
        let result = ProfileName::new("_bad");
        assert!(result.is_err());
    }

    #[test]
    fn reject_leading_dot() {
        // Prevents hidden directories on Unix
        let result = ProfileName::new(".hidden");
        assert!(result.is_err());
    }

    #[test]
    fn reject_path_traversal_dots() {
        let result = ProfileName::new("..");
        assert!(result.is_err());
    }

    #[test]
    fn reject_path_separator_slash() {
        let result = ProfileName::new("foo/bar");
        assert!(result.is_err());
    }

    #[test]
    fn reject_path_separator_backslash() {
        let result = ProfileName::new("foo\\bar");
        assert!(result.is_err());
    }

    #[test]
    fn reject_spaces() {
        let result = ProfileName::new("has space");
        assert!(result.is_err());
    }

    #[test]
    fn reject_shell_metacharacters() {
        for name in &["a;b", "a&b", "a|b", "a$b", "a`b", "a(b", "a)b"] {
            let result = ProfileName::new(name);
            assert!(result.is_err(), "Should reject metachar in '{name}'");
        }
    }

    #[test]
    fn reject_null_bytes() {
        let result = ProfileName::new("a\0b");
        assert!(result.is_err());
    }

    #[test]
    fn display_impl_returns_name() {
        let name = ProfileName::new("opus").unwrap();
        assert_eq!(format!("{name}"), "opus");
    }
}

// =============================================================================
// 2. ProfilePaths resolution
// =============================================================================

#[cfg(test)]
mod profile_paths {
    use skwaq_gym::profiles::{ProfileName, ProfilePaths};
    use std::path::PathBuf;

    fn test_profile_paths() -> (ProfileName, ProfilePaths) {
        let name = ProfileName::new("test-model").unwrap();
        let base = PathBuf::from("/tmp/test-skwaq-profiles");
        let paths = ProfilePaths::new(&name, &base);
        (name, paths)
    }

    #[test]
    fn profile_dir_is_under_base() {
        let (_, paths) = test_profile_paths();
        assert_eq!(
            paths.profile_dir(),
            PathBuf::from("/tmp/test-skwaq-profiles/test-model")
        );
    }

    #[test]
    fn config_toml_path() {
        let (_, paths) = test_profile_paths();
        assert_eq!(
            paths.config_path(),
            PathBuf::from("/tmp/test-skwaq-profiles/test-model/config.toml")
        );
    }

    #[test]
    fn results_db_path() {
        let (_, paths) = test_profile_paths();
        assert_eq!(
            paths.results_db_path(),
            PathBuf::from("/tmp/test-skwaq-profiles/test-model/results.db")
        );
    }

    #[test]
    fn memory_graph_path() {
        let (_, paths) = test_profile_paths();
        assert_eq!(
            paths.memory_graph_dir(),
            PathBuf::from("/tmp/test-skwaq-profiles/test-model/memory_graph")
        );
    }

    #[test]
    fn telemetry_dir_path() {
        let (_, paths) = test_profile_paths();
        assert_eq!(
            paths.telemetry_dir(),
            PathBuf::from("/tmp/test-skwaq-profiles/test-model/telemetry")
        );
    }

    #[test]
    fn active_runs_path() {
        let (_, paths) = test_profile_paths();
        assert_eq!(
            paths.active_runs_path(),
            PathBuf::from("/tmp/test-skwaq-profiles/test-model/active_runs.jsonl")
        );
    }
}

// =============================================================================
// 3. Profile creation and listing
// =============================================================================

#[cfg(test)]
mod profile_crud {
    use skwaq_gym::profiles::{ProfileName, ProfilePaths};
    use tempfile::TempDir;

    #[test]
    fn ensure_creates_profile_directory_structure() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("myprofile").unwrap();
        let paths = ProfilePaths::new(&name, &base);

        paths.ensure().unwrap();

        assert!(paths.profile_dir().is_dir());
        assert!(
            paths.config_path().exists(),
            "config.toml should be created"
        );
    }

    #[test]
    fn ensure_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("myprofile").unwrap();
        let paths = ProfilePaths::new(&name, &base);

        paths.ensure().unwrap();
        // Write custom content to config.toml
        std::fs::write(paths.config_path(), "[llm]\nreasoning = \"azure\"\n").unwrap();

        // Second ensure should NOT overwrite existing config
        paths.ensure().unwrap();

        let content = std::fs::read_to_string(paths.config_path()).unwrap();
        assert!(
            content.contains("azure"),
            "ensure() must not overwrite existing config.toml"
        );
    }

    #[test]
    fn list_profiles_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let profiles = skwaq_gym::profiles::list_profiles(tmp.path()).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn list_profiles_finds_created_profiles() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        for name in &["opus", "gpt54", "local-llama"] {
            let pn = ProfileName::new(name).unwrap();
            let paths = ProfilePaths::new(&pn, &base);
            paths.ensure().unwrap();
        }

        let mut profiles = skwaq_gym::profiles::list_profiles(&base).unwrap();
        profiles.sort();
        assert_eq!(profiles, vec!["gpt54", "local-llama", "opus"]);
    }

    #[test]
    fn list_profiles_ignores_non_directories() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        // Create a regular file that shouldn't appear as a profile
        std::fs::write(base.join("not-a-profile.txt"), "junk").unwrap();

        let pn = ProfileName::new("real").unwrap();
        let paths = ProfilePaths::new(&pn, &base);
        paths.ensure().unwrap();

        let profiles = skwaq_gym::profiles::list_profiles(&base).unwrap();
        assert_eq!(profiles, vec!["real"]);
    }

    #[test]
    fn list_profiles_nonexistent_base_returns_empty() {
        let result = skwaq_gym::profiles::list_profiles(std::path::Path::new(
            "/tmp/nonexistent-skwaq-test-dir-xyz",
        ))
        .unwrap();
        assert!(result.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_creates_dir_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("secure").unwrap();
        let paths = ProfilePaths::new(&name, &base);

        paths.ensure().unwrap();

        let meta = std::fs::metadata(paths.profile_dir()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "Profile dir should be owner-only (0o700)");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_rejects_symlink_target() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let target = tmp.path().join("real-dir");
        std::fs::create_dir(&target).unwrap();

        // Create a symlink where the profile dir would be
        let symlink_path = base.join("evil");
        std::os::unix::fs::symlink(&target, &symlink_path).unwrap();

        let name = ProfileName::new("evil").unwrap();
        let paths = ProfilePaths::new(&name, &base);

        let result = paths.ensure();
        assert!(result.is_err(), "Should reject symlink as profile dir");
    }
}

// =============================================================================
// 4. Config merging
// =============================================================================

#[cfg(test)]
mod config_merge {
    use skwaq_core::config::{Config, LlmConfig};

    #[test]
    fn merge_overlay_replaces_llm_section() {
        let mut base = Config::default();
        base.llm.reasoning = "copilot".to_string();
        base.llm.decompilation = "copilot".to_string();
        base.llm.copilot.model = "claude-sonnet-4-5-20250514".to_string();

        let mut overlay = LlmConfig {
            reasoning: "azure".to_string(),
            decompilation: "azure".to_string(),
            ..Default::default()
        };
        overlay.azure.endpoint = "https://my-endpoint.openai.azure.com/".to_string();
        overlay.azure.deployment = "gpt-54-skwaq".to_string();

        base.llm.merge_overlay(overlay.clone());

        assert_eq!(base.llm.reasoning, "azure");
        assert_eq!(base.llm.decompilation, "azure");
        assert_eq!(
            base.llm.azure.endpoint,
            "https://my-endpoint.openai.azure.com/"
        );
        assert_eq!(base.llm.azure.deployment, "gpt-54-skwaq");
    }

    #[test]
    fn merge_overlay_does_not_touch_non_llm_sections() {
        let mut base = Config::default();
        base.general.log_level = "debug".to_string();
        base.analysis.max_taint_depth = 99;
        base.binary.default_timeout = 1234;

        let overlay = LlmConfig::default();
        base.llm.merge_overlay(overlay);

        // Non-LLM sections must be untouched
        assert_eq!(base.general.log_level, "debug");
        assert_eq!(base.analysis.max_taint_depth, 99);
        assert_eq!(base.binary.default_timeout, 1234);
    }

    #[test]
    fn load_profile_config_parses_toml() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config_path = tmp.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = "https://test.openai.azure.com/"
deployment = "gpt-54"
"#,
        )
        .unwrap();

        let profile_config: Config = {
            let content = std::fs::read_to_string(&config_path).unwrap();
            toml::from_str(&content).unwrap()
        };

        assert_eq!(profile_config.llm.reasoning, "azure");
        assert_eq!(
            profile_config.llm.azure.endpoint,
            "https://test.openai.azure.com/"
        );
        assert_eq!(profile_config.llm.azure.deployment, "gpt-54");
    }

    #[test]
    fn load_merged_config_applies_profile_over_base() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let name = skwaq_gym::profiles::ProfileName::new("azure-test").unwrap();
        let paths = skwaq_gym::profiles::ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        // Write profile config with azure backend
        std::fs::write(
            paths.config_path(),
            r#"
[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = "https://merged.openai.azure.com/"
deployment = "gpt-54-merged"
"#,
        )
        .unwrap();

        let base_config = Config::default();
        let merged = paths.load_merged_config(&base_config).unwrap();

        // LLM section should come from profile
        assert_eq!(merged.llm.reasoning, "azure");
        assert_eq!(
            merged.llm.azure.endpoint,
            "https://merged.openai.azure.com/"
        );

        // Non-LLM sections should come from base
        assert_eq!(merged.general.log_level, base_config.general.log_level);
    }
}

// =============================================================================
// 5. Default profile templates
// =============================================================================

#[cfg(test)]
mod default_templates {
    use skwaq_gym::profiles::default_templates;

    #[test]
    fn opus_template_uses_copilot_backend() {
        let templates = default_templates();
        let opus = templates.iter().find(|(name, _)| name == "opus").unwrap();
        let config_toml = &opus.1;
        assert!(
            config_toml.contains("copilot"),
            "opus should use copilot backend"
        );
    }

    #[test]
    fn opus_template_uses_claude_opus_model() {
        let templates = default_templates();
        let opus = templates.iter().find(|(name, _)| name == "opus").unwrap();
        let config_toml = &opus.1;
        assert!(
            config_toml.contains("claude-opus"),
            "opus template should reference claude-opus model"
        );
    }

    #[test]
    fn gpt54_template_uses_azure_backend() {
        let templates = default_templates();
        let gpt54 = templates.iter().find(|(name, _)| name == "gpt54").unwrap();
        let config_toml = &gpt54.1;
        assert!(
            config_toml.contains("azure"),
            "gpt54 should use azure backend"
        );
    }

    #[test]
    fn templates_are_valid_toml() {
        let templates = default_templates();
        for (name, config_toml) in &templates {
            let result: Result<skwaq_core::config::Config, _> = toml::from_str(config_toml);
            assert!(
                result.is_ok(),
                "Template '{name}' should be valid TOML: {:?}",
                result.err()
            );
        }
    }
}

// =============================================================================
// 6. RunMetadata profile field — backward compatibility
// =============================================================================

#[cfg(test)]
mod run_metadata_profile {
    use skwaq_gym::history::RunMetadata;

    #[test]
    fn run_metadata_has_profile_field() {
        let meta = RunMetadata {
            profile: Some("opus".to_string()),
            ..Default::default()
        };
        assert_eq!(meta.profile.as_deref(), Some("opus"));
    }

    #[test]
    fn run_metadata_profile_defaults_to_none() {
        let meta = RunMetadata::default();
        assert_eq!(meta.profile, None);
    }

    #[test]
    fn run_metadata_deserializes_without_profile_field() {
        // Old JSON without "profile" should still deserialize (backward compat)
        let json = r#"{
            "llm_backend": "copilot",
            "llm_model": "claude-opus-4.6",
            "run_mode": "hybrid",
            "binary_mode": false,
            "git_dirty": false,
            "concurrency": 4,
            "skip": 0,
            "max_cases": null
        }"#;

        let meta: RunMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.profile, None);
        assert_eq!(meta.llm_backend, "copilot");
    }

    #[test]
    fn run_metadata_serializes_with_profile() {
        let meta = RunMetadata {
            profile: Some("gpt54".to_string()),
            llm_backend: "azure".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"profile\""));
        assert!(json.contains("gpt54"));
    }

    #[test]
    fn run_metadata_round_trips_with_profile() {
        let original = RunMetadata {
            profile: Some("test-profile".to_string()),
            llm_backend: "copilot".to_string(),
            llm_model: "claude-opus-4.6".to_string(),
            run_mode: "hybrid".to_string(),
            binary_mode: false,
            git_dirty: false,
            concurrency: 4,
            skip: 0,
            max_cases: Some(10),
            ..Default::default()
        };

        let json = serde_json::to_string(&original).unwrap();
        let restored: RunMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }
}

// =============================================================================
// 7. HistoryDb stores and queries profile
// =============================================================================

#[cfg(test)]
mod history_db_profile {
    use skwaq_gym::history::{HistoryDb, RunMetadata};

    #[test]
    fn start_run_with_profile_stores_it() {
        let db = HistoryDb::in_memory().unwrap();
        let meta = RunMetadata {
            profile: Some("opus".to_string()),
            llm_backend: "copilot".to_string(),
            ..Default::default()
        };

        let run_id = db.start_run("fixtures", "abc123", &meta).unwrap();

        // Retrieve and check profile is stored in metadata
        let runs = db.recent_runs(1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, run_id);
        assert_eq!(runs[0].metadata.profile.as_deref(), Some("opus"));
    }

    #[test]
    fn start_run_without_profile_stores_none() {
        let db = HistoryDb::in_memory().unwrap();
        let meta = RunMetadata::default();

        db.start_run("fixtures", "abc123", &meta).unwrap();

        let runs = db.recent_runs(1).unwrap();
        assert_eq!(runs[0].metadata.profile, None);
    }
}

// =============================================================================
// 8. Edge cases and error handling
// =============================================================================

#[cfg(test)]
mod edge_cases {
    use skwaq_gym::profiles::{ProfileName, ProfilePaths};
    use tempfile::TempDir;

    #[test]
    fn profile_paths_with_unicode_base_dir() {
        // ProfilePaths should work with any valid base dir
        let name = ProfileName::new("test").unwrap();
        let base = std::path::PathBuf::from("/tmp/skwaq-ünïcödë");
        let paths = ProfilePaths::new(&name, &base);
        assert!(paths.profile_dir().to_str().unwrap().contains("test"));
    }

    #[test]
    fn concurrent_ensure_calls_are_safe() {
        // Multiple threads calling ensure() on the same profile should not panic
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("concurrent").unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let base = base.clone();
                let name_str = name.as_str().to_string();
                std::thread::spawn(move || {
                    let name = ProfileName::new(&name_str).unwrap();
                    let paths = ProfilePaths::new(&name, &base);
                    paths.ensure().unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Profile should exist and be valid
        let name = ProfileName::new("concurrent").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        assert!(paths.profile_dir().is_dir());
    }

    #[test]
    fn load_merged_config_with_empty_config_toml() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("empty-config").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        // Write empty config — should load the base config only
        std::fs::write(paths.config_path(), "").unwrap();

        let base_config = skwaq_core::config::Config::default();
        let merged = paths.load_merged_config(&base_config).unwrap();

        // Should match base config defaults
        assert_eq!(merged.llm.reasoning, base_config.llm.reasoning);
    }

    #[test]
    fn load_merged_config_with_malformed_toml_returns_error() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("bad-toml").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        std::fs::write(paths.config_path(), "{{{{ not valid toml").unwrap();

        let base_config = skwaq_core::config::Config::default();
        let result = paths.load_merged_config(&base_config);
        assert!(result.is_err(), "Malformed TOML should return an error");
    }

    #[test]
    fn profile_name_equality_and_clone() {
        let a = ProfileName::new("opus").unwrap();
        let b = ProfileName::new("opus").unwrap();
        let c = a.clone();
        assert_eq!(a.as_str(), b.as_str());
        assert_eq!(a.as_str(), c.as_str());
    }

    #[test]
    fn ensure_does_not_create_results_db() {
        // ensure() creates the directory and config.toml, but NOT results.db
        // The DB is created lazily when Gym opens it
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        let name = ProfileName::new("lazy-db").unwrap();
        let paths = ProfilePaths::new(&name, &base);
        paths.ensure().unwrap();

        assert!(
            !paths.results_db_path().exists(),
            "results.db should not be pre-created by ensure()"
        );
    }
}
