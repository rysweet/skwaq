//! Adapter for skwaq's own test fixtures as a mini benchmark.

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

/// Collect all C/C++ source and header files in a directory (non-recursive).
/// Used to enumerate companion files for multi-file fixture cases.
fn collect_companion_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| matches!(e, "c" | "h" | "cpp" | "cxx" | "cc" | "hpp"))
                    .unwrap_or(false)
        })
        .collect();
    files.sort(); // deterministic ordering
    files
}

/// Uses skwaq's own test fixtures (tests/fixtures/) as a mini benchmark.
pub struct FixturesAdapter {
    manifest_path: PathBuf,
    fixtures_dir: PathBuf,
}

impl FixturesAdapter {
    pub fn new(manifest_path: PathBuf, fixtures_dir: PathBuf) -> Self {
        Self {
            manifest_path,
            fixtures_dir,
        }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for FixturesAdapter {
    fn name(&self) -> &str {
        "fixtures"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, _config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        // Fixtures are already in the repo.
        Ok(self.fixtures_dir.clone())
    }

    fn is_ready(&self, _config: &BenchmarkConfig) -> bool {
        self.fixtures_dir.exists()
    }

    async fn compile(&self, data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // Compile C fixtures if a Makefile exists.
        let makefile = data_dir.join("Makefile");
        if makefile.exists() {
            let status = std::process::Command::new("make")
                .arg("-C")
                .arg(data_dir)
                .arg("-j4")
                .stderr(std::process::Stdio::piped())
                .status()?;
            if !status.success() {
                tracing::warn!("Fixture compilation had errors (some may be expected)");
            }
        }
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
        runtime_config: &skwaq_core::config::Config,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // Binary mode: analyze compiled binary instead of source
        if config.binary_mode {
            if let Some(bp) = &case.binary_path {
                let binary = data_dir.join(bp);
                if !binary.exists() {
                    anyhow::bail!(
                        "Binary '{}' not found for case '{}'. Run `skwaq gym setup` to compile fixtures.",
                        binary.display(),
                        case.id
                    );
                }
                return if config.quick_mode {
                    run_binary_pattern_detection(&binary)
                } else if config.llm_only {
                    crate::agentic::run_llm_only_binary_analysis_with_runtime_config(
                        &binary,
                        config.timeout_secs,
                        runtime_config,
                    )
                    .await
                } else {
                    crate::agentic::run_agentic_binary_analysis_with_runtime_config(
                        &binary,
                        config.timeout_secs,
                        runtime_config,
                    )
                    .await
                };
            }
            // No binary_path for this case — non-C cases (python, js) analyzed as source
        }

        let path = data_dir.join(&case.path);

        // Detect multi-file cases: when the target lives in a subdirectory and
        // that directory contains multiple source/header files, the vulnerability
        // chain can span companion compilation units.
        let path_dir = path.parent().unwrap_or(data_dir);
        let companion_files = if path_dir != data_dir {
            collect_companion_files(path_dir)
        } else {
            vec![]
        };
        let is_multi_file_case = companion_files.len() > 1;

        if config.quick_mode {
            if is_multi_file_case {
                crate::agentic::run_multi_file_pattern_analysis(&companion_files)
            } else {
                run_source_pattern_detection(&path)
            }
        } else if config.llm_only {
            crate::agentic::run_llm_only_source_analysis_with_runtime_config(
                &path,
                config.timeout_secs,
                runtime_config,
            )
            .await
        } else {
            // Full agentic analysis: ingest → multi-agent pipeline → findings
            if is_multi_file_case {
                crate::agentic::run_agentic_multi_file_source_analysis_with_runtime_config(
                    &path,
                    &companion_files,
                    config.timeout_secs,
                    runtime_config,
                )
                .await
            } else {
                crate::agentic::run_agentic_source_analysis_with_runtime_config(
                    &path,
                    config.timeout_secs,
                    runtime_config,
                )
                .await
            }
        }
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        crate::adapters::default_map_finding_to_cwes(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop(); // crates/
        dir.pop(); // workspace root
        dir
    }

    fn test_fixtures_dir() -> PathBuf {
        workspace_root().join("tests/fixtures")
    }

    fn test_manifest_path() -> PathBuf {
        workspace_root().join("data/gym/ground_truth/fixtures.toml")
    }

    fn test_config() -> BenchmarkConfig {
        BenchmarkConfig {
            cache_dir: PathBuf::from("/tmp/gym-test"),
            cwe_filter: None,
            max_cases: None,
            quick_mode: true,
            llm_only: false,
            binary_mode: false,
            parallelism: 1,
            skip: 0,
            concurrency: 1,
            timeout_secs: 30,
            holdout_fraction: 0.0,
            max_improvements_per_cycle: 0,
        }
    }

    #[test]
    fn test_adapter_name() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        assert_eq!(adapter.name(), "fixtures");
    }

    #[test]
    fn test_adapter_is_ready() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        assert!(adapter.is_ready(&test_config()));
    }

    #[test]
    fn test_adapter_not_ready_with_bad_dir() {
        let adapter = FixturesAdapter::new(
            PathBuf::from("/nonexistent/manifest.toml"),
            PathBuf::from("/nonexistent/fixtures"),
        );
        assert!(!adapter.is_ready(&test_config()));
    }

    #[test]
    fn test_adapter_ground_truth_loads() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        let gt = adapter.ground_truth().unwrap();
        assert_eq!(gt.suite, "fixtures");
        assert!(!gt.cases.is_empty());
    }

    #[tokio::test]
    async fn test_run_case_buffer_overflow() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        let case = TestCase {
            id: "buffer_overflow".to_string(),
            path: "buffer_overflow.c".to_string(),
            binary_path: Some("binaries/buffer_overflow_O0".to_string()),
            expected_cwes: vec![121],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = adapter
            .run_case(
                &case,
                &test_fixtures_dir(),
                &test_config(),
                &skwaq_core::config::Config::default(),
            )
            .await
            .unwrap();
        assert!(
            !findings.is_empty(),
            "Expected findings for buffer_overflow.c"
        );
        let has_memory = findings.iter().any(|f| {
            let cwes = adapter.map_finding_to_cwes(f);
            cwes.iter().any(|&c| crate::scoring::cwe_family(c) == 119)
        });
        assert!(
            has_memory,
            "Expected memory-family CWE in buffer_overflow.c"
        );
    }

    #[tokio::test]
    async fn test_run_case_command_injection() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        let case = TestCase {
            id: "command_injection".to_string(),
            path: "command_injection.c".to_string(),
            binary_path: Some("binaries/command_injection_O0".to_string()),
            expected_cwes: vec![78],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = adapter
            .run_case(
                &case,
                &test_fixtures_dir(),
                &test_config(),
                &skwaq_core::config::Config::default(),
            )
            .await
            .unwrap();
        assert!(
            !findings.is_empty(),
            "Expected findings for command_injection.c"
        );
        let has_injection = findings.iter().any(|f| {
            let cwes = adapter.map_finding_to_cwes(f);
            cwes.iter().any(|&c| crate::scoring::cwe_family(c) == 74)
        });
        assert!(
            has_injection,
            "Expected injection-family CWE in command_injection.c"
        );
    }

    fn binary_test_config() -> BenchmarkConfig {
        BenchmarkConfig {
            cache_dir: PathBuf::from("/tmp/gym-test"),
            cwe_filter: None,
            max_cases: None,
            quick_mode: true,
            llm_only: false,
            binary_mode: true,
            parallelism: 1,
            skip: 0,
            concurrency: 1,
            timeout_secs: 30,
            holdout_fraction: 0.0,
            max_improvements_per_cycle: 0,
        }
    }

    #[tokio::test]
    async fn test_run_case_binary_mode() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        let case = TestCase {
            id: "buffer_overflow".to_string(),
            path: "buffer_overflow.c".to_string(),
            binary_path: Some("binaries/buffer_overflow_O0".to_string()),
            expected_cwes: vec![121],
            is_negative: false,
            language: "c".to_string(),
        };
        // Ensure binary exists
        let binary = test_fixtures_dir().join("binaries/buffer_overflow_O0");
        if !binary.exists() {
            return; // Skip if fixtures not compiled
        }
        let findings = adapter
            .run_case(
                &case,
                &test_fixtures_dir(),
                &binary_test_config(),
                &skwaq_core::config::Config::default(),
            )
            .await
            .unwrap();
        assert!(
            !findings.is_empty(),
            "Expected findings from binary analysis of buffer_overflow"
        );
    }

    #[tokio::test]
    async fn test_run_case_binary_mode_uses_source_for_non_c() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        // Python case has no binary_path — binary_mode still analyzes source for non-C cases
        let case = TestCase {
            id: "vuln_app_py".to_string(),
            path: "vuln_app.py".to_string(),
            binary_path: None,
            expected_cwes: vec![78],
            is_negative: false,
            language: "python".to_string(),
        };
        let findings = adapter
            .run_case(
                &case,
                &test_fixtures_dir(),
                &binary_test_config(),
                &skwaq_core::config::Config::default(),
            )
            .await
            .unwrap();
        // Non-C cases without binary_path are analyzed as source
        assert!(
            !findings.is_empty(),
            "Expected findings from source analysis for vuln_app.py"
        );
    }

    #[tokio::test]
    async fn test_run_case_multi_file_quick_detects_cross_file_vulns() {
        // The multi_file case has vulnerabilities spanning three files:
        //   main.c: entry point (no dangerous patterns itself)
        //   parser.c: CWE-122 heap overflow via strcpy to malloc'd buffer
        //   processor.c: CWE-78 command injection via system() with user data
        // In quick mode the adapter must analyze ALL files in the subdirectory,
        // not just main.c, so that both vulnerabilities are detected.
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        let case = TestCase {
            id: "multi_file".to_string(),
            path: "multi_file/main.c".to_string(),
            binary_path: Some("binaries/multi_file_O0".to_string()),
            expected_cwes: vec![122, 78],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = adapter
            .run_case(
                &case,
                &test_fixtures_dir(),
                &test_config(),
                &skwaq_core::config::Config::default(),
            )
            .await
            .unwrap();
        assert!(
            !findings.is_empty(),
            "Expected findings for multi_file case (cross-file taint chain), got none"
        );
        // Must detect the injection sink (system()) in processor.c
        let has_injection = findings
            .iter()
            .any(|f| f.category == "injection" || f.title.to_lowercase().contains("system"));
        assert!(
            has_injection,
            "Expected injection finding (CWE-78 system() sink) from processor.c, got: {findings:?}"
        );
        // Must detect the memory-safety issue (strcpy to heap) in parser.c
        let has_memory = findings
            .iter()
            .any(|f| f.category == "memory" || f.title.to_lowercase().contains("strcpy"));
        assert!(
            has_memory,
            "Expected memory finding (CWE-122 strcpy heap overflow) from parser.c, got: {findings:?}"
        );
    }

    #[test]
    fn test_collect_companion_files_returns_c_files() {
        let multi_dir = test_fixtures_dir().join("multi_file");
        if !multi_dir.exists() {
            return;
        }
        let files = collect_companion_files(&multi_dir);
        let names: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .collect();
        assert!(
            names.iter().any(|n| n == "parser.c"),
            "Expected parser.c in companion files, got: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "processor.c"),
            "Expected processor.c in companion files, got: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "main.c"),
            "Expected main.c in companion files, got: {names:?}"
        );
        // Non-source files should be excluded
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with(".toml") || n.ends_with(".md")),
            "Expected no non-source files in companion list, got: {names:?}"
        );
    }
}
