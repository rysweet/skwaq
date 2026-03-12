//! Adapter for skwaq's own test fixtures as a mini benchmark.

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

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
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // Binary mode: analyze compiled binary instead of source
        if config.binary_mode {
            if let Some(bp) = &case.binary_path {
                let binary = data_dir.join(bp);
                if binary.exists() {
                    return if config.quick_mode {
                        run_binary_pattern_detection(&binary)
                    } else {
                        crate::agentic::run_agentic_binary_analysis(&binary, config.timeout_secs)
                            .await
                    };
                }
                tracing::warn!(
                    "Binary {} not found for case {}, falling back to source",
                    binary.display(),
                    case.id
                );
            }
        }

        let path = data_dir.join(&case.path);
        if config.quick_mode {
            run_source_pattern_detection(&path)
        } else {
            // Full agentic analysis: ingest → multi-agent pipeline → findings
            crate::agentic::run_agentic_source_analysis(&path, config.timeout_secs).await
        }
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        crate::scoring::category_to_cwes(&finding.category)
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
            binary_mode: false,
            parallelism: 1,
            timeout_secs: 30,
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
            .run_case(&case, &test_fixtures_dir(), &test_config())
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
            .run_case(&case, &test_fixtures_dir(), &test_config())
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
            binary_mode: true,
            parallelism: 1,
            timeout_secs: 30,
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
            .run_case(&case, &test_fixtures_dir(), &binary_test_config())
            .await
            .unwrap();
        assert!(
            !findings.is_empty(),
            "Expected findings from binary analysis of buffer_overflow"
        );
    }

    #[tokio::test]
    async fn test_run_case_binary_mode_falls_back_to_source() {
        let adapter = FixturesAdapter::new(test_manifest_path(), test_fixtures_dir());
        // Python case has no binary_path, should fall back to source
        let case = TestCase {
            id: "vuln_app_py".to_string(),
            path: "vuln_app.py".to_string(),
            binary_path: None,
            expected_cwes: vec![78],
            is_negative: false,
            language: "python".to_string(),
        };
        let findings = adapter
            .run_case(&case, &test_fixtures_dir(), &binary_test_config())
            .await
            .unwrap();
        // Should still produce findings from source analysis fallback
        assert!(
            !findings.is_empty(),
            "Expected findings from source fallback for vuln_app.py"
        );
    }
}
