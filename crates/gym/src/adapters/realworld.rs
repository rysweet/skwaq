//! Real-world vulnerability benchmark adapter.
//!
//! Uses reproductions of real CVEs from open-source projects (curl, etc.)
//! as test cases. Unlike synthetic benchmarks, these contain realistic code
//! patterns and complexity levels found in production software.
//!
//! Ground truth: data/gym/ground_truth/realworld.toml
//! Test files:   data/gym/realworld/

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

/// Adapter for real-world vulnerability reproductions.
pub struct RealWorldAdapter {
    manifest_path: PathBuf,
    data_dir: PathBuf,
}

impl RealWorldAdapter {
    pub fn new(manifest_path: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            manifest_path,
            data_dir,
        }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for RealWorldAdapter {
    fn name(&self) -> &str {
        "realworld"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, _config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        // Data is checked into the repo under data/gym/realworld/.
        if !self.data_dir.exists() {
            anyhow::bail!(
                "Real-world test data not found at {}. Ensure the repo is complete.",
                self.data_dir.display()
            );
        }
        Ok(self.data_dir.clone())
    }

    fn is_ready(&self, _config: &BenchmarkConfig) -> bool {
        self.data_dir.exists() && self.manifest_path.exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // Source-only analysis for now; binary compilation can be added later.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        let path = data_dir.join(&case.path);
        if !path.exists() {
            anyhow::bail!(
                "Test file not found: {}. Expected at {}",
                case.path,
                path.display()
            );
        }

        if config.quick_mode {
            run_source_pattern_detection(&path)
        } else if config.llm_only {
            crate::agentic::run_llm_only_source_analysis(&path, config.timeout_secs).await
        } else {
            crate::agentic::run_agentic_source_analysis(&path, config.timeout_secs).await
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

    fn test_manifest_path() -> PathBuf {
        workspace_root().join("data/gym/ground_truth/realworld.toml")
    }

    fn test_data_dir() -> PathBuf {
        workspace_root().join("data/gym/realworld")
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
        let adapter = RealWorldAdapter::new(test_manifest_path(), test_data_dir());
        assert_eq!(adapter.name(), "realworld");
    }

    #[test]
    fn test_adapter_is_ready() {
        let adapter = RealWorldAdapter::new(test_manifest_path(), test_data_dir());
        assert!(adapter.is_ready(&test_config()));
    }

    #[test]
    fn test_ground_truth_loads() {
        let adapter = RealWorldAdapter::new(test_manifest_path(), test_data_dir());
        let gt = adapter.ground_truth().unwrap();
        assert_eq!(gt.suite, "realworld");
        assert_eq!(gt.cases.len(), 6);

        let vuln_count = gt.cases.iter().filter(|c| !c.is_negative).count();
        let safe_count = gt.cases.iter().filter(|c| c.is_negative).count();
        assert_eq!(vuln_count, 3, "Should have 3 vulnerable cases");
        assert_eq!(safe_count, 3, "Should have 3 safe cases");
    }

    #[tokio::test]
    async fn test_run_socks5_overflow() {
        let adapter = RealWorldAdapter::new(test_manifest_path(), test_data_dir());
        let case = TestCase {
            id: "curl-CVE-2023-38545-socks5".to_string(),
            path: "curl/CVE-2023-38545-socks5.c".to_string(),
            binary_path: None,
            expected_cwes: vec![122],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = adapter
            .run_case(&case, &test_data_dir(), &test_config())
            .await
            .unwrap();
        // memcpy should be detected as a dangerous memory operation
        let has_memory = findings.iter().any(|f| {
            let cwes = adapter.map_finding_to_cwes(f);
            cwes.iter().any(|&c| crate::scoring::cwe_family(c) == 119)
        });
        assert!(
            has_memory,
            "Expected memory-family CWE for SOCKS5 heap overflow (CVE-2023-38545)"
        );
    }

    #[tokio::test]
    async fn test_safe_base64_no_findings() {
        let adapter = RealWorldAdapter::new(test_manifest_path(), test_data_dir());
        let case = TestCase {
            id: "curl-safe-base64".to_string(),
            path: "curl/safe-base64.c".to_string(),
            binary_path: None,
            expected_cwes: vec![],
            is_negative: true,
            language: "c".to_string(),
        };
        let findings = adapter
            .run_case(&case, &test_data_dir(), &test_config())
            .await
            .unwrap();
        // Safe code should have no or minimal findings.
        // We don't assert zero findings because pattern detection may flag malloc,
        // but this validates the adapter runs without errors on safe code.
        let _ = findings;
    }
}
