//! OWASP Benchmark adapter.
//!
//! The OWASP Benchmark is a Java test suite with ~2,800 test cases.
//! Each case is a servlet that either contains a real vulnerability (true positive)
//! or a safe implementation (false positive). Scoring uses Youden's index: TPR - FPR.
//!
//! For Skwaq, we analyze the Java source files using pattern detection
//! and LLM agents, since our primary analysis is source-based.

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct OwaspBenchmarkAdapter {
    manifest_path: PathBuf,
}

impl OwaspBenchmarkAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for OwaspBenchmarkAdapter {
    fn name(&self) -> &str {
        "owasp"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("owasp");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        if gt.download_url.is_empty() {
            anyhow::bail!(
                "OWASP Benchmark must be cloned: git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git {}",
                dest.display()
            );
        }
        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("owasp").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // OWASP Benchmark is Java source - no compilation needed for analysis.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        let source_path = data_dir.join(&case.path);
        if config.quick_mode {
            run_source_pattern_detection(&source_path)
        } else if config.llm_only {
            crate::agentic::run_llm_only_source_analysis(&source_path, config.timeout_secs).await
        } else {
            crate::agentic::run_agentic_source_analysis(&source_path, config.timeout_secs).await
        }
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        crate::adapters::default_map_finding_to_cwes(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = OwaspBenchmarkAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "owasp");
    }
}
