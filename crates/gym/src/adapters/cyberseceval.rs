//! Meta CyberSecEval adapter.
//!
//! CyberSecEval (from Meta's PurpleLlama) tests whether tools can detect
//! insecure code patterns across multiple languages. Each test case is a
//! code snippet with a known vulnerability type.

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct CyberSecEvalAdapter {
    manifest_path: PathBuf,
}

impl CyberSecEvalAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for CyberSecEvalAdapter {
    fn name(&self) -> &str {
        "cyberseceval"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("cyberseceval");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        if gt.download_url.is_empty() {
            anyhow::bail!(
                "CyberSecEval data must be cloned: git clone https://github.com/meta-llama/PurpleLlama.git {}",
                dest.display()
            );
        }
        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config
            .cache_dir
            .join("cyberseceval")
            .join(".ready")
            .exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // CyberSecEval cases are source snippets, no compilation needed.
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
        } else {
            crate::agentic::run_agentic_source_analysis(&source_path, config.timeout_secs).await
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

    #[test]
    fn test_adapter_name() {
        let adapter = CyberSecEvalAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "cyberseceval");
    }
}
