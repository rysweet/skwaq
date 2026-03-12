//! BinMetric adapter: comprehensive binary code analysis benchmark for LLMs.
//!
//! BinMetric (IJCAI 2025) contains 1,000 questions from 20 real-world projects
//! across 6 binary analysis tasks: decompilation, code summarization, call-site
//! reconstruction, signature recovery, algorithm classification, and assembly
//! instruction generation.
//!
//! Dataset: https://github.com/BinMetric/BinMetric (expected)
//! Paper: https://arxiv.org/abs/2505.07360

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct BinMetricAdapter {
    manifest_path: PathBuf,
}

impl BinMetricAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for BinMetricAdapter {
    fn name(&self) -> &str {
        "binmetric"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let dest = config.cache_dir.join("binmetric");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }

        let gt = self.ground_truth()?;
        if gt.download_url.is_empty() {
            anyhow::bail!(
                "BinMetric data not yet available. Check https://arxiv.org/abs/2505.07360 for dataset release."
            );
        }

        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("binmetric").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // BinMetric provides pre-compiled binaries.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        if let Some(bp) = &case.binary_path {
            let binary = data_dir.join(bp);
            if !binary.exists() {
                anyhow::bail!(
                    "BinMetric binary '{}' not found for case '{}'.",
                    binary.display(),
                    case.id
                );
            }
            return if config.quick_mode {
                run_binary_pattern_detection(&binary)
            } else if config.llm_only {
                crate::agentic::run_llm_only_binary_analysis(&binary, config.timeout_secs).await
            } else {
                crate::agentic::run_agentic_binary_analysis(&binary, config.timeout_secs).await
            };
        }

        // Source fallback for BinMetric cases that include source
        let source = data_dir.join(&case.path);
        if config.quick_mode {
            run_source_pattern_detection(&source)
        } else if config.llm_only {
            crate::agentic::run_llm_only_source_analysis(&source, config.timeout_secs).await
        } else {
            crate::agentic::run_agentic_source_analysis(&source, config.timeout_secs).await
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
        let adapter = BinMetricAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "binmetric");
    }
}
