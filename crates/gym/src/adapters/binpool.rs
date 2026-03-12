//! BinPool adapter: real-world CVE binary vulnerability benchmark.
//!
//! BinPool (FSE 2025) contains 603 CVEs across 89 CWE classes from 162
//! Debian packages, with vulnerable AND patched versions at 4 optimization
//! levels. This is the gold standard for binary vulnerability detection.
//!
//! Dataset: https://github.com/SimaArasteh/binpool
//! Paper: "BinPool: A Dataset of Vulnerabilities for Binary Security Analysis"

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct BinPoolAdapter {
    manifest_path: PathBuf,
}

impl BinPoolAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for BinPoolAdapter {
    fn name(&self) -> &str {
        "binpool"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let dest = config.cache_dir.join("binpool");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }

        let gt = self.ground_truth()?;
        if gt.download_url.is_empty() {
            anyhow::bail!(
                "BinPool data must be cloned manually:\n  \
                 git clone https://github.com/SimaArasteh/binpool.git {}\n  \
                 Then run: skwaq gym setup",
                dest.display()
            );
        }

        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("binpool").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // BinPool provides pre-compiled binaries at 4 optimization levels.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // BinPool cases are always binaries
        if let Some(bp) = &case.binary_path {
            let binary = data_dir.join(bp);
            if !binary.exists() {
                anyhow::bail!(
                    "BinPool binary '{}' not found for case '{}'. Run `skwaq gym setup`.",
                    binary.display(),
                    case.id
                );
            }
            return if config.quick_mode {
                run_binary_pattern_detection(&binary)
            } else {
                crate::agentic::run_agentic_binary_analysis(&binary, config.timeout_secs).await
            };
        }

        // BinPool cases should always have binary_path
        anyhow::bail!("BinPool case '{}' missing binary_path in manifest", case.id);
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
        let adapter = BinPoolAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "binpool");
    }
}
