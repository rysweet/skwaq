//! DARPA Cyber Grand Challenge (CGC) adapter.
//!
//! Uses the Trail of Bits cb-multios port of CGC challenge binaries.
//! Each challenge contains intentional vulnerabilities (primarily memory corruption).
//! Source code is available for each challenge, enabling both source and binary analysis.

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct CgcAdapter {
    manifest_path: PathBuf,
}

impl CgcAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for CgcAdapter {
    fn name(&self) -> &str {
        "cgc"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("cgc");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        if gt.download_url.is_empty() {
            // CGC uses git clone, not archive download
            anyhow::bail!(
                "CGC data must be cloned manually: git clone https://github.com/trailofbits/cb-multios.git {}",
                dest.display()
            );
        }
        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("cgc").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // CGC challenges include source code that can be compiled.
        // For now, we analyze the source directly.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        _config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // CGC challenges span multiple source files. Analyze ALL .c files
        // in the challenge's src/ directory, not just the one listed in path.
        let source_path = data_dir.join(&case.path);
        let challenge_src_dir = source_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        let mut all_findings = Vec::new();

        // Collect all .c files in the challenge source directory
        if challenge_src_dir.is_dir() {
            for entry in std::fs::read_dir(challenge_src_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("c") {
                    match run_source_pattern_detection(&path) {
                        Ok(findings) => all_findings.extend(findings),
                        Err(e) => tracing::debug!("CGC file {} failed: {}", path.display(), e),
                    }
                }
            }
        }

        // Fallback: analyze just the listed file if directory walk found nothing
        if all_findings.is_empty() && source_path.exists() {
            all_findings = run_source_pattern_detection(&source_path)?;
        }

        Ok(all_findings)
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        // CGC challenges are overwhelmingly memory corruption (CWE-119 family)
        crate::scoring::category_to_cwes(&finding.category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = CgcAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "cgc");
    }
}
