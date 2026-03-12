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

    async fn compile(&self, data_dir: &Path, config: &BenchmarkConfig) -> anyhow::Result<()> {
        // CGC challenges have Makefiles in each challenge directory.
        // Compile if binary_mode is requested.
        if !config.binary_mode {
            return Ok(());
        }

        let gt = self.ground_truth()?;
        let bin_dir = data_dir.join("compiled");
        std::fs::create_dir_all(&bin_dir)?;

        for case in &gt.cases {
            let source_path = data_dir.join(&case.path);
            let challenge_dir = source_path
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or(data_dir);

            let makefile = challenge_dir.join("Makefile");
            if makefile.exists() {
                let out = bin_dir.join(format!("{}.bin", case.id));
                if out.exists() {
                    continue;
                }
                let status = std::process::Command::new("make")
                    .arg("-C")
                    .arg(challenge_dir)
                    .stderr(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .status()?;
                if !status.success() {
                    tracing::warn!("CGC compilation failed for {}", case.id);
                }
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
        // Binary mode: analyze compiled binary
        if config.binary_mode {
            let binary = if let Some(bp) = &case.binary_path {
                data_dir.join(bp)
            } else {
                data_dir.join("compiled").join(format!("{}.bin", case.id))
            };
            if binary.exists() {
                return if config.quick_mode {
                    run_binary_pattern_detection(&binary)
                } else {
                    crate::agentic::run_agentic_binary_analysis(&binary, config.timeout_secs).await
                };
            }
            // No binary available — fall through to source analysis for CGC
            // (CGC binaries require special build environment)
        }

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
                    let findings = if config.quick_mode {
                        run_source_pattern_detection(&path)
                    } else {
                        crate::agentic::run_agentic_source_analysis(&path, config.timeout_secs)
                            .await
                    };
                    match findings {
                        Ok(f) => all_findings.extend(f),
                        Err(e) => tracing::debug!("CGC file {} failed: {}", path.display(), e),
                    }
                }
            }
        }

        // Fallback: analyze just the listed file if directory walk found nothing
        if all_findings.is_empty() && source_path.exists() {
            if config.quick_mode {
                all_findings = run_source_pattern_detection(&source_path)?;
            } else {
                all_findings =
                    crate::agentic::run_agentic_source_analysis(&source_path, config.timeout_secs)
                        .await?;
            }
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
