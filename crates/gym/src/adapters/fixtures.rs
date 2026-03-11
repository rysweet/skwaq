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

#[async_trait]
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
        _config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        let path = data_dir.join(&case.path);
        run_source_pattern_detection(&path)
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        crate::scoring::category_to_cwes(&finding.category)
    }
}
