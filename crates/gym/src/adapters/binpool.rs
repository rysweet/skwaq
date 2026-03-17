//! BinPool adapter: real-world CVE binary vulnerability benchmark.
//!
//! BinPool (FSE 2025) contains 603 CVEs across 89 CWE classes from 162
//! Debian packages, with vulnerable AND patched versions at 4 optimization
//! levels. skwaq tracks the subset of upstream entries that currently publish
//! at least one vulnerable binary and at least one CWE in `binpool_info.json`.
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

    fn ensure_staged_dataset_ready(&self, dest: &Path) -> anyhow::Result<()> {
        let artifact_root = dest.join("binpool_artifact");
        if !artifact_root.exists() {
            anyhow::bail!(self.manual_setup_message(dest));
        }

        let gt = self.ground_truth()?;
        let missing_binaries: Vec<String> = gt
            .cases
            .iter()
            .filter_map(|case| case.binary_path.as_ref())
            .filter(|binary_path| !dest.join(binary_path).exists())
            .take(3)
            .cloned()
            .collect();

        if !missing_binaries.is_empty() {
            anyhow::bail!(
                "{}\n  \
                 The extracted tree is incomplete. Missing example manifest binaries:\n     {}",
                self.manual_setup_message(dest),
                missing_binaries.join("\n     ")
            );
        }

        Ok(())
    }

    fn manual_setup_message(&self, dest: &Path) -> String {
        format!(
            "BinPool data is not auto-downloaded by skwaq.\n  \
             1. Download the upstream BinPool artifact from the Zenodo link in https://github.com/SimaArasteh/binpool\n  \
             2. Extract it so this path exists:\n     {}/binpool_artifact/\n  \
             3. Re-run: skwaq gym setup",
            dest.display()
        )
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
            self.ensure_staged_dataset_ready(&dest)?;
            return Ok(dest);
        }

        if dest.join("binpool_artifact").exists() {
            self.ensure_staged_dataset_ready(&dest)?;
            std::fs::write(dest.join(".ready"), "")?;
            return Ok(dest);
        }

        let gt = self.ground_truth()?;
        if gt.download_url.is_empty() {
            anyhow::bail!(self.manual_setup_message(&dest));
        }

        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("binpool").join(".ready").exists()
    }

    fn validate_config(&self, config: &BenchmarkConfig) -> anyhow::Result<()> {
        if !config.binary_mode {
            anyhow::bail!("BinPool only supports binary analysis. Re-run without `--source-only`.");
        }
        Ok(())
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
        if !config.binary_mode {
            anyhow::bail!("BinPool only supports binary analysis. Re-run without `--source-only`.");
        }

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
            } else if config.llm_only {
                crate::agentic::run_llm_only_binary_analysis(&binary, config.timeout_secs).await
            } else {
                crate::agentic::run_agentic_binary_analysis(&binary, config.timeout_secs).await
            };
        }

        // BinPool cases should always have binary_path
        anyhow::bail!("BinPool case '{}' missing binary_path in manifest", case.id);
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        crate::adapters::default_map_finding_to_cwes(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ground_truth::TestCase;

    fn write_manifest(path: &Path) {
        std::fs::write(
            path,
            r#"suite = "binpool"
version = "test"
download_url = ""
download_sha256 = ""

[[cases]]
id = "CVE-2023-0001"
path = "src/example.c"
binary_path = "binpool_artifact/CVE-2023-0001/vulnerable/opt0/example.bin"
expected_cwes = [121]
is_negative = false
language = "binary"
"#,
        )
        .unwrap();
    }

    fn test_config(cache_dir: PathBuf) -> BenchmarkConfig {
        BenchmarkConfig {
            cache_dir,
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

    #[test]
    fn test_adapter_name() {
        let adapter = BinPoolAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "binpool");
    }

    #[tokio::test]
    async fn test_setup_accepts_manually_extracted_dataset() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("binpool.toml");
        write_manifest(&manifest);

        let cache_dir = temp.path().join("cache");
        let extracted = cache_dir.join("binpool/binpool_artifact");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::create_dir_all(extracted.join("CVE-2023-0001/vulnerable/opt0")).unwrap();
        std::fs::write(
            extracted.join("CVE-2023-0001/vulnerable/opt0/example.bin"),
            b"fake-binary",
        )
        .unwrap();

        let adapter = BinPoolAdapter::new(manifest);
        let dest = adapter
            .setup(&test_config(cache_dir.clone()))
            .await
            .unwrap();

        assert_eq!(dest, cache_dir.join("binpool"));
        assert!(dest.join(".ready").exists());
    }

    #[tokio::test]
    async fn test_setup_explains_manual_dataset_steps() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("binpool.toml");
        write_manifest(&manifest);

        let cache_dir = temp.path().join("cache");
        let adapter = BinPoolAdapter::new(manifest);
        let err = adapter
            .setup(&test_config(cache_dir.clone()))
            .await
            .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Zenodo"));
        assert!(message.contains("binpool_artifact"));
        assert!(message.contains("skwaq gym setup"));
    }

    #[tokio::test]
    async fn test_setup_rejects_empty_extracted_tree() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("binpool.toml");
        write_manifest(&manifest);

        let cache_dir = temp.path().join("cache");
        std::fs::create_dir_all(cache_dir.join("binpool/binpool_artifact")).unwrap();

        let adapter = BinPoolAdapter::new(manifest);
        let err = adapter.setup(&test_config(cache_dir)).await.unwrap_err();

        assert!(err.to_string().contains("The extracted tree is incomplete"));
    }

    #[tokio::test]
    async fn test_run_case_reports_missing_binary_path() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("binpool.toml");
        write_manifest(&manifest);

        let adapter = BinPoolAdapter::new(manifest);
        let case = TestCase {
            id: "CVE-2023-0001".to_string(),
            path: "src/example.c".to_string(),
            binary_path: Some("binpool_artifact/CVE-2023-0001/vulnerable/opt0/example.bin".into()),
            expected_cwes: vec![121],
            is_negative: false,
            language: "binary".to_string(),
        };

        let err = adapter
            .run_case(
                &case,
                temp.path(),
                &BenchmarkConfig {
                    cache_dir: temp.path().join("cache"),
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
                },
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("Run `skwaq gym setup`"));
    }

    #[test]
    fn test_validate_config_rejects_source_only_mode() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("binpool.toml");
        write_manifest(&manifest);

        let adapter = BinPoolAdapter::new(manifest);
        let mut config = test_config(temp.path().join("cache"));
        config.binary_mode = false;
        let err = adapter.validate_config(&config).unwrap_err();

        assert!(err
            .to_string()
            .contains("BinPool only supports binary analysis"));
    }

    #[tokio::test]
    async fn test_run_case_rejects_source_only_mode() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = temp.path().join("binpool.toml");
        write_manifest(&manifest);

        let adapter = BinPoolAdapter::new(manifest);
        let case = TestCase {
            id: "CVE-2023-0001".to_string(),
            path: "src/example.c".to_string(),
            binary_path: Some("binpool_artifact/CVE-2023-0001/vulnerable/opt0/example.bin".into()),
            expected_cwes: vec![121],
            is_negative: false,
            language: "binary".to_string(),
        };

        let mut config = test_config(temp.path().join("cache"));
        config.binary_mode = false;

        let err = adapter
            .run_case(&case, temp.path(), &config)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("only supports binary analysis"));
    }
}
