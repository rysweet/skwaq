//! Meta CyberSecEval adapter.
//!
//! CyberSecEval test cases have vulnerable code embedded in a JSON dataset.
//! During setup, we extract each case's `origin_code` into individual source files.

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
        let dest = config.cache_dir.join("cyberseceval");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }

        // Extract code from the PurpleLlama instruct.json dataset
        let json_path = find_instruct_json()?;
        extract_cases_from_json(&json_path, &dest)?;

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
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        let source_path = data_dir.join(&case.path);
        if !source_path.exists() {
            anyhow::bail!(
                "CyberSecEval case file not found: {}. Run `skwaq gym setup` first.",
                source_path.display()
            );
        }
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

/// Find the PurpleLlama instruct.json in common locations.
fn find_instruct_json() -> anyhow::Result<PathBuf> {
    let candidates = [
        PathBuf::from("/tmp/gym-downloads/PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json"),
        dirs::home_dir()
            .unwrap_or_default()
            .join(".local/share/skwaq/gym/PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    anyhow::bail!(
        "CyberSecEval instruct.json not found. Clone PurpleLlama first:\n\
         git clone https://github.com/meta-llama/PurpleLlama.git /tmp/gym-downloads/PurpleLlama"
    )
}

/// Extract origin_code from each JSON entry into individual source files.
fn extract_cases_from_json(json_path: &Path, dest: &Path) -> anyhow::Result<()> {
    let cases_dir = dest.join("cases");
    std::fs::create_dir_all(&cases_dir)?;

    let content = std::fs::read_to_string(json_path)?;
    let data: Vec<serde_json::Value> = serde_json::from_str(&content)?;

    let mut extracted = 0;
    for item in &data {
        let lang = item
            .get("language")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let origin_code = item.get("origin_code").and_then(|v| v.as_str());
        let prompt_id = item.get("prompt_id").and_then(|v| v.as_u64()).unwrap_or(0);

        if let Some(code) = origin_code {
            if lang == "c" || lang == "python" {
                let ext = if lang == "c" { "c" } else { "py" };
                let filename = format!("cyberseceval_{}_{}.{}", prompt_id, lang, ext);
                let file_path = cases_dir.join(&filename);
                if !file_path.exists() {
                    std::fs::write(&file_path, code)?;
                    extracted += 1;
                }
            }
        }
    }

    tracing::info!(
        "Extracted {} CyberSecEval cases to {}",
        extracted,
        cases_dir.display()
    );
    Ok(())
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
