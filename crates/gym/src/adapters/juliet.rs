//! NIST Juliet Test Suite adapter.
//!
//! Juliet C/C++ 1.3 contains 45,324 test cases across 116 CWEs.
//! Each test case has a vulnerable version and a "good" (patched) version.
//! Directory structure: testcases/CWE{NNN}_{name}/s{NN}/{file}.c

use super::*;
use crate::ground_truth::GroundTruth;
use std::path::{Path, PathBuf};

pub struct JulietAdapter {
    manifest_path: PathBuf,
}

impl JulietAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }

    /// Parse CWE number from Juliet directory structure.
    /// Used when generating manifests from downloaded Juliet data.
    /// Juliet organizes files as: testcases/CWE{NNN}_{name}/s{NN}/{file}.c
    pub fn parse_cwe_from_path(path: &str) -> Option<u32> {
        path.split('/')
            .find(|s| s.starts_with("CWE"))
            .and_then(|s| s.split('_').next())
            .and_then(|s| s.strip_prefix("CWE"))
            .and_then(|s| s.parse().ok())
    }
}

#[async_trait(?Send)]
impl BenchmarkAdapter for JulietAdapter {
    fn name(&self) -> &str {
        "juliet"
    }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("juliet");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        crate::download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("juliet").join(".ready").exists()
    }

    async fn compile(&self, data_dir: &Path, config: &BenchmarkConfig) -> anyhow::Result<()> {
        let gt = self.ground_truth()?;
        let bin_dir = data_dir.join("compiled");
        std::fs::create_dir_all(&bin_dir)?;

        let cases: Vec<_> = gt
            .cases
            .iter()
            .filter(|c| !c.is_negative)
            .filter(|c| {
                config
                    .cwe_filter
                    .as_ref()
                    .is_none_or(|f| c.expected_cwes.iter().any(|cwe| f.contains(cwe)))
            })
            .take(config.max_cases.unwrap_or(usize::MAX))
            .collect();

        // Compile in parallel using rayon.
        use rayon::prelude::*;
        let support_dir = data_dir.join("testcasesupport");
        cases.par_iter().for_each(|case| {
            let source = data_dir.join(&case.path);
            let out = bin_dir.join(format!("{}.bin", case.id));
            if out.exists() || !source.exists() {
                return;
            }
            let _ = compile_single(&source, &out, &support_dir);
        });

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
            if let Some(bp) = &case.binary_path {
                let binary = data_dir.join(bp);
                if binary.exists() {
                    return if config.quick_mode {
                        run_binary_pattern_detection(&binary)
                    } else {
                        crate::agentic::run_agentic_binary_analysis(
                            &binary,
                            config.timeout_secs,
                        )
                        .await
                    };
                }
                tracing::warn!(
                    "Binary {} not found for case {}, falling back to source",
                    binary.display(),
                    case.id
                );
            }
        }

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

/// Compile a single C/C++ Juliet test case with sandboxed resource limits.
fn compile_single(source: &Path, output: &Path, support_dir: &Path) -> anyhow::Result<()> {
    let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("c");
    let compiler = if ext == "cpp" { "g++" } else { "gcc" };

    // Sandboxed compilation: ulimit CPU time (60s), memory (512MB), file size (100MB)
    let status = std::process::Command::new("bash")
        .args([
            "-c",
            &format!(
                "ulimit -t 60 -v 524288 -f 102400 2>/dev/null; \
                 {} -o '{}' '{}' -I'{}' -lpthread -lm \
                 -fno-stack-protector -z execstack -no-pie -D_FORTIFY_SOURCE=0 2>/dev/null",
                compiler,
                output.display(),
                source.display(),
                support_dir.display(),
            ),
        ])
        .stderr(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        tracing::debug!("Compilation failed for {}", source.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cwe_from_path() {
        assert_eq!(
            JulietAdapter::parse_cwe_from_path(
                "testcases/CWE121_Stack_Based_Buffer_Overflow/s01/test.c"
            ),
            Some(121)
        );
        assert_eq!(
            JulietAdapter::parse_cwe_from_path("testcases/CWE78_OS_Command_Injection/s01/test.c"),
            Some(78)
        );
        assert_eq!(JulietAdapter::parse_cwe_from_path("no_cwe_here.c"), None);
    }

    #[test]
    fn test_adapter_name() {
        let adapter = JulietAdapter::new(PathBuf::from("/nonexistent"));
        assert_eq!(adapter.name(), "juliet");
    }
}
