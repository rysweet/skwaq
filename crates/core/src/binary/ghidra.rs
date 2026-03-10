//! Ghidra headless analyzer integration via subprocess.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::binary::subprocess::*;
use crate::binary::types::*;

pub struct GhidraRunner {
    ghidra_path: Option<PathBuf>,
}

impl GhidraRunner {
    pub fn new(ghidra_path: Option<PathBuf>) -> Self {
        Self { ghidra_path }
    }

    /// Find Ghidra installation directory.
    pub fn find_ghidra() -> Option<PathBuf> {
        // Check env var first
        if let Ok(path) = std::env::var("GHIDRA_INSTALL_DIR") {
            let p = PathBuf::from(path);
            if p.join("support/analyzeHeadless").exists() {
                return Some(p);
            }
        }

        // Check common locations
        let candidates = [
            "/opt/ghidra",
            "/usr/local/ghidra",
            "/usr/share/ghidra",
        ];
        for candidate in candidates {
            let p = PathBuf::from(candidate);
            if p.join("support/analyzeHeadless").exists() {
                return Some(p);
            }
        }

        // Check home directory
        if let Some(home) = dirs::home_dir() {
            let p = home.join("ghidra");
            if p.join("support/analyzeHeadless").exists() {
                return Some(p);
            }
        }

        None
    }

    fn headless_path(&self) -> Option<PathBuf> {
        let base = self.ghidra_path.as_ref()?;
        let path = base.join("support/analyzeHeadless");
        if path.exists() { Some(path) } else { None }
    }

    /// Run Ghidra headless analysis on a binary.
    /// Returns parsed analysis output.
    pub async fn analyze(&self, binary_path: &Path, timeout_secs: u64) -> anyhow::Result<GhidraAnalysis> {
        let headless = self.headless_path()
            .ok_or_else(|| anyhow::anyhow!("Ghidra not found. Set GHIDRA_INSTALL_DIR"))?;

        let project_dir = tempfile::tempdir()?;
        let output_file = project_dir.path().join("output.json");

        // TODO: Bundle Python post-scripts with the binary
        // For now, use a simple analysis that exports JSON
        let mut cmd = tokio::process::Command::new(&headless);
        cmd.args([
            project_dir.path().to_str().ok_or_else(|| anyhow::anyhow!("non-UTF-8 path"))?,
            "skwaq_project",
            "-import",
            binary_path.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF-8 path"))?,
            "-analysisTimeoutPerFile",
            &timeout_secs.to_string(),
        ]);

        let _output = run_tool(
            &mut cmd,
            "Ghidra",
            Duration::from_secs(timeout_secs),
            Some(project_dir.path()),
        ).await?;

        // Parse output if available
        if output_file.exists() {
            let data = tokio::fs::read_to_string(&output_file).await?;
            let analysis: GhidraAnalysis = serde_json::from_str(&data)?;
            Ok(analysis)
        } else {
            // Return empty analysis if no post-script output
            Ok(GhidraAnalysis {
                functions: Vec::new(),
                strings: Vec::new(),
                imports: Vec::new(),
            })
        }
    }
}

#[async_trait]
impl SubprocessTool for GhidraRunner {
    fn name(&self) -> &str { "Ghidra" }

    async fn health_check(&self) -> ToolHealth {
        match Self::find_ghidra() {
            Some(path) => {
                let headless_str = path.join("support/analyzeHeadless");
                let version = get_version(
                    headless_str.to_str().unwrap_or(""),
                    &[],
                ).await;
                ToolHealth {
                    available: true,
                    version,
                    path: Some(path.to_string_lossy().to_string()),
                    error: None,
                }
            }
            None => ToolHealth {
                available: false,
                version: None,
                path: None,
                error: Some("Ghidra not found".into()),
            },
        }
    }

    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }

    fn install_hint(&self) -> &str {
        "Download from https://ghidra-sre.org/ and set GHIDRA_INSTALL_DIR"
    }
}
