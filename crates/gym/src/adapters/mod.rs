//! Benchmark adapter trait and implementations.

pub mod cgc;
pub mod cyberseceval;
pub mod fixtures;
pub mod juliet;
pub mod owasp;

use crate::ground_truth::{GroundTruth, TestCase};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// Configuration for running a benchmark.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Root directory where benchmark data is cached.
    pub cache_dir: PathBuf,
    /// Optional CWE filter: only run test cases matching these CWEs.
    pub cwe_filter: Option<Vec<u32>>,
    /// Maximum test cases to run (for quick validation). None = all.
    pub max_cases: Option<usize>,
    /// Whether to use skwaq's quick mode or full analysis.
    pub quick_mode: bool,
    /// Number of parallel compilation/analysis jobs.
    pub parallelism: usize,
    /// Per-case timeout in seconds.
    pub timeout_secs: u64,
}

/// Every benchmark suite implements this trait.
/// Uses ?Send since skwaq runs on a single-threaded tokio runtime
/// and GraphDb (SQLite Connection) is !Send.
#[async_trait(?Send)]
pub trait BenchmarkAdapter {
    /// Human-readable name of this suite.
    fn name(&self) -> &str;

    /// Load the ground truth manifest for this suite.
    fn ground_truth(&self) -> anyhow::Result<GroundTruth>;

    /// Download and prepare benchmark data. Idempotent.
    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf>;

    /// Check if benchmark data is already set up.
    fn is_ready(&self, config: &BenchmarkConfig) -> bool;

    /// Compile test cases if needed. No-op for pre-built suites.
    async fn compile(&self, data_dir: &Path, config: &BenchmarkConfig) -> anyhow::Result<()>;

    /// Run skwaq against a single test case and return raw findings.
    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>>;

    /// Map a raw skwaq finding to CWE numbers.
    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32>;
}

/// A finding detected by skwaq during a benchmark run.
#[derive(Debug, Clone)]
pub struct DetectedFinding {
    /// Skwaq finding ID.
    pub id: String,
    /// Finding category from skwaq.
    pub category: String,
    /// Severity from skwaq.
    pub severity: String,
    /// CWE IDs that skwaq associated with this finding.
    pub cwes: Vec<u32>,
    /// File where found.
    pub file: String,
    /// Function where found.
    pub function: String,
    /// Line number if available.
    pub line: Option<u32>,
    /// Short description.
    pub title: String,
}

/// Run skwaq's source analysis on a file and collect findings.
/// Uses DangerousApiDetector::detect_in_source_content() (the correct API).
pub fn run_source_pattern_detection(path: &Path) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::analysis::patterns_binary::DangerousApiDetector;

    let content = std::fs::read_to_string(path)?;
    let file_str = path.to_string_lossy().to_string();

    // Detect language from extension.
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("c");
    let language = match ext {
        "c" | "h" => "c",
        "cpp" | "cxx" | "cc" | "hpp" => "cpp",
        "py" => "python",
        "js" | "ts" => "javascript",
        "java" => "java",
        _ => ext,
    };

    let detector = DangerousApiDetector::new();
    let hits = detector.detect_in_source_content(&content, language, &file_str)?;

    let findings = hits
        .into_iter()
        .map(|hit| DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: hit.danger_category.to_string(),
            severity: hit.severity.to_string(),
            cwes: vec![],
            file: file_str.clone(),
            function: hit.function_name.clone(),
            line: if hit.line > 0 {
                Some(hit.line as u32)
            } else {
                None
            },
            title: format!("Dangerous API: {}", hit.function_name),
        })
        .collect();

    Ok(findings)
}
