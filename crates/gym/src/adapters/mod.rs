//! Benchmark adapter trait and implementations.

pub mod binmetric;
pub mod binpool;
pub mod cgc;
pub mod cyberseceval;
pub mod fixtures;
pub mod juliet;
pub mod owasp;
pub mod realworld;

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
    /// Whether to use skwaq's quick mode (pattern-only, no LLM agents).
    pub quick_mode: bool,
    /// Whether to use LLM-only mode (no pattern detection, agents only).
    pub llm_only: bool,
    /// Whether to analyze compiled binaries instead of source code.
    pub binary_mode: bool,
    /// Number of parallel compilation/analysis jobs.
    pub parallelism: usize,
    /// Number of cases to skip (for multi-process parallelism).
    pub skip: usize,
    /// Number of cases to run concurrently (in-process async parallelism).
    pub concurrency: usize,
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

/// Run skwaq's binary analysis on a compiled binary and collect findings.
///
/// Two-layer detection:
/// 1. Import scanning: check binary imports for dangerous APIs
/// 2. Graph-based detection: ingest binary into graph, run DangerousApiDetector
///    on function names, symbols, and call relationships
pub fn run_binary_pattern_detection(path: &Path) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::analysis::patterns_binary::DangerousApiDetector;
    use skwaq_core::binary::native::parse_binary;
    use skwaq_core::graph::builder::GraphBuilder;
    use skwaq_core::graph::GraphDb;
    use std::collections::HashSet;

    let binary_info = parse_binary(path)?;
    let file_str = path.to_string_lossy().to_string();

    // Layer 1: Import scanning
    let detector = DangerousApiDetector::new();
    let import_hits = detector.check_imports(&binary_info.imports);

    let mut findings: Vec<DetectedFinding> = import_hits
        .into_iter()
        .map(|hit| DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: hit.danger_category.to_string(),
            severity: hit.severity.to_string(),
            cwes: vec![],
            file: file_str.clone(),
            function: hit.function_name.clone(),
            line: None,
            title: format!("Binary import: {}", hit.function_name),
        })
        .collect();

    // Layer 2: Graph-based detection (function names, call relationships)
    let db = GraphDb::in_memory()?;
    let inv_id = format!("bin-pat-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &file_str.as_str(),
            &file_str.as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    let builder = GraphBuilder::new(&db);
    builder.build_from_binary_info(&binary_info, &inv_id)?;

    // Detect dangerous APIs via graph (catches call relationships + versioned names)
    let graph_hits = detector.detect(&db)?;

    // Deduplicate: normalize to base names (strip @GLIBC_2.x version suffixes)
    let seen: HashSet<String> = findings
        .iter()
        .map(|f| {
            f.function
                .split('@')
                .next()
                .unwrap_or(&f.function)
                .to_string()
        })
        .collect();

    for hit in graph_hits {
        let base_name = hit
            .function_name
            .split('@')
            .next()
            .unwrap_or(&hit.function_name);
        if !seen.contains(base_name) {
            findings.push(DetectedFinding {
                id: uuid::Uuid::new_v4().to_string(),
                category: hit.danger_category.to_string(),
                severity: hit.severity.to_string(),
                cwes: vec![],
                file: file_str.clone(),
                function: hit.function_name.clone(),
                line: None,
                title: format!("Binary function: {}", hit.function_name),
            });
        }
    }

    Ok(findings)
}

/// Run skwaq's source analysis on a file and collect findings.
/// Uses DangerousApiDetector::detect_in_source_content() (the correct API).
pub fn run_source_pattern_detection(path: &Path) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::analysis::DangerousApiDetector;

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

#[cfg(test)]
mod tests {
    use super::run_source_pattern_detection;

    #[test]
    fn test_run_source_pattern_detection_uses_source_detector() {
        let temp_path =
            std::env::temp_dir().join(format!("skwaq-source-detector-{}.c", uuid::Uuid::new_v4()));
        std::fs::write(
            &temp_path,
            r#"
void vuln(char *buf, size_t count) {
    gets(buf);
    malloc(sizeof(int) * count);
}
"#,
        )
        .expect("write temp source file");

        let findings = run_source_pattern_detection(&temp_path).expect("run source detector");
        let functions = findings
            .iter()
            .map(|finding| finding.function.as_str())
            .collect::<Vec<_>>();

        std::fs::remove_file(&temp_path).ok();

        assert!(
            functions.iter().any(|name| name.contains("gets")),
            "Expected source detector to flag gets(), got {functions:?}"
        );
        assert!(
            functions.iter().any(|name| name.contains("malloc")),
            "Expected source detector to flag malloc overflow pattern, got {functions:?}"
        );
    }
}
