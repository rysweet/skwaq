# Skwaq Gym: Benchmark Harness Design

## Overview

Skwaq Gym is a benchmark harness that measures skwaq's vulnerability detection accuracy against known ground truth datasets, tracks improvement over time, and drives a self-improvement loop.

It lives as a new crate `crates/gym` in the workspace, with CLI integration via a `Gym` subcommand in `crates/cli`.

---

## 1. File Structure

```
crates/gym/
    Cargo.toml
    src/
        lib.rs                  # Public API: run_suite, score, report, improve
        adapters/
            mod.rs              # BenchmarkAdapter trait
            juliet.rs           # NIST Juliet Test Suite adapter
            cgc.rs              # DARPA CGC adapter
            cyberseceval.rs     # Meta CyberSecEval adapter
            fixtures.rs         # skwaq's own test fixtures adapter
        scoring.rs              # TP/FP/FN computation, precision/recall/F1
        ground_truth.rs         # Ground truth data model and loader
        reporting/
            mod.rs
            terminal.rs         # Rich terminal output
            json_report.rs      # Machine-readable JSON
            markdown_report.rs  # GitHub-compatible markdown
        history.rs              # Run history storage and comparison
        improve.rs              # Self-improvement loop
        download.rs             # Benchmark data download/cache management

crates/cli/src/commands/
    gym_cmd.rs                  # CLI dispatch for `skwaq gym *`

data/gym/
    ground_truth/               # Ground truth manifests (checked into repo)
        juliet.toml
        cgc.toml
        cyberseceval.toml
        fixtures.toml
    cache/                      # Downloaded/compiled benchmarks (gitignored)
```

### Cargo.toml for `crates/gym`

```toml
[package]
name = "skwaq-gym"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
skwaq-core = { path = "../core" }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
toml = { workspace = true }
anyhow = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
reqwest = { workspace = true }
rusqlite = { workspace = true }
sha2 = { workspace = true }
tempfile = { workspace = true }
dirs = { workspace = true }
flate2 = "1"
tar = "0.4"
zip = "2"
walkdir = "2"
rayon = "1"          # Parallel compilation of Juliet test cases
indicatif = "0.17"   # Progress bars

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
tempfile = { workspace = true }
```

---

## 2. Data Model

### 2.1 Ground Truth

Each benchmark suite ships a TOML manifest mapping test case identifiers to expected CWEs. These manifests live in `data/gym/ground_truth/` and are checked into the repo.

```rust
// crates/gym/src/ground_truth.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A single test case with its expected vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique identifier within the suite (e.g., "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01").
    pub id: String,
    /// Relative path to the test file/binary within the benchmark data directory.
    pub path: String,
    /// CWE IDs that SHOULD be detected in this test case.
    pub expected_cwes: Vec<u32>,
    /// Whether this is a "good" (patched) variant that should have NO findings.
    /// Juliet includes both vulnerable and fixed versions of each test case.
    pub is_negative: bool,
    /// Language of the test case (c, cpp, java, python, etc.).
    pub language: String,
}

/// Ground truth for an entire benchmark suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    /// Suite name (juliet, cgc, cyberseceval, fixtures).
    pub suite: String,
    /// Version or commit hash of the benchmark data.
    pub version: String,
    /// URL to download the benchmark data (empty for fixtures).
    pub download_url: String,
    /// SHA-256 of the download archive for integrity verification.
    pub download_sha256: String,
    /// All test cases in this suite.
    pub cases: Vec<TestCase>,
}

impl GroundTruth {
    /// Load from a TOML manifest file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}
```

**Example `data/gym/ground_truth/juliet.toml`** (abbreviated):

```toml
suite = "juliet"
version = "1.3"
download_url = "https://samate.nist.gov/SARD/downloads/test-suites/juliet/Juliet_Test_Suite_v1.3_for_C_Cpp.zip"
download_sha256 = "abc123..."

[[cases]]
id = "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01"
path = "testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c"
expected_cwes = [121]
is_negative = false
language = "c"

[[cases]]
id = "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_good"
path = "testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c"
expected_cwes = []
is_negative = true
language = "c"
```

### 2.2 Benchmark Results

Results are stored in an SQLite database at `~/.skwaq/gym/results.db`. This reuses the rusqlite dependency already in the workspace.

```rust
// crates/gym/src/history.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRun {
    /// Unique run ID.
    pub id: String,
    /// When the run started.
    pub started_at: DateTime<Utc>,
    /// When the run finished.
    pub finished_at: Option<DateTime<Utc>>,
    /// Which suite was run (or "all").
    pub suite: String,
    /// Git commit hash of skwaq at run time.
    pub skwaq_commit: String,
    /// Overall precision (0.0 - 1.0).
    pub precision: f64,
    /// Overall recall (0.0 - 1.0).
    pub recall: f64,
    /// Overall F1 score.
    pub f1: f64,
    /// Total true positives.
    pub true_positives: u32,
    /// Total false positives.
    pub false_positives: u32,
    /// Total false negatives.
    pub false_negatives: u32,
    /// Total true negatives (negative test cases with no findings).
    pub true_negatives: u32,
}

/// Per-CWE result within a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweResult {
    /// Run ID this belongs to.
    pub run_id: String,
    /// CWE number.
    pub cwe_id: u32,
    /// Number of test cases for this CWE.
    pub total_cases: u32,
    /// True positives for this CWE.
    pub true_positives: u32,
    /// False positives for this CWE.
    pub false_positives: u32,
    /// False negatives for this CWE.
    pub false_negatives: u32,
    /// Detection rate (TP / (TP + FN)).
    pub detection_rate: f64,
    /// Precision for this CWE (TP / (TP + FP)).
    pub precision: f64,
}

/// Per-test-case result within a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    /// Run ID this belongs to.
    pub run_id: String,
    /// Suite this case belongs to.
    pub suite: String,
    /// Test case ID.
    pub case_id: String,
    /// Expected CWEs from ground truth.
    pub expected_cwes: Vec<u32>,
    /// CWEs actually detected by skwaq.
    pub detected_cwes: Vec<u32>,
    /// Skwaq finding IDs that matched.
    pub matched_finding_ids: Vec<String>,
    /// Skwaq finding IDs that did NOT match any expected CWE (false positives).
    pub unmatched_finding_ids: Vec<String>,
    /// Classification: tp, fp, fn, tn.
    pub classification: String,
}

/// SQLite-backed history database.
pub struct HistoryDb {
    conn: rusqlite::Connection,
}

impl HistoryDb {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn };
        db.ensure_schema()?;
        Ok(db)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let db = Self { conn };
        db.ensure_schema()?;
        Ok(db)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                suite TEXT NOT NULL,
                skwaq_commit TEXT NOT NULL,
                precision REAL DEFAULT 0.0,
                recall REAL DEFAULT 0.0,
                f1 REAL DEFAULT 0.0,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                false_negatives INTEGER DEFAULT 0,
                true_negatives INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS cwe_results (
                run_id TEXT NOT NULL REFERENCES runs(id),
                cwe_id INTEGER NOT NULL,
                total_cases INTEGER NOT NULL,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                false_negatives INTEGER DEFAULT 0,
                detection_rate REAL DEFAULT 0.0,
                precision REAL DEFAULT 0.0,
                PRIMARY KEY (run_id, cwe_id)
            );

            CREATE TABLE IF NOT EXISTS case_results (
                run_id TEXT NOT NULL REFERENCES runs(id),
                suite TEXT NOT NULL,
                case_id TEXT NOT NULL,
                expected_cwes TEXT NOT NULL,   -- JSON array of u32
                detected_cwes TEXT NOT NULL,   -- JSON array of u32
                matched_finding_ids TEXT NOT NULL,    -- JSON array of strings
                unmatched_finding_ids TEXT NOT NULL,  -- JSON array of strings
                classification TEXT NOT NULL,
                PRIMARY KEY (run_id, suite, case_id)
            );

            CREATE INDEX IF NOT EXISTS idx_cwe_results_cwe ON cwe_results(cwe_id);
            CREATE INDEX IF NOT EXISTS idx_case_results_suite ON case_results(suite);
            CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
            "
        )?;
        Ok(())
    }

    /// Insert a new run record. Returns the run ID.
    pub fn start_run(&self, suite: &str, skwaq_commit: &str) -> anyhow::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO runs (id, started_at, suite, skwaq_commit) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, now, suite, skwaq_commit],
        )?;
        Ok(id)
    }

    /// Finish a run with aggregate scores.
    pub fn finish_run(&self, run: &BenchmarkRun) -> anyhow::Result<()> {
        let finished = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE runs SET finished_at=?1, precision=?2, recall=?3, f1=?4,
             true_positives=?5, false_positives=?6, false_negatives=?7, true_negatives=?8
             WHERE id=?9",
            rusqlite::params![
                finished, run.precision, run.recall, run.f1,
                run.true_positives, run.false_positives, run.false_negatives, run.true_negatives,
                run.id
            ],
        )?;
        Ok(())
    }

    /// Insert per-CWE results.
    pub fn insert_cwe_result(&self, result: &CweResult) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO cwe_results (run_id, cwe_id, total_cases, true_positives,
             false_positives, false_negatives, detection_rate, precision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                result.run_id, result.cwe_id, result.total_cases,
                result.true_positives, result.false_positives, result.false_negatives,
                result.detection_rate, result.precision
            ],
        )?;
        Ok(())
    }

    /// Insert per-case result.
    pub fn insert_case_result(&self, result: &CaseResult) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO case_results (run_id, suite, case_id, expected_cwes,
             detected_cwes, matched_finding_ids, unmatched_finding_ids, classification)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                result.run_id, result.suite, result.case_id,
                serde_json::to_string(&result.expected_cwes)?,
                serde_json::to_string(&result.detected_cwes)?,
                serde_json::to_string(&result.matched_finding_ids)?,
                serde_json::to_string(&result.unmatched_finding_ids)?,
                result.classification
            ],
        )?;
        Ok(())
    }

    /// Load the N most recent runs.
    pub fn recent_runs(&self, limit: u32) -> anyhow::Result<Vec<BenchmarkRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, suite, skwaq_commit,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives
             FROM runs ORDER BY started_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(rusqlite::params![limit], |row| {
            Ok(BenchmarkRun {
                id: row.get(0)?,
                started_at: row.get::<_, String>(1)?
                    .parse().unwrap_or_default(),
                finished_at: row.get::<_, Option<String>>(2)?
                    .and_then(|s| s.parse().ok()),
                suite: row.get(3)?,
                skwaq_commit: row.get(4)?,
                precision: row.get(5)?,
                recall: row.get(6)?,
                f1: row.get(7)?,
                true_positives: row.get(8)?,
                false_positives: row.get(9)?,
                false_negatives: row.get(10)?,
                true_negatives: row.get(11)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Load per-CWE results for a run.
    pub fn cwe_results_for_run(&self, run_id: &str) -> anyhow::Result<Vec<CweResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id, cwe_id, total_cases, true_positives, false_positives,
                    false_negatives, detection_rate, precision
             FROM cwe_results WHERE run_id = ?1 ORDER BY cwe_id"
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |row| {
            Ok(CweResult {
                run_id: row.get(0)?,
                cwe_id: row.get(1)?,
                total_cases: row.get(2)?,
                true_positives: row.get(3)?,
                false_positives: row.get(4)?,
                false_negatives: row.get(5)?,
                detection_rate: row.get(6)?,
                precision: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}
```

---

## 3. Benchmark Adapter Trait

```rust
// crates/gym/src/adapters/mod.rs

pub mod juliet;
pub mod cgc;
pub mod cyberseceval;
pub mod fixtures;

use crate::ground_truth::{GroundTruth, TestCase};
use crate::scoring::CaseOutcome;
use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// Configuration for running a benchmark.
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
}

/// Every benchmark suite implements this trait.
#[async_trait]
pub trait BenchmarkAdapter: Send + Sync {
    /// Human-readable name of this suite.
    fn name(&self) -> &str;

    /// Load the ground truth manifest for this suite.
    fn ground_truth(&self) -> anyhow::Result<GroundTruth>;

    /// Download and prepare benchmark data. Idempotent -- skips if data already cached.
    /// Returns the root path where benchmark data lives.
    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf>;

    /// Check if benchmark data is already set up.
    fn is_ready(&self, config: &BenchmarkConfig) -> bool;

    /// Compile test cases if needed (e.g., Juliet C files). No-op for pre-built suites.
    async fn compile(&self, data_dir: &Path, config: &BenchmarkConfig) -> anyhow::Result<()>;

    /// Run skwaq against a single test case and return the raw findings.
    /// The adapter is responsible for invoking skwaq correctly for its data type
    /// (source analysis for Juliet/CyberSecEval, binary analysis for CGC).
    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>>;

    /// Map a raw skwaq finding to CWE numbers. Different suites may need different
    /// mapping strategies (e.g., CGC uses CWE-119 broadly, Juliet has exact CWE dirs).
    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32>;
}

/// A finding detected by skwaq during a benchmark run.
#[derive(Debug, Clone)]
pub struct DetectedFinding {
    /// Skwaq finding ID.
    pub id: String,
    /// Finding category from skwaq (memory, injection, etc.).
    pub category: String,
    /// Severity from skwaq.
    pub severity: String,
    /// CWE IDs that skwaq associated with this finding (if any).
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
```

### 3.1 CWE Mapping Strategy

Skwaq's `DangerCategory` maps to CWEs as follows. This is the default mapping used by `map_finding_to_cwes` when skwaq doesn't report explicit CWE IDs:

```rust
// crates/gym/src/scoring.rs (partial)

use std::collections::HashMap;

/// Default mapping from skwaq DangerCategory to CWE IDs.
/// Used when skwaq findings don't carry explicit CWE annotations.
pub fn category_to_cwes(category: &str) -> Vec<u32> {
    match category {
        "memory" => vec![119, 120, 121, 122, 125, 126, 787, 416, 415],
        "injection" => vec![78, 89, 90, 94, 77],
        "format_string" => vec![134],
        "race" => vec![362, 367],
        "temp_file" => vec![377],
        "path_traversal" => vec![22, 23, 36],
        "deserialization" => vec![502],
        "crypto" => vec![326, 327, 328, 330],
        "unsafe_code" => vec![676],
        "prototype_pollution" => vec![1321],
        "xss" => vec![79, 80],
        _ => vec![],
    }
}
```

This is intentionally broad. A match means: the skwaq finding's category is in the same CWE family as the expected CWE. We score at the CWE-family level, not at the exact sub-CWE level, because skwaq's category system doesn't distinguish CWE-121 from CWE-122 (both are "memory").

### 3.2 Juliet Adapter

```rust
// crates/gym/src/adapters/juliet.rs

use super::*;
use crate::download;
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
    /// Juliet organizes files as: testcases/CWE{NNN}_{name}/s{NN}/{file}.c
    fn parse_cwe_from_path(path: &str) -> Option<u32> {
        // Extract "CWE121" from "testcases/CWE121_Stack_Based.../..."
        path.split('/')
            .find(|s| s.starts_with("CWE"))
            .and_then(|s| s.split('_').next())
            .and_then(|s| s.strip_prefix("CWE"))
            .and_then(|s| s.parse().ok())
    }

    /// Compile a single C/C++ test case.
    /// Juliet provides support files (io.c, std_testcase.c) that must be linked.
    fn compile_single(
        source: &Path,
        output: &Path,
        support_dir: &Path,
    ) -> anyhow::Result<()> {
        let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("c");
        let compiler = if ext == "cpp" { "g++" } else { "gcc" };

        let status = std::process::Command::new(compiler)
            .args([
                "-o", &output.to_string_lossy(),
                &source.to_string_lossy(),
                &support_dir.join("io.c").to_string_lossy(),
                &support_dir.join("std_testcase.c").to_string_lossy(),
                "-I", &support_dir.to_string_lossy(),
                "-lpthread",
                "-lm",
                // Deliberately compile WITHOUT hardening to make vulns detectable:
                "-fno-stack-protector",
                "-z", "execstack",
                "-no-pie",
                "-D_FORTIFY_SOURCE=0",
            ])
            .stderr(std::process::Stdio::piped())
            .status()?;

        if !status.success() {
            // Compilation failures are expected for some Juliet cases.
            // Log and skip rather than failing the whole suite.
            tracing::debug!("Compilation failed for {}", source.display());
        }
        Ok(())
    }
}

#[async_trait]
impl BenchmarkAdapter for JulietAdapter {
    fn name(&self) -> &str { "juliet" }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("juliet");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("juliet").join(".ready").exists()
    }

    async fn compile(&self, data_dir: &Path, config: &BenchmarkConfig) -> anyhow::Result<()> {
        let gt = self.ground_truth()?;
        let support_dir = data_dir.join("testcasesupport");
        let bin_dir = data_dir.join("compiled");
        std::fs::create_dir_all(&bin_dir)?;

        let cases: Vec<_> = gt.cases.iter()
            .filter(|c| !c.is_negative)
            .filter(|c| {
                config.cwe_filter.as_ref().map_or(true, |f| {
                    c.expected_cwes.iter().any(|cwe| f.contains(cwe))
                })
            })
            .take(config.max_cases.unwrap_or(usize::MAX))
            .collect();

        // Parallel compilation with rayon.
        use rayon::prelude::*;
        cases.par_iter().for_each(|case| {
            let source = data_dir.join(&case.path);
            let out = bin_dir.join(format!("{}.bin", case.id));
            if out.exists() { return; }
            let _ = Self::compile_single(&source, &out, &support_dir);
        });

        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // Run skwaq source analysis on the C file.
        let source_path = data_dir.join(&case.path);
        run_skwaq_source_analysis(&source_path, config.quick_mode).await
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        crate::scoring::category_to_cwes(&finding.category)
    }
}

/// Run skwaq's source analysis on a file and collect findings.
/// This invokes skwaq programmatically via skwaq-core, NOT as a subprocess.
async fn run_skwaq_source_analysis(
    path: &Path,
    quick: bool,
) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::analysis::{
        DangerousApiHit, TaintAnalyzer, TaintPath,
    };
    use skwaq_core::analysis::patterns_source::SourcePatternDetector;
    use skwaq_core::graph::GraphDb;

    let db = GraphDb::in_memory()?;
    let content = std::fs::read_to_string(path)?;
    let file_str = path.to_string_lossy().to_string();

    let mut findings = Vec::new();

    // 1. Pattern detection
    let detector = SourcePatternDetector::new();
    let hits = detector.detect(&content, &file_str);
    for hit in &hits {
        findings.push(DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: hit.category.to_string(),
            severity: hit.severity.to_string(),
            cwes: vec![],
            file: file_str.clone(),
            function: hit.function.clone().unwrap_or_default(),
            line: hit.line,
            title: format!("Dangerous API: {}", hit.api_name),
        });
    }

    // 2. Taint analysis (if not quick mode)
    if !quick {
        // Run taint analysis via the orchestrator for deeper detection.
        let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 2);
        // ... invoke orchestrator on the ingested content
    }

    Ok(findings)
}
```

### 3.3 CGC Adapter

```rust
// crates/gym/src/adapters/cgc.rs

use super::*;

pub struct CgcAdapter {
    manifest_path: PathBuf,
}

impl CgcAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait]
impl BenchmarkAdapter for CgcAdapter {
    fn name(&self) -> &str { "cgc" }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("cgc");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("cgc").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // CGC binaries are pre-built. No compilation needed.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // Run skwaq binary analysis on the CGC challenge binary.
        let binary_path = data_dir.join(&case.path);
        run_skwaq_binary_analysis(&binary_path, config.quick_mode).await
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        // CGC challenges are overwhelmingly memory corruption (CWE-119 family).
        crate::scoring::category_to_cwes(&finding.category)
    }
}

async fn run_skwaq_binary_analysis(
    path: &Path,
    quick: bool,
) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::binary;
    use skwaq_core::analysis::DangerousApiDetector;
    use skwaq_core::graph::GraphDb;

    let db = GraphDb::in_memory()?;
    let data = std::fs::read(path)?;
    let file_str = path.to_string_lossy().to_string();

    let mut findings = Vec::new();

    // 1. Checksec (hardening analysis)
    // Lack of hardening is informational, not a direct finding.

    // 2. Dangerous API detection in imports
    let detector = DangerousApiDetector::new(&db);
    let hits = detector.detect_in_binary(&data, &file_str)?;
    for hit in &hits {
        findings.push(DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: hit.category.to_string(),
            severity: hit.severity.to_string(),
            cwes: vec![],
            file: file_str.clone(),
            function: hit.function.clone(),
            line: None,
            title: format!("Dangerous import: {}", hit.api_name),
        });
    }

    // 3. Full analysis (non-quick) would invoke LLM agents.
    if !quick {
        // Invoke analysis orchestrator for deeper binary analysis.
    }

    Ok(findings)
}
```

### 3.4 CyberSecEval Adapter

```rust
// crates/gym/src/adapters/cyberseceval.rs

use super::*;

/// Meta's CyberSecEval is different from Juliet/CGC: it tests whether
/// an LLM-based system can detect insecure code or refuse to generate it.
/// We run skwaq's agent pipeline on CyberSecEval's code snippets
/// and check if skwaq correctly identifies the vulnerabilities.
pub struct CyberSecEvalAdapter {
    manifest_path: PathBuf,
}

impl CyberSecEvalAdapter {
    pub fn new(manifest_path: PathBuf) -> Self {
        Self { manifest_path }
    }
}

#[async_trait]
impl BenchmarkAdapter for CyberSecEvalAdapter {
    fn name(&self) -> &str { "cyberseceval" }

    fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
        GroundTruth::load(&self.manifest_path)
    }

    async fn setup(&self, config: &BenchmarkConfig) -> anyhow::Result<PathBuf> {
        let gt = self.ground_truth()?;
        let dest = config.cache_dir.join("cyberseceval");
        if dest.join(".ready").exists() {
            return Ok(dest);
        }
        download::download_and_extract(&gt.download_url, &gt.download_sha256, &dest).await?;
        std::fs::write(dest.join(".ready"), "")?;
        Ok(dest)
    }

    fn is_ready(&self, config: &BenchmarkConfig) -> bool {
        config.cache_dir.join("cyberseceval").join(".ready").exists()
    }

    async fn compile(&self, _data_dir: &Path, _config: &BenchmarkConfig) -> anyhow::Result<()> {
        // CyberSecEval is source snippets, no compilation.
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        // CyberSecEval cases are source code snippets in various languages.
        // Run skwaq source analysis (pattern + optional LLM).
        let source_path = data_dir.join(&case.path);
        run_skwaq_source_analysis(&source_path, config.quick_mode).await
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        crate::scoring::category_to_cwes(&finding.category)
    }
}
```

### 3.5 Fixtures Adapter

```rust
// crates/gym/src/adapters/fixtures.rs

use super::*;

/// Uses skwaq's own test fixtures (tests/fixtures/) as a mini benchmark.
/// These are small, hand-crafted programs with known vulnerabilities.
pub struct FixturesAdapter {
    manifest_path: PathBuf,
    fixtures_dir: PathBuf,
}

impl FixturesAdapter {
    pub fn new(manifest_path: PathBuf, fixtures_dir: PathBuf) -> Self {
        Self { manifest_path, fixtures_dir }
    }
}

#[async_trait]
impl BenchmarkAdapter for FixturesAdapter {
    fn name(&self) -> &str { "fixtures" }

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
        // Compile C fixtures using the Makefile already in tests/fixtures/.
        let status = std::process::Command::new("make")
            .arg("-C")
            .arg(data_dir)
            .arg("-j4")
            .status()?;
        if !status.success() {
            anyhow::bail!("Failed to compile test fixtures");
        }
        Ok(())
    }

    async fn run_case(
        &self,
        case: &TestCase,
        data_dir: &Path,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<DetectedFinding>> {
        let path = data_dir.join(&case.path);
        if case.language == "c" || case.language == "cpp" {
            run_skwaq_source_analysis(&path, config.quick_mode).await
        } else {
            run_skwaq_source_analysis(&path, config.quick_mode).await
        }
    }

    fn map_finding_to_cwes(&self, finding: &DetectedFinding) -> Vec<u32> {
        if !finding.cwes.is_empty() {
            return finding.cwes.clone();
        }
        crate::scoring::category_to_cwes(&finding.category)
    }
}
```

---

## 4. Scoring Engine

```rust
// crates/gym/src/scoring.rs

use crate::adapters::DetectedFinding;
use crate::ground_truth::TestCase;
use crate::history::{CaseResult, CweResult};
use std::collections::{HashMap, HashSet};

/// Outcome for a single test case.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    pub case_id: String,
    pub suite: String,
    pub expected_cwes: Vec<u32>,
    pub detected_cwes: Vec<u32>,
    pub matched_finding_ids: Vec<String>,
    pub unmatched_finding_ids: Vec<String>,
    /// Per expected CWE: was it detected?
    pub cwe_hits: HashMap<u32, bool>,
}

/// Aggregate scores for a set of case outcomes.
#[derive(Debug, Clone, Default)]
pub struct AggregateScore {
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub per_cwe: HashMap<u32, CweScore>,
}

#[derive(Debug, Clone, Default)]
pub struct CweScore {
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

/// Score a single test case against ground truth.
pub fn score_case(
    case: &TestCase,
    findings: &[DetectedFinding],
    finding_to_cwes: &dyn Fn(&DetectedFinding) -> Vec<u32>,
) -> CaseOutcome {
    let detected_cwe_set: HashSet<u32> = findings.iter()
        .flat_map(|f| finding_to_cwes(f))
        .collect();

    let expected_set: HashSet<u32> = case.expected_cwes.iter().copied().collect();

    // For each expected CWE, check if any detected CWE is in the same family.
    // "Same family" means they share a parent CWE or are the same CWE.
    let mut cwe_hits = HashMap::new();
    let mut matched_ids = Vec::new();
    let mut unmatched_ids: Vec<String> = Vec::new();

    for &expected in &case.expected_cwes {
        let family = cwe_family(expected);
        let hit = detected_cwe_set.iter().any(|&d| cwe_family(d) == family || d == expected);
        cwe_hits.insert(expected, hit);
    }

    // Classify findings as matched or unmatched.
    for f in findings {
        let f_cwes: HashSet<u32> = finding_to_cwes(f).into_iter().collect();
        let matches_any_expected = expected_set.iter().any(|&e| {
            let family = cwe_family(e);
            f_cwes.iter().any(|&d| cwe_family(d) == family || d == e)
        });
        if matches_any_expected {
            matched_ids.push(f.id.clone());
        } else {
            unmatched_ids.push(f.id.clone());
        }
    }

    CaseOutcome {
        case_id: case.id.clone(),
        suite: String::new(), // Set by caller.
        expected_cwes: case.expected_cwes.clone(),
        detected_cwes: detected_cwe_set.into_iter().collect(),
        matched_finding_ids: matched_ids,
        unmatched_finding_ids: unmatched_ids,
        cwe_hits,
    }
}

/// Map a specific CWE to its broad family for matching purposes.
/// E.g., CWE-121 and CWE-122 both map to CWE-119 (buffer overflow family).
pub fn cwe_family(cwe: u32) -> u32 {
    match cwe {
        // Buffer overflow family -> CWE-119
        120 | 121 | 122 | 124 | 125 | 126 | 127 | 787 => 119,
        // Use-after-free family -> CWE-416
        415 => 416,
        // Injection family -> CWE-74
        77 | 78 | 79 | 80 | 89 | 90 | 94 | 95 | 96 => 74,
        // Race condition family -> CWE-362
        367 => 362,
        // Integer overflow family -> CWE-190
        191 | 192 | 194 | 195 | 196 | 197 => 190,
        // Null pointer family -> CWE-476
        252 | 253 => 476,
        // Everything else maps to itself.
        other => other,
    }
}

/// Compute aggregate scores from a list of case outcomes.
pub fn aggregate(outcomes: &[CaseOutcome]) -> AggregateScore {
    let mut score = AggregateScore::default();
    let mut per_cwe: HashMap<u32, CweScore> = HashMap::new();

    for outcome in outcomes {
        if outcome.expected_cwes.is_empty() {
            // Negative test case.
            if outcome.detected_cwes.is_empty() {
                score.true_negatives += 1;
            } else {
                score.false_positives += outcome.unmatched_finding_ids.len() as u32;
            }
        } else {
            // Positive test case.
            for (&cwe, &hit) in &outcome.cwe_hits {
                let entry = per_cwe.entry(cwe_family(cwe)).or_insert_with(|| CweScore {
                    cwe_id: cwe_family(cwe),
                    ..Default::default()
                });
                entry.total_cases += 1;
                if hit {
                    entry.true_positives += 1;
                    score.true_positives += 1;
                } else {
                    entry.false_negatives += 1;
                    score.false_negatives += 1;
                }
            }
            // False positives: findings that don't match any expected CWE.
            score.false_positives += outcome.unmatched_finding_ids.len() as u32;
            for &cwe in &outcome.detected_cwes {
                let family = cwe_family(cwe);
                if !outcome.expected_cwes.iter().any(|&e| cwe_family(e) == family) {
                    let entry = per_cwe.entry(family).or_insert_with(|| CweScore {
                        cwe_id: family,
                        ..Default::default()
                    });
                    entry.false_positives += 1;
                }
            }
        }
    }

    // Compute rates.
    let tp = score.true_positives as f64;
    let fp = score.false_positives as f64;
    let fn_ = score.false_negatives as f64;

    score.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
    score.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
    score.f1 = if score.precision + score.recall > 0.0 {
        2.0 * score.precision * score.recall / (score.precision + score.recall)
    } else {
        0.0
    };

    for entry in per_cwe.values_mut() {
        let tp = entry.true_positives as f64;
        let fp = entry.false_positives as f64;
        let fn_ = entry.false_negatives as f64;
        entry.detection_rate = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        entry.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
    }

    score.per_cwe = per_cwe;
    score
}

/// Default mapping from skwaq DangerCategory to CWE IDs.
pub fn category_to_cwes(category: &str) -> Vec<u32> {
    match category {
        "memory" => vec![119, 120, 121, 122, 125, 126, 787, 416, 415],
        "injection" => vec![78, 89, 90, 94, 77],
        "format_string" => vec![134],
        "race" => vec![362, 367],
        "temp_file" => vec![377],
        "path_traversal" => vec![22, 23, 36],
        "deserialization" => vec![502],
        "crypto" => vec![326, 327, 328, 330],
        "unsafe_code" => vec![676],
        "prototype_pollution" => vec![1321],
        "xss" => vec![79, 80],
        _ => vec![],
    }
}
```

---

## 5. Reporting

### 5.1 Terminal Report

```rust
// crates/gym/src/reporting/terminal.rs

use crate::history::{BenchmarkRun, CweResult, HistoryDb};
use crate::scoring::AggregateScore;

/// Print a rich terminal report of benchmark results.
/// Uses ANSI escape codes for colors (no heavy TUI dependency).
pub fn print_summary(score: &AggregateScore, suite: &str) {
    println!("\n{}", "=".repeat(70));
    println!("  SKWAQ GYM RESULTS: {}", suite.to_uppercase());
    println!("{}", "=".repeat(70));
    println!();
    println!("  Precision:  {:.1}%", score.precision * 100.0);
    println!("  Recall:     {:.1}%", score.recall * 100.0);
    println!("  F1 Score:   {:.1}%", score.f1 * 100.0);
    println!();
    println!("  TP: {}  FP: {}  FN: {}  TN: {}",
        score.true_positives, score.false_positives,
        score.false_negatives, score.true_negatives);
    println!();

    // Per-CWE detection rates (sorted by detection rate ascending = worst first).
    let mut cwes: Vec<_> = score.per_cwe.values().collect();
    cwes.sort_by(|a, b| a.detection_rate.partial_cmp(&b.detection_rate).unwrap());

    println!("  {:>8} {:>8} {:>8} {:>8} {:>10} {:>10}",
        "CWE", "Cases", "TP", "FN", "Detect%", "Prec%");
    println!("  {}", "-".repeat(62));

    for cwe in &cwes {
        let detect_color = if cwe.detection_rate >= 0.8 { "\x1b[32m" }  // green
            else if cwe.detection_rate >= 0.5 { "\x1b[33m" }  // yellow
            else { "\x1b[31m" };  // red
        println!("  {:>8} {:>8} {:>8} {:>8} {}{:>9.1}%\x1b[0m {:>9.1}%",
            cwe.cwe_id, cwe.total_cases, cwe.true_positives, cwe.false_negatives,
            detect_color, cwe.detection_rate * 100.0, cwe.precision * 100.0);
    }
    println!();
}

/// Print a comparison between two runs.
pub fn print_comparison(previous: &BenchmarkRun, current: &BenchmarkRun) {
    println!("\n{}", "=".repeat(70));
    println!("  IMPROVEMENT COMPARISON");
    println!("{}", "=".repeat(70));
    println!();

    let delta_f1 = current.f1 - previous.f1;
    let delta_p = current.precision - previous.precision;
    let delta_r = current.recall - previous.recall;

    let arrow = |d: f64| if d > 0.0 { "\x1b[32m+\x1b[0m" }
        else if d < 0.0 { "\x1b[31m" } else { " " };

    println!("  {:>12} {:>10} {:>10} {:>10}",
        "", "Previous", "Current", "Delta");
    println!("  {}", "-".repeat(46));
    println!("  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%",
        "Precision", previous.precision * 100.0, current.precision * 100.0, delta_p * 100.0);
    println!("  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%",
        "Recall", previous.recall * 100.0, current.recall * 100.0, delta_r * 100.0);
    println!("  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%",
        "F1", previous.f1 * 100.0, current.f1 * 100.0, delta_f1 * 100.0);
    println!();

    if delta_f1 > 0.0 {
        println!("  Overall: IMPROVED");
    } else if delta_f1 < 0.0 {
        println!("  Overall: REGRESSED");
    } else {
        println!("  Overall: No change");
    }
    println!();
}
```

### 5.2 JSON Report

```rust
// crates/gym/src/reporting/json_report.rs

use crate::scoring::AggregateScore;
use serde::Serialize;

#[derive(Serialize)]
pub struct JsonReport {
    pub suite: String,
    pub timestamp: String,
    pub skwaq_commit: String,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
    pub per_cwe: Vec<JsonCweResult>,
}

#[derive(Serialize)]
pub struct JsonCweResult {
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

pub fn generate(score: &AggregateScore, suite: &str, commit: &str) -> String {
    let report = JsonReport {
        suite: suite.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        skwaq_commit: commit.to_string(),
        precision: score.precision,
        recall: score.recall,
        f1: score.f1,
        true_positives: score.true_positives,
        false_positives: score.false_positives,
        false_negatives: score.false_negatives,
        true_negatives: score.true_negatives,
        per_cwe: score.per_cwe.values().map(|c| JsonCweResult {
            cwe_id: c.cwe_id,
            total_cases: c.total_cases,
            true_positives: c.true_positives,
            false_positives: c.false_positives,
            false_negatives: c.false_negatives,
            detection_rate: c.detection_rate,
            precision: c.precision,
        }).collect(),
    };
    serde_json::to_string_pretty(&report).unwrap_or_default()
}
```

### 5.3 Markdown Report

```rust
// crates/gym/src/reporting/markdown_report.rs

use crate::scoring::AggregateScore;

pub fn generate(score: &AggregateScore, suite: &str, commit: &str) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Skwaq Gym Results: {}\n\n", suite));
    md.push_str(&format!("**Commit**: `{}`\n", commit));
    md.push_str(&format!("**Date**: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")));

    md.push_str("## Summary\n\n");
    md.push_str(&format!("| Metric | Value |\n"));
    md.push_str(&format!("|--------|-------|\n"));
    md.push_str(&format!("| Precision | {:.1}% |\n", score.precision * 100.0));
    md.push_str(&format!("| Recall | {:.1}% |\n", score.recall * 100.0));
    md.push_str(&format!("| F1 Score | {:.1}% |\n", score.f1 * 100.0));
    md.push_str(&format!("| True Positives | {} |\n", score.true_positives));
    md.push_str(&format!("| False Positives | {} |\n", score.false_positives));
    md.push_str(&format!("| False Negatives | {} |\n", score.false_negatives));
    md.push_str(&format!("| True Negatives | {} |\n\n", score.true_negatives));

    md.push_str("## Per-CWE Detection Rates\n\n");
    md.push_str("| CWE | Cases | TP | FN | Detection % | Precision % |\n");
    md.push_str("|-----|-------|----|----|-------------|-------------|\n");

    let mut cwes: Vec<_> = score.per_cwe.values().collect();
    cwes.sort_by(|a, b| a.detection_rate.partial_cmp(&b.detection_rate).unwrap());

    for cwe in &cwes {
        let emoji = if cwe.detection_rate >= 0.8 { "+" }
            else if cwe.detection_rate >= 0.5 { "~" }
            else { "-" };
        md.push_str(&format!("| CWE-{} {} | {} | {} | {} | {:.1}% | {:.1}% |\n",
            cwe.cwe_id, emoji, cwe.total_cases, cwe.true_positives,
            cwe.false_negatives, cwe.detection_rate * 100.0, cwe.precision * 100.0));
    }

    md.push_str("\n\n_Legend: + >80% detection, ~ 50-80%, - <50%_\n");
    md
}
```

---

## 6. Self-Improvement Loop

This is the most important part. The improvement loop analyzes failures, proposes changes to skwaq's pattern files and agent prompts, applies them, re-runs the affected benchmarks, and only keeps changes that improve metrics without regressions.

```rust
// crates/gym/src/improve.rs

use crate::adapters::{BenchmarkAdapter, BenchmarkConfig, DetectedFinding};
use crate::ground_truth::TestCase;
use crate::history::{BenchmarkRun, HistoryDb};
use crate::scoring::{self, AggregateScore, CaseOutcome};
use std::path::{Path, PathBuf};

/// A proposed improvement to skwaq.
#[derive(Debug, Clone)]
pub struct Improvement {
    /// What kind of change this is.
    pub kind: ImprovementKind,
    /// Human-readable description.
    pub description: String,
    /// Which CWEs this improvement targets.
    pub target_cwes: Vec<u32>,
    /// The file to modify.
    pub target_file: PathBuf,
    /// The change to make (old content -> new content).
    pub patch: Patch,
}

#[derive(Debug, Clone)]
pub enum ImprovementKind {
    /// Add a new dangerous API pattern to patterns_source.rs or patterns_binary.rs.
    NewPattern,
    /// Improve an agent prompt in agents/*.md.
    AgentPrompt,
    /// Add a new CWE mapping.
    CweMapping,
    /// Add a new taint source/sink.
    TaintRule,
}

#[derive(Debug, Clone)]
pub struct Patch {
    /// Content to find (empty for append).
    pub find: String,
    /// Content to replace with (or content to append).
    pub replace: String,
}

/// Result of an improvement attempt.
#[derive(Debug)]
pub struct ImprovementResult {
    pub improvement: Improvement,
    pub baseline_score: AggregateScore,
    pub new_score: AggregateScore,
    pub accepted: bool,
    pub reason: String,
}

/// The self-improvement loop algorithm.
///
/// 1. Run baseline benchmark on affected CWEs.
/// 2. Analyze false negatives to identify patterns of missed detections.
/// 3. Generate improvement proposals (new patterns, better prompts, etc.).
/// 4. For each proposal:
///    a. Apply the patch.
///    b. Re-run the affected CWE benchmarks.
///    c. If F1 improved AND no regressions on other CWEs: KEEP.
///    d. Otherwise: REVERT.
/// 5. Report results.
pub struct ImprovementLoop {
    history_db: HistoryDb,
    skwaq_root: PathBuf,
}

impl ImprovementLoop {
    pub fn new(history_db: HistoryDb, skwaq_root: PathBuf) -> Self {
        Self { history_db, skwaq_root }
    }

    /// Run the full improvement loop.
    pub async fn run(
        &self,
        adapter: &dyn BenchmarkAdapter,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<ImprovementResult>> {
        let mut results = Vec::new();

        // Step 1: Get baseline from the most recent run.
        let recent = self.history_db.recent_runs(1)?;
        let baseline_run = recent.first()
            .ok_or_else(|| anyhow::anyhow!("No previous runs. Run `skwaq gym run` first."))?;

        // Step 2: Identify worst-performing CWEs.
        let cwe_results = self.history_db.cwe_results_for_run(&baseline_run.id)?;
        let weak_cwes: Vec<_> = cwe_results.iter()
            .filter(|c| c.detection_rate < 0.5 && c.total_cases >= 5)
            .collect();

        if weak_cwes.is_empty() {
            tracing::info!("No weak CWEs with sufficient test cases found. Nothing to improve.");
            return Ok(results);
        }

        tracing::info!("Found {} weak CWEs to improve", weak_cwes.len());

        // Step 3: For each weak CWE, analyze failures and propose improvements.
        for weak in &weak_cwes {
            let proposals = self.analyze_failures_and_propose(weak.cwe_id, adapter, config).await?;

            for proposal in proposals {
                let result = self.try_improvement(proposal, adapter, config).await?;
                let accepted = result.accepted;
                results.push(result);

                // If this improvement was accepted, the baseline has shifted.
                // Continue with updated state.
                if accepted {
                    tracing::info!("Improvement accepted, continuing with updated baseline.");
                }
            }
        }

        Ok(results)
    }

    /// Analyze false negatives for a CWE and propose improvements.
    async fn analyze_failures_and_propose(
        &self,
        cwe_id: u32,
        adapter: &dyn BenchmarkAdapter,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<Vec<Improvement>> {
        let mut proposals = Vec::new();

        // Strategy 1: Check if the CWE's typical dangerous APIs are in our pattern list.
        let missing_patterns = self.find_missing_patterns_for_cwe(cwe_id);
        for (api_name, category) in missing_patterns {
            proposals.push(Improvement {
                kind: ImprovementKind::NewPattern,
                description: format!("Add pattern for '{}' (CWE-{})", api_name, cwe_id),
                target_cwes: vec![cwe_id],
                target_file: self.skwaq_root.join("crates/core/src/analysis/patterns_source.rs"),
                patch: Patch {
                    find: String::new(), // Append
                    replace: format!(
                        r#"    SourcePattern {{ name: "{api_name}", category: DangerCategory::{category}, severity: Severity::High, languages: &["c", "cpp"], regex: r"\b{api_name}\s*\(" }},"#,
                    ),
                },
            });
        }

        // Strategy 2: Check if taint sources/sinks for this CWE family are covered.
        // Strategy 3: If using LLM agents, propose prompt improvements.

        Ok(proposals)
    }

    /// Look up which dangerous APIs are commonly associated with a CWE
    /// but not yet in skwaq's pattern lists.
    fn find_missing_patterns_for_cwe(&self, cwe_id: u32) -> Vec<(String, String)> {
        // CWE -> typical vulnerable APIs mapping.
        // This is a curated knowledge base.
        let cwe_apis: std::collections::HashMap<u32, Vec<(&str, &str)>> = [
            (119, vec![("memcpy", "Memory"), ("memmove", "Memory"), ("bcopy", "Memory")]),
            (120, vec![("strcpy", "Memory"), ("strcat", "Memory"), ("gets", "Memory")]),
            (134, vec![("printf", "FormatString"), ("fprintf", "FormatString"), ("syslog", "FormatString")]),
            (190, vec![("atoi", "Memory"), ("strtol", "Memory")]),
            (416, vec![("free", "Memory")]),
            (78, vec![("system", "Injection"), ("popen", "Injection"), ("execvp", "Injection")]),
            (89, vec![("mysql_query", "Injection"), ("sqlite3_exec", "Injection")]),
            (22, vec![("realpath", "PathTraversal"), ("readlink", "PathTraversal")]),
        ].into_iter().collect();

        let family = scoring::cwe_family(cwe_id);
        let apis = cwe_apis.get(&family).cloned().unwrap_or_default();

        // Check which ones are already in our pattern list.
        let patterns_file = self.skwaq_root
            .join("crates/core/src/analysis/patterns_source.rs");
        let patterns_content = std::fs::read_to_string(&patterns_file).unwrap_or_default();

        apis.into_iter()
            .filter(|(name, _)| !patterns_content.contains(name))
            .map(|(name, cat)| (name.to_string(), cat.to_string()))
            .collect()
    }

    /// Try applying an improvement, benchmark it, and accept or revert.
    async fn try_improvement(
        &self,
        improvement: Improvement,
        adapter: &dyn BenchmarkAdapter,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<ImprovementResult> {
        tracing::info!("Trying improvement: {}", improvement.description);

        // 1. Read baseline score for target CWEs.
        let baseline_config = BenchmarkConfig {
            cwe_filter: Some(improvement.target_cwes.clone()),
            max_cases: Some(100), // Cap for speed during improvement loop.
            ..*config
        };
        let baseline_score = self.run_and_score(adapter, &baseline_config).await?;

        // 2. Apply the patch.
        let original_content = std::fs::read_to_string(&improvement.target_file)?;
        let new_content = if improvement.patch.find.is_empty() {
            // Append mode: add before the closing bracket/array.
            original_content.replace(
                "]; // END_PATTERNS",
                &format!("{}\n]; // END_PATTERNS", improvement.patch.replace),
            )
        } else {
            original_content.replace(&improvement.patch.find, &improvement.patch.replace)
        };
        std::fs::write(&improvement.target_file, &new_content)?;

        // 3. Re-run the benchmark.
        let new_score = self.run_and_score(adapter, &baseline_config).await?;

        // 4. Decision: accept if F1 improved and no CWE regressed.
        let f1_improved = new_score.f1 > baseline_score.f1;
        let no_regression = !has_cwe_regression(&baseline_score, &new_score);
        let accepted = f1_improved && no_regression;

        let reason = if accepted {
            format!("F1 improved from {:.1}% to {:.1}%",
                baseline_score.f1 * 100.0, new_score.f1 * 100.0)
        } else if !f1_improved {
            format!("F1 did not improve ({:.1}% -> {:.1}%)",
                baseline_score.f1 * 100.0, new_score.f1 * 100.0)
        } else {
            "Regression detected on other CWEs".to_string()
        };

        // 5. Revert if not accepted.
        if !accepted {
            std::fs::write(&improvement.target_file, &original_content)?;
            tracing::info!("Reverted: {}", reason);
        } else {
            tracing::info!("Accepted: {}", reason);
        }

        Ok(ImprovementResult {
            improvement,
            baseline_score,
            new_score,
            accepted,
            reason,
        })
    }

    /// Run a benchmark suite and return the aggregate score.
    async fn run_and_score(
        &self,
        adapter: &dyn BenchmarkAdapter,
        config: &BenchmarkConfig,
    ) -> anyhow::Result<AggregateScore> {
        let gt = adapter.ground_truth()?;
        let data_dir = adapter.setup(config).await?;

        let cases: Vec<_> = gt.cases.iter()
            .filter(|c| {
                config.cwe_filter.as_ref().map_or(true, |f| {
                    c.expected_cwes.iter().any(|cwe| f.contains(cwe))
                })
            })
            .take(config.max_cases.unwrap_or(usize::MAX))
            .collect();

        let mut outcomes = Vec::new();
        for case in &cases {
            let findings = adapter.run_case(case, &data_dir, config).await?;
            let outcome = scoring::score_case(
                case,
                &findings,
                &|f| adapter.map_finding_to_cwes(f),
            );
            outcomes.push(outcome);
        }

        Ok(scoring::aggregate(&outcomes))
    }
}

/// Check if any CWE's detection rate dropped.
fn has_cwe_regression(baseline: &AggregateScore, new: &AggregateScore) -> bool {
    for (cwe_id, baseline_cwe) in &baseline.per_cwe {
        if let Some(new_cwe) = new.per_cwe.get(cwe_id) {
            // Allow up to 2% regression (noise margin).
            if new_cwe.detection_rate < baseline_cwe.detection_rate - 0.02 {
                return true;
            }
        }
    }
    false
}
```

---

## 7. Main Orchestrator

```rust
// crates/gym/src/lib.rs

pub mod adapters;
pub mod download;
pub mod ground_truth;
pub mod history;
pub mod improve;
pub mod reporting;
pub mod scoring;

use adapters::{
    BenchmarkAdapter, BenchmarkConfig,
    cgc::CgcAdapter, cyberseceval::CyberSecEvalAdapter,
    fixtures::FixturesAdapter, juliet::JulietAdapter,
};
use history::HistoryDb;
use std::path::PathBuf;

/// Top-level gym runner that coordinates all suites.
pub struct Gym {
    history_db: HistoryDb,
    adapters: Vec<Box<dyn BenchmarkAdapter>>,
    config: BenchmarkConfig,
    skwaq_root: PathBuf,
}

impl Gym {
    pub fn new(skwaq_root: PathBuf) -> anyhow::Result<Self> {
        let gym_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("skwaq")
            .join("gym");

        let history_db = HistoryDb::open(&gym_dir.join("results.db"))?;

        let gt_dir = skwaq_root.join("data/gym/ground_truth");
        let cache_dir = gym_dir.join("cache");

        let adapters: Vec<Box<dyn BenchmarkAdapter>> = vec![
            Box::new(JulietAdapter::new(gt_dir.join("juliet.toml"))),
            Box::new(CgcAdapter::new(gt_dir.join("cgc.toml"))),
            Box::new(CyberSecEvalAdapter::new(gt_dir.join("cyberseceval.toml"))),
            Box::new(FixturesAdapter::new(
                gt_dir.join("fixtures.toml"),
                skwaq_root.join("tests/fixtures"),
            )),
        ];

        let config = BenchmarkConfig {
            cache_dir,
            cwe_filter: None,
            max_cases: None,
            quick_mode: true,
            parallelism: num_cpus::get(),
        };

        Ok(Self { history_db, adapters, config, skwaq_root })
    }

    /// Setup all benchmark data.
    pub async fn setup(&self) -> anyhow::Result<()> {
        for adapter in &self.adapters {
            if !adapter.is_ready(&self.config) {
                tracing::info!("Setting up {}...", adapter.name());
                let data_dir = adapter.setup(&self.config).await?;
                adapter.compile(&data_dir, &self.config).await?;
            } else {
                tracing::info!("{} already set up.", adapter.name());
            }
        }
        Ok(())
    }

    /// Run a specific suite or all suites.
    pub async fn run(&self, suite: Option<&str>, cwe_filter: Option<Vec<u32>>) -> anyhow::Result<()> {
        let commit = get_git_commit(&self.skwaq_root)?;

        let adapters: Vec<_> = match suite {
            Some(name) => self.adapters.iter()
                .filter(|a| a.name() == name)
                .collect(),
            None => self.adapters.iter().collect(),
        };

        if adapters.is_empty() {
            anyhow::bail!("Unknown suite. Available: juliet, cgc, cyberseceval, fixtures");
        }

        let mut config = self.config.clone();
        config.cwe_filter = cwe_filter;

        for adapter in adapters {
            let suite_name = adapter.name().to_string();
            tracing::info!("Running {} benchmark...", suite_name);

            let run_id = self.history_db.start_run(&suite_name, &commit)?;
            let gt = adapter.ground_truth()?;
            let data_dir = adapter.setup(&config).await?;

            let cases: Vec<_> = gt.cases.iter()
                .filter(|c| {
                    config.cwe_filter.as_ref().map_or(true, |f| {
                        c.expected_cwes.iter().any(|cwe| f.contains(cwe)) || c.expected_cwes.is_empty()
                    })
                })
                .take(config.max_cases.unwrap_or(usize::MAX))
                .collect();

            let mut outcomes = Vec::new();
            let total = cases.len();

            for (i, case) in cases.iter().enumerate() {
                if i % 100 == 0 {
                    tracing::info!("[{}/{}] Processing {}", i, total, case.id);
                }
                let findings = adapter.run_case(case, &data_dir, &config).await?;
                let outcome = scoring::score_case(
                    case,
                    &findings,
                    &|f| adapter.map_finding_to_cwes(f),
                );
                outcomes.push(outcome);
            }

            let score = scoring::aggregate(&outcomes);

            // Save results.
            let run = history::BenchmarkRun {
                id: run_id.clone(),
                started_at: chrono::Utc::now(),
                finished_at: Some(chrono::Utc::now()),
                suite: suite_name.clone(),
                skwaq_commit: commit.clone(),
                precision: score.precision,
                recall: score.recall,
                f1: score.f1,
                true_positives: score.true_positives,
                false_positives: score.false_positives,
                false_negatives: score.false_negatives,
                true_negatives: score.true_negatives,
            };
            self.history_db.finish_run(&run)?;

            for cwe_score in score.per_cwe.values() {
                self.history_db.insert_cwe_result(&history::CweResult {
                    run_id: run_id.clone(),
                    cwe_id: cwe_score.cwe_id,
                    total_cases: cwe_score.total_cases,
                    true_positives: cwe_score.true_positives,
                    false_positives: cwe_score.false_positives,
                    false_negatives: cwe_score.false_negatives,
                    detection_rate: cwe_score.detection_rate,
                    precision: cwe_score.precision,
                })?;
            }

            // Print terminal report.
            reporting::terminal::print_summary(&score, &suite_name);
        }

        Ok(())
    }

    /// Show the most recent report.
    pub fn report(&self, format: ReportFormat) -> anyhow::Result<String> {
        let runs = self.history_db.recent_runs(1)?;
        let run = runs.first()
            .ok_or_else(|| anyhow::anyhow!("No runs yet. Run `skwaq gym run` first."))?;

        let cwe_results = self.history_db.cwe_results_for_run(&run.id)?;
        let score = reconstruct_score(run, &cwe_results);

        match format {
            ReportFormat::Terminal => {
                reporting::terminal::print_summary(&score, &run.suite);
                Ok(String::new())
            }
            ReportFormat::Json => {
                Ok(reporting::json_report::generate(&score, &run.suite, &run.skwaq_commit))
            }
            ReportFormat::Markdown => {
                Ok(reporting::markdown_report::generate(&score, &run.suite, &run.skwaq_commit))
            }
        }
    }

    /// Compare the two most recent runs.
    pub fn compare(&self) -> anyhow::Result<()> {
        let runs = self.history_db.recent_runs(2)?;
        if runs.len() < 2 {
            anyhow::bail!("Need at least 2 runs to compare. Run `skwaq gym run` twice.");
        }
        reporting::terminal::print_comparison(&runs[1], &runs[0]);
        Ok(())
    }

    /// Show run history.
    pub fn history(&self, limit: u32) -> anyhow::Result<()> {
        let runs = self.history_db.recent_runs(limit)?;
        println!("\n{:>4} {:>19} {:>8} {:>8} {:>8} {:>8} {:>6}",
            "#", "Date", "Suite", "Prec%", "Rec%", "F1%", "Commit");
        println!("{}", "-".repeat(80));
        for (i, run) in runs.iter().enumerate() {
            println!("{:>4} {:>19} {:>8} {:>7.1}% {:>7.1}% {:>7.1}% {:>6}",
                i + 1,
                run.started_at.format("%Y-%m-%d %H:%M"),
                run.suite,
                run.precision * 100.0,
                run.recall * 100.0,
                run.f1 * 100.0,
                &run.skwaq_commit[..6.min(run.skwaq_commit.len())]);
        }
        println!();
        Ok(())
    }

    /// Run the self-improvement loop.
    pub async fn improve(&self) -> anyhow::Result<()> {
        let history_db = HistoryDb::open(
            &dirs::data_dir().unwrap().join("skwaq/gym/results.db")
        )?;
        let loop_ = improve::ImprovementLoop::new(history_db, self.skwaq_root.clone());

        // Run improvement on each adapter.
        for adapter in &self.adapters {
            let results = loop_.run(adapter.as_ref(), &self.config).await?;
            for result in &results {
                let status = if result.accepted { "ACCEPTED" } else { "REJECTED" };
                println!("  [{}] {}: {}", status, result.improvement.description, result.reason);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Terminal,
    Json,
    Markdown,
}

fn get_git_commit(repo: &std::path::Path) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn reconstruct_score(
    run: &history::BenchmarkRun,
    cwe_results: &[history::CweResult],
) -> scoring::AggregateScore {
    let mut per_cwe = std::collections::HashMap::new();
    for cr in cwe_results {
        per_cwe.insert(cr.cwe_id, scoring::CweScore {
            cwe_id: cr.cwe_id,
            total_cases: cr.total_cases,
            true_positives: cr.true_positives,
            false_positives: cr.false_positives,
            false_negatives: cr.false_negatives,
            detection_rate: cr.detection_rate,
            precision: cr.precision,
        });
    }
    scoring::AggregateScore {
        true_positives: run.true_positives,
        false_positives: run.false_positives,
        false_negatives: run.false_negatives,
        true_negatives: run.true_negatives,
        precision: run.precision,
        recall: run.recall,
        f1: run.f1,
        per_cwe,
    }
}
```

---

## 8. CLI Integration

```rust
// crates/cli/src/commands/gym_cmd.rs

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GymSub {
    /// Download and prepare all benchmark data
    Setup,

    /// Run benchmarks
    Run {
        /// Suite name (juliet, cgc, cyberseceval, fixtures). Omit for all.
        suite: Option<String>,

        /// Filter to specific CWE (e.g., CWE-119)
        #[arg(long)]
        cwe: Option<String>,

        /// Maximum test cases per suite (for quick validation)
        #[arg(long)]
        max_cases: Option<usize>,

        /// Use full analysis (default is quick mode)
        #[arg(long)]
        full: bool,

        /// Output JSON report to file
        #[arg(long)]
        json: Option<PathBuf>,

        /// Output Markdown report to file
        #[arg(long)]
        markdown: Option<PathBuf>,
    },

    /// Show latest benchmark results
    Report {
        /// Output format (terminal, json, markdown)
        #[arg(long, default_value = "terminal")]
        format: String,
    },

    /// Compare last two runs
    Compare,

    /// Run self-improvement loop
    Improve,

    /// Show benchmark history
    History {
        /// Number of runs to show
        #[arg(long, default_value = "10")]
        limit: u32,
    },
}

pub async fn run(sub: &GymSub) -> anyhow::Result<()> {
    // Determine skwaq root (workspace root).
    let skwaq_root = std::env::current_dir()?;
    let gym = skwaq_gym::Gym::new(skwaq_root)?;

    match sub {
        GymSub::Setup => {
            gym.setup().await?;
            println!("All benchmarks set up.");
        }
        GymSub::Run { suite, cwe, max_cases, full, json, markdown } => {
            let cwe_filter = cwe.as_ref().map(|c| {
                let num: u32 = c.trim_start_matches("CWE-")
                    .trim_start_matches("cwe-")
                    .parse()
                    .expect("Invalid CWE number");
                vec![num]
            });
            gym.run(suite.as_deref(), cwe_filter).await?;

            if let Some(path) = json {
                let report = gym.report(skwaq_gym::ReportFormat::Json)?;
                std::fs::write(path, report)?;
            }
            if let Some(path) = markdown {
                let report = gym.report(skwaq_gym::ReportFormat::Markdown)?;
                std::fs::write(path, report)?;
            }
        }
        GymSub::Report { format } => {
            let fmt = match format.as_str() {
                "json" => skwaq_gym::ReportFormat::Json,
                "markdown" | "md" => skwaq_gym::ReportFormat::Markdown,
                _ => skwaq_gym::ReportFormat::Terminal,
            };
            let output = gym.report(fmt)?;
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        GymSub::Compare => {
            gym.compare()?;
        }
        GymSub::Improve => {
            gym.improve().await?;
        }
        GymSub::History { limit } => {
            gym.history(*limit)?;
        }
    }

    Ok(())
}
```

Add to the CLI command enum in `crates/cli/src/commands/mod.rs`:

```rust
// Add to the Commands enum:
    /// Benchmark and self-improvement harness
    Gym {
        #[command(subcommand)]
        sub: GymSub,
    },

// Add to main.rs match:
    Commands::Gym { sub } => {
        skwaq::commands::gym_cmd::run(sub).await?;
    }
```

Add to workspace `Cargo.toml`:

```toml
[workspace]
members = ["crates/core", "crates/cli", "crates/gym"]
```

Add `skwaq-gym` as a dependency in `crates/cli/Cargo.toml`:

```toml
skwaq-gym = { path = "../gym" }
```

---

## 9. Download Manager

```rust
// crates/gym/src/download.rs

use sha2::{Sha256, Digest};
use std::path::Path;

/// Download a file, verify its SHA-256, and extract it.
pub async fn download_and_extract(
    url: &str,
    expected_sha256: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;

    let tmp = tempfile::NamedTempFile::new()?;
    let tmp_path = tmp.path().to_path_buf();

    // Download.
    tracing::info!("Downloading {}...", url);
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    std::fs::write(&tmp_path, &bytes)?;

    // Verify SHA-256.
    if !expected_sha256.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = format!("{:x}", hasher.finalize());
        if hash != expected_sha256 {
            anyhow::bail!(
                "SHA-256 mismatch for {}:\n  expected: {}\n  got:      {}",
                url, expected_sha256, hash
            );
        }
    }

    // Extract based on extension.
    if url.ends_with(".zip") {
        extract_zip(&tmp_path, dest)?;
    } else if url.ends_with(".tar.gz") || url.ends_with(".tgz") {
        extract_tar_gz(&tmp_path, dest)?;
    } else {
        // Single file, just copy.
        let filename = url.rsplit('/').next().unwrap_or("data");
        std::fs::copy(&tmp_path, dest.join(filename))?;
    }

    Ok(())
}

fn extract_zip(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(archive)?;
    let mut archive = zip::ZipArchive::new(file)?;
    archive.extract(dest)?;
    Ok(())
}

fn extract_tar_gz(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);
    tar.unpack(dest)?;
    Ok(())
}
```

---

## 10. CI Integration

Running the full Juliet suite (81K cases) takes hours. CI needs a fast path.

### Strategy: Tiered Benchmarks

| Tier | What | Cases | Time | When |
|------|------|-------|------|------|
| **smoke** | Fixtures only | ~10 | <30s | Every PR |
| **quick** | 100 cases per suite, quick mode | ~400 | <5min | Nightly |
| **full** | All cases, quick mode | ~82K | ~2hr | Weekly |
| **deep** | All cases, full analysis (LLM) | ~82K | ~8hr | Release |

### CI Workflow (GitHub Actions)

```yaml
# .github/workflows/gym-smoke.yml
name: Gym Smoke
on: [pull_request]
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: cargo run --release -- gym run fixtures --max-cases 50 --json gym-results.json
      - uses: actions/upload-artifact@v4
        with:
          name: gym-smoke-results
          path: gym-results.json

# .github/workflows/gym-nightly.yml
name: Gym Nightly
on:
  schedule:
    - cron: '0 2 * * *'
jobs:
  nightly:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: sudo apt-get install -y gcc g++
      - run: cargo build --release
      - run: cargo run --release -- gym setup
      - run: cargo run --release -- gym run --max-cases 100 --json gym-nightly.json --markdown gym-nightly.md
      - uses: actions/upload-artifact@v4
        with:
          name: gym-nightly-results
          path: |
            gym-nightly.json
            gym-nightly.md
```

### CI Regression Gate

The nightly job can fail the build if F1 drops below a threshold:

```rust
// In gym_cmd.rs run handler, after run completes:
if let Some(threshold) = std::env::var("SKWAQ_GYM_MIN_F1").ok()
    .and_then(|s| s.parse::<f64>().ok())
{
    let runs = gym.history_db.recent_runs(1)?;
    if let Some(run) = runs.first() {
        if run.f1 < threshold {
            eprintln!("FAIL: F1 score {:.1}% below threshold {:.1}%",
                run.f1 * 100.0, threshold * 100.0);
            std::process::exit(1);
        }
    }
}
```

Set `SKWAQ_GYM_MIN_F1=0.3` in CI environment to enforce a minimum F1 score.

---

## 11. Ground Truth Manifest Generation

The TOML manifests in `data/gym/ground_truth/` are large (Juliet has 81K entries). A one-time script generates them from the benchmark data:

```bash
# scripts/generate-juliet-manifest.sh
# Run this once after downloading Juliet, then check in the .toml file.
# The script walks the Juliet directory structure and emits TOML.

#!/bin/bash
JULIET_DIR=$1
echo 'suite = "juliet"'
echo 'version = "1.3"'
echo 'download_url = "https://samate.nist.gov/SARD/downloads/test-suites/juliet/Juliet_Test_Suite_v1.3_for_C_Cpp.zip"'
echo 'download_sha256 = ""'
echo ''

find "$JULIET_DIR/testcases" -name "*.c" -o -name "*.cpp" | sort | while read f; do
    relpath="${f#$JULIET_DIR/}"
    basename=$(basename "$f" | sed 's/\.\(c\|cpp\)$//')
    # Extract CWE number
    cwe=$(echo "$relpath" | grep -oP 'CWE\K[0-9]+' | head -1)
    # Detect if "good" variant
    is_good=false
    if echo "$basename" | grep -q "_good"; then
        is_good=true
    fi

    ext="${f##*.}"
    lang="c"
    [ "$ext" = "cpp" ] && lang="cpp"

    echo '[[cases]]'
    echo "id = \"$basename\""
    echo "path = \"$relpath\""
    if [ "$is_good" = true ]; then
        echo "expected_cwes = []"
        echo "is_negative = true"
    else
        echo "expected_cwes = [$cwe]"
        echo "is_negative = false"
    fi
    echo "language = \"$lang\""
    echo ""
done
```

For CGC, the manifest maps challenge names to CWE categories based on the DARPA metadata files included in the CGC corpus.

---

## 12. Design Decisions and Trade-offs

### Why a separate crate, not a module in core?

The gym depends on all of skwaq-core (it runs the full analysis pipeline) plus heavy additional dependencies (zip, tar, flate2, rayon, indicatif). Keeping it in a separate crate means `cargo build` for normal skwaq usage doesn't pull in benchmark dependencies. It also keeps the gym code clearly isolated from production analysis code.

### Why SQLite for history, not the main graph DB?

The gym's data model is purely relational (runs, CWE results, case results). The graph DB is for program analysis artifacts (functions, call graphs, taint flows). Mixing them would pollute the analysis database. SQLite is already a workspace dependency.

### Why CWE-family matching instead of exact CWE matching?

Skwaq's `DangerCategory` groups multiple CWEs together (e.g., "memory" covers CWE-119 through CWE-787). Requiring exact CWE-121 vs CWE-122 matching would penalize skwaq for correctly finding a buffer overflow but labeling it as the parent category. Family matching is standard practice in SAST benchmarking (OWASP Benchmark uses the same approach).

### Why invoke skwaq-core programmatically instead of as a subprocess?

Running `skwaq analyze` as a subprocess for 81K test cases would be extremely slow (process startup overhead per case). By calling the analysis functions directly from Rust, we avoid that overhead. The trade-off is tighter coupling, but since gym is in the same workspace, that coupling is acceptable.

### Why the improvement loop is conservative (accept only on improvement + no regression)?

Aggressive changes that help one CWE but hurt another lead to oscillation. The no-regression check ensures monotonic improvement. The 2% noise margin in `has_cwe_regression` prevents rejecting improvements due to statistical noise in small sample sizes.

---

## 13. Implementation Order

1. **Create `crates/gym` with Cargo.toml and empty `lib.rs`**. Add to workspace. Verify it compiles.
2. **Implement `ground_truth.rs`** and create the `fixtures.toml` manifest (smallest, already available).
3. **Implement `scoring.rs`** with unit tests for `score_case`, `aggregate`, `cwe_family`.
4. **Implement `history.rs`** with the SQLite schema and CRUD operations. Unit test with in-memory DB.
5. **Implement `adapters/fixtures.rs`** as the simplest adapter. Wire it up end-to-end.
6. **Implement `reporting/terminal.rs`** so you can see results.
7. **Wire up CLI** (`gym_cmd.rs`, add `Gym` variant to `Commands` enum). Test `skwaq gym run fixtures`.
8. **Implement `download.rs`** for the HTTP download + extract pipeline.
9. **Implement `adapters/juliet.rs`** with compilation. Test with `--max-cases 10`.
10. **Implement `adapters/cgc.rs`**. Test with a handful of binaries.
11. **Implement `adapters/cyberseceval.rs`**.
12. **Implement `reporting/json_report.rs`** and `reporting/markdown_report.rs`**.
13. **Implement `improve.rs`** -- the self-improvement loop. Start with `NewPattern` improvements only.
14. **Add CI workflows**.
15. **Generate full Juliet and CGC manifests** from downloaded data.

Each step is independently testable. Do not proceed to step N+1 until step N has passing tests.

---

## Review Findings & Required Changes

Two independent reviews (code reviewer + security specialist) identified issues that MUST be addressed during implementation.

### Critical (Must Fix Before Merge)

1. **SHA-256 verification must be mandatory** - Downloads without checksums must fail, not silently proceed. The manifest must include hashes for all benchmark archives.

2. **Self-improvement loop must require human approval** - Write proposed patches to a staging area or PR branch, not directly to source. Add a holdout test set for validation. Add max-improvements-per-run cap.

3. **API mismatches with actual codebase** - `SourcePatternDetector` doesn't exist (use `DangerousApiDetector::detect_in_source_content()`). `DangerousApiDetector::new()` takes no args (not `&db`). Fix all references before implementation.

### High (Must Fix)

4. **Add compilation sandboxing** - Use `ulimit` constraints (CPU time, memory, processes, file size) on all compilation subprocesses. Consider container-based sandboxing for CI.

5. **Add per-case timeouts** - Every test case analysis must have a timeout (30s for quick, 300s for AI). Without this, a hung case blocks the entire run.

6. **Choose ONE CWE matching strategy** - Either CWE-family matching OR category-to-CWE mapping, not both stacked. Report both strict and relaxed scores side-by-side.

7. **Safe archive extraction** - Validate zip/tar entry paths before extraction. Reject paths containing `..` or absolute paths.

### Medium (Should Fix)

8. **Move `run_skwaq_source_analysis` to shared module** - All adapters need it, not just Juliet.

9. **Add disk space checks** before downloading multi-hundred-MB benchmark archives.

10. **Add resource limits** - Download size cap, rayon thread cap (num_cpus/2), disk space monitoring.

11. **Split `improve.rs`** into `analyzer.rs` (failure analysis) + `patcher.rs` (apply/revert) per brick philosophy.

12. **Add `actions/cache`** to CI workflows for benchmark data - ephemeral runners lose cache between runs.

13. **Validate ground truth manifest fields** - Reject paths with `..`, absolute paths, null bytes. Restrict `case.id` to alphanumeric + underscore + hyphen.

### Design Decisions Confirmed

- Separate `crates/gym` crate: **Approved** - keeps benchmark deps out of production binary
- Programmatic invocation of skwaq-core: **Approved** - avoids 81K process startups
- 4-tier CI strategy: **Approved** with cache fix
- Conservative accept/revert for improvements: **Approved** with human gate addition
- SQLite for results history: **Approved** with file permission enforcement (0o600)

---

## Architecture Diagrams

### Analysis Pipeline (Synthesis Model)

```
┌─────────────────────────────────────────────────────┐
│                  Source/Binary File                   │
└──────────┬──────────────────────┬────────────────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐   ┌──────────────────────────────┐
│  Layer 1-3:      │   │  Layer 4:                     │
│  Pattern Det.    │   │  LLM Agent Pipeline           │
│  + Dataflow      │   │  (vuln-hunter, taint-tracer,  │
│  + Context Val.  │   │   cwe-classifier, etc.)       │
│                  │   │                                │
│  "Junior Analyst"│   │  "Senior Researcher"           │
└────────┬─────────┘   └──────────┬────────────────────┘
         │                        │
         └──────────┬─────────────┘
                    ▼
         ┌──────────────────────┐
         │  Layer 5: SYNTHESIS  │
         │  (Lead Reviewer)     │
         │                      │
         │  Weighs ALL evidence │
         │  LLM findings first, │
         │  then pattern-only   │
         │  for uncovered cats  │
         └──────────┬───────────┘
                    ▼
         ┌──────────────────────┐
         │  Deduplicated        │
         │  Findings            │
         └──────────────────────┘
```

**Key change**: Layer 5 was previously "dual-judge intersection" which
discarded LLM-only findings. Now it synthesizes ALL evidence.

### Benchmark Modes

```
--pattern-only (--quick)    Full (default)           --llm-only
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Patterns only    │    │ Patterns + LLM   │    │ LLM agents only  │
│ No LLM agents   │    │ + Synthesis       │    │ No patterns      │
│ 30s timeout      │    │ 1800s timeout    │    │ 1800s timeout    │
│ Fast baseline    │    │ Best accuracy    │    │ Measures agent   │
│                  │    │                  │    │ understanding    │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

### Self-Improvement Loop (with Overfitting Gate)

```
┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
│ Run      │───▶│ Score    │───▶│ Analyze FN   │───▶│ Propose      │
│ Benchmark│    │ Results  │    │ Cases        │    │ Improvements │
└──────────┘    └──────────┘    └──────────────┘    └──────┬───────┘
                                                           │
                                                           ▼
                                                   ┌──────────────────┐
                                                   │ OVERFITTING      │
                                                   │ REVIEW GATE      │
                                                   │                  │
                                                   │ Checks:          │
                                                   │ • Real-world     │
                                                   │   generality?    │
                                                   │ • Pattern        │
                                                   │   specificity?   │
                                                   │ • CWE mapping    │
                                                   │   accuracy?      │
                                                   └──────┬───────────┘
                                                          │
                                    ┌─────────────────────┼──────────┐
                                    │ ACCEPT              │ REJECT   │
                                    ▼                     ▼          │
                             ┌──────────────┐    ┌──────────────┐   │
                             │ Implement    │    │ Logged &     │   │
                             │ Change       │    │ Discarded    │   │
                             └──────┬───────┘    └──────────────┘   │
                                    │                                │
                                    ▼                                │
                             ┌──────────────┐                       │
                             │ Verify       │                       │
                             │ No Regression│                       │
                             └──────────────┘                       │
```
