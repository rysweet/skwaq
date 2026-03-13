//! Run history storage (SQLite-backed) and comparison.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRun {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub suite: String,
    pub skwaq_commit: String,
    pub metadata: RunMetadata,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunMetadata {
    pub llm_backend: String,
    pub llm_model: String,
    pub run_mode: String,
    pub binary_mode: bool,
    pub git_dirty: bool,
    pub concurrency: usize,
    pub skip: usize,
    pub max_cases: Option<usize>,
}

/// Per-CWE result within a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweResult {
    pub run_id: String,
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

/// Per-test-case result within a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub run_id: String,
    pub suite: String,
    pub case_id: String,
    pub expected_cwes: Vec<u32>,
    pub detected_cwes: Vec<u32>,
    pub matched_finding_ids: Vec<String>,
    pub unmatched_finding_ids: Vec<String>,
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

        // Set file permissions to 0o600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }

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
                run_metadata_json TEXT NOT NULL DEFAULT '{}',
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
                expected_cwes TEXT NOT NULL,
                detected_cwes TEXT NOT NULL,
                matched_finding_ids TEXT NOT NULL,
                unmatched_finding_ids TEXT NOT NULL,
                classification TEXT NOT NULL,
                PRIMARY KEY (run_id, suite, case_id)
            );

            CREATE INDEX IF NOT EXISTS idx_cwe_results_cwe ON cwe_results(cwe_id);
            CREATE INDEX IF NOT EXISTS idx_case_results_suite ON case_results(suite);
            CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
            ",
        )?;
        self.ensure_run_metadata_column()?;
        Ok(())
    }

    /// Insert a new run record. Returns the run ID.
    pub fn start_run(
        &self,
        suite: &str,
        skwaq_commit: &str,
        metadata: &RunMetadata,
    ) -> anyhow::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO runs (id, started_at, suite, skwaq_commit, run_metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                id,
                now,
                suite,
                skwaq_commit,
                serde_json::to_string(metadata)?
            ],
        )?;
        Ok(id)
    }

    /// Finish a run with aggregate scores.
    pub fn finish_run(&self, run: &BenchmarkRun) -> anyhow::Result<()> {
        let finished = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE runs SET finished_at=?1, precision=?2, recall=?3, f1=?4,
             true_positives=?5, false_positives=?6, false_negatives=?7, true_negatives=?8,
             run_metadata_json=?9
             WHERE id=?10",
            rusqlite::params![
                finished,
                run.precision,
                run.recall,
                run.f1,
                run.true_positives,
                run.false_positives,
                run.false_negatives,
                run.true_negatives,
                serde_json::to_string(&run.metadata)?,
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
                result.run_id,
                result.cwe_id,
                result.total_cases,
                result.true_positives,
                result.false_positives,
                result.false_negatives,
                result.detection_rate,
                result.precision
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
                result.run_id,
                result.suite,
                result.case_id,
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
            "SELECT id, started_at, finished_at, suite, skwaq_commit, run_metadata_json,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives
              FROM runs ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit], |row| {
            let metadata_json: String = row.get(5)?;
            Ok(BenchmarkRun {
                id: row.get(0)?,
                started_at: row.get::<_, String>(1)?.parse().unwrap_or_default(),
                finished_at: row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| s.parse().ok()),
                suite: row.get(3)?,
                skwaq_commit: row.get(4)?,
                metadata: serde_json::from_str(&metadata_json).unwrap_or_default(),
                precision: row.get(6)?,
                recall: row.get(7)?,
                f1: row.get(8)?,
                true_positives: row.get(9)?,
                false_positives: row.get(10)?,
                false_negatives: row.get(11)?,
                true_negatives: row.get(12)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn ensure_run_metadata_column(&self) -> anyhow::Result<()> {
        let mut stmt = self.conn.prepare("PRAGMA table_info(runs)")?;
        let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
        let mut has_metadata = false;
        for column in columns {
            if column? == "run_metadata_json" {
                has_metadata = true;
                break;
            }
        }
        if !has_metadata {
            self.conn.execute(
                "ALTER TABLE runs ADD COLUMN run_metadata_json TEXT NOT NULL DEFAULT '{}'",
                [],
            )?;
        }
        Ok(())
    }

    /// Load per-CWE results for a run.
    pub fn cwe_results_for_run(&self, run_id: &str) -> anyhow::Result<Vec<CweResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id, cwe_id, total_cases, true_positives, false_positives,
                    false_negatives, detection_rate, precision
             FROM cwe_results WHERE run_id = ?1 ORDER BY cwe_id",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_db_lifecycle() {
        let db = HistoryDb::in_memory().unwrap();
        let metadata = RunMetadata {
            llm_backend: "copilot".to_string(),
            llm_model: "claude-opus-4.6".to_string(),
            run_mode: "hybrid".to_string(),
            binary_mode: true,
            git_dirty: false,
            concurrency: 2,
            skip: 0,
            max_cases: Some(5),
        };

        // Start a run.
        let run_id = db.start_run("fixtures", "abc123", &metadata).unwrap();

        // Finish it.
        let run = BenchmarkRun {
            id: run_id.clone(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "fixtures".to_string(),
            skwaq_commit: "abc123".to_string(),
            metadata: metadata.clone(),
            precision: 0.8,
            recall: 0.6,
            f1: 0.686,
            true_positives: 3,
            false_positives: 1,
            false_negatives: 2,
            true_negatives: 1,
        };
        db.finish_run(&run).unwrap();

        // Insert CWE result.
        db.insert_cwe_result(&CweResult {
            run_id: run_id.clone(),
            cwe_id: 119,
            total_cases: 5,
            true_positives: 3,
            false_positives: 0,
            false_negatives: 2,
            detection_rate: 0.6,
            precision: 1.0,
        })
        .unwrap();

        // Query recent runs.
        let runs = db.recent_runs(10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].suite, "fixtures");
        assert_eq!(runs[0].metadata, metadata);
        assert!((runs[0].precision - 0.8).abs() < 0.001);

        // Query CWE results.
        let cwes = db.cwe_results_for_run(&run_id).unwrap();
        assert_eq!(cwes.len(), 1);
        assert_eq!(cwes[0].cwe_id, 119);
    }
}
