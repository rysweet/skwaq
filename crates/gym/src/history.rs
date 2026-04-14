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
    /// Number of findings that disagree with the benchmark label.
    ///
    /// These are findings on cases the benchmark does not confirm as
    /// vulnerable.  They are *pending adjudication*, not confirmed-wrong.
    #[serde(default)]
    pub benchmark_disagreements: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RunMetadata {
    #[serde(default)]
    pub llm_backend: String,
    #[serde(default)]
    pub llm_model: String,
    #[serde(default)]
    pub run_mode: String,
    #[serde(default)]
    pub binary_mode: bool,
    #[serde(default)]
    pub git_dirty: bool,
    #[serde(default)]
    pub concurrency: usize,
    #[serde(default)]
    pub skip: usize,
    #[serde(default)]
    pub max_cases: Option<usize>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub total_prompt_tokens: u64,
    #[serde(default)]
    pub total_completion_tokens: u64,
    #[serde(default)]
    pub estimated_cost_usd: f64,
    /// Whether max_cases was applied (truncated run).
    /// When true, results may not represent the full suite.
    #[serde(default)]
    pub is_capped: bool,
    /// Sampling strategy used when is_capped is true.
    /// One of: "stratified", "sequential", "all".
    #[serde(default)]
    pub sampling_strategy: String,
    /// Explicit suite name recorded at run time.
    #[serde(default)]
    pub suite_name: String,
    /// Number of cases scheduled for this run/shard.
    #[serde(default)]
    pub scheduled_cases: u32,
    /// Number of cases that produced scoreable outcomes.
    #[serde(default)]
    pub scored_cases: u32,
    /// Number of scheduled cases that did not produce scoreable outcomes.
    #[serde(default)]
    pub unscored_cases: u32,
    /// Number of scored negative/safe cases.
    #[serde(default)]
    pub scored_negative_cases: u32,
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

/// Per-semantic-class result within a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticResult {
    pub run_id: String,
    pub class_name: String,
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

/// Per-case outcome classification persisted for per-CWE diffs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseOutcomeKind {
    TruePositive,
    FalsePositive,
    FalseNegative,
    /// The tool produced a finding on a case the benchmark does not label
    /// as vulnerable (or failed to find one the benchmark confirms).
    ///
    /// This is distinct from `FalsePositive` because the benchmark answer
    /// key may be incomplete: the finding may be a real bug the benchmark
    /// missed.  Adjudication is required before reclassifying as TP or FP.
    BenchmarkDisagreement,
}

impl std::fmt::Display for CaseOutcomeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaseOutcomeKind::TruePositive => write!(f, "TP"),
            CaseOutcomeKind::FalsePositive => write!(f, "FP"),
            CaseOutcomeKind::FalseNegative => write!(f, "FN"),
            CaseOutcomeKind::BenchmarkDisagreement => write!(f, "BD"),
        }
    }
}

impl std::str::FromStr for CaseOutcomeKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TP" => Ok(CaseOutcomeKind::TruePositive),
            "FP" => Ok(CaseOutcomeKind::FalsePositive),
            "FN" => Ok(CaseOutcomeKind::FalseNegative),
            "BD" | "BenchmarkDisagreement" => Ok(CaseOutcomeKind::BenchmarkDisagreement),
            _ => anyhow::bail!("Unknown outcome kind: {}", s),
        }
    }
}

/// A single per-case outcome stored in the case_outcomes table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseOutcome {
    pub run_id: String,
    pub case_id: String,
    pub outcome: CaseOutcomeKind,
    pub cwe: u32,
}

/// A benchmark-disagreement record persisted for future adjudication.
///
/// When the tool produces a finding on a case the benchmark does not confirm
/// as vulnerable, a `DisagreementRecord` is stored.  A future adjudication
/// pass can promote the record to a confirmed TP or confirmed FP by setting
/// `adjudication` to `"TP"` or `"FP"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisagreementRecord {
    pub id: String,
    pub run_id: String,
    pub suite: String,
    pub case_id: String,
    /// JSON-encoded list of CWE IDs reported by the tool.
    pub detected_cwes: String,
    pub finding_id: String,
    /// `None` = pending, `Some("TP")` = analyst confirmed real bug,
    /// `Some("FP")` = analyst confirmed wrong detection.
    pub adjudication: Option<String>,
    pub adjudicated_at: Option<String>,
    pub adjudicated_by: Option<String>,
}

/// Describes how a specific case changed between two runs.
#[derive(Debug, Clone)]
pub enum CaseDelta {
    Improved { case_id: String, cwe: u32 },
    Regressed { case_id: String, cwe: u32 },
    NewFalsePositive { case_id: String, cwe: u32 },
    FixedFalsePositive { case_id: String, cwe: u32 },
}

/// A regression where a case went from detected (TP) to missed (FN).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRegression {
    pub case_id: String,
    pub suite: String,
    pub expected_cwes: Vec<u32>,
    pub baseline_detected: Vec<u32>,
    pub new_detected: Vec<u32>,
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
                true_negatives INTEGER DEFAULT 0,
                benchmark_disagreements INTEGER DEFAULT 0
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

            CREATE TABLE IF NOT EXISTS semantic_results (
                run_id TEXT NOT NULL REFERENCES runs(id),
                class_name TEXT NOT NULL,
                total_cases INTEGER NOT NULL,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                false_negatives INTEGER DEFAULT 0,
                detection_rate REAL DEFAULT 0.0,
                precision REAL DEFAULT 0.0,
                PRIMARY KEY (run_id, class_name)
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

            CREATE TABLE IF NOT EXISTS case_outcomes (
                run_id TEXT NOT NULL REFERENCES runs(id),
                case_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                cwe INTEGER NOT NULL,
                PRIMARY KEY (run_id, case_id, cwe)
            );

            CREATE TABLE IF NOT EXISTS disagreements (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(id),
                suite TEXT NOT NULL,
                case_id TEXT NOT NULL,
                detected_cwes TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                adjudication TEXT,
                adjudicated_at TEXT,
                adjudicated_by TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_cwe_results_cwe ON cwe_results(cwe_id);
            CREATE INDEX IF NOT EXISTS idx_semantic_results_class ON semantic_results(class_name);
            CREATE INDEX IF NOT EXISTS idx_case_results_suite ON case_results(suite);
            CREATE INDEX IF NOT EXISTS idx_case_outcomes_run ON case_outcomes(run_id);
            CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
            CREATE INDEX IF NOT EXISTS idx_disagreements_run ON disagreements(run_id);
            CREATE INDEX IF NOT EXISTS idx_disagreements_adjudication ON disagreements(adjudication);

            CREATE TABLE IF NOT EXISTS poc_results (
                id TEXT PRIMARY KEY,
                disagreement_id TEXT NOT NULL REFERENCES disagreements(id),
                case_id TEXT NOT NULL,
                cwe TEXT NOT NULL,
                strategy TEXT NOT NULL,
                verdict TEXT NOT NULL,
                evidence_score TEXT NOT NULL,
                disproof_evidence_json TEXT NOT NULL DEFAULT '[]',
                proof_evidence_json TEXT NOT NULL DEFAULT '[]',
                exploit_sketch TEXT,
                reasoning TEXT NOT NULL DEFAULT '',
                tools_used_json TEXT NOT NULL DEFAULT '[]',
                duration_ms INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_poc_results_disagreement ON poc_results(disagreement_id);
            CREATE INDEX IF NOT EXISTS idx_poc_results_verdict ON poc_results(verdict);
            ",
        )?;
        self.ensure_run_metadata_column()?;
        self.ensure_benchmark_disagreements_column()?;
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
             run_metadata_json=?9, benchmark_disagreements=?10
             WHERE id=?11",
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
                run.benchmark_disagreements,
                run.id
            ],
        )?;
        Ok(())
    }

    /// Remove a run that failed before producing a usable result.
    pub fn abandon_run(&self, run_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM case_outcomes WHERE run_id = ?1",
            rusqlite::params![run_id],
        )?;
        self.conn.execute(
            "DELETE FROM case_results WHERE run_id = ?1",
            rusqlite::params![run_id],
        )?;
        self.conn.execute(
            "DELETE FROM cwe_results WHERE run_id = ?1",
            rusqlite::params![run_id],
        )?;
        self.conn.execute(
            "DELETE FROM semantic_results WHERE run_id = ?1",
            rusqlite::params![run_id],
        )?;
        self.conn
            .execute("DELETE FROM runs WHERE id = ?1", rusqlite::params![run_id])?;
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

    /// Insert per-semantic-class results.
    pub fn insert_semantic_result(&self, result: &SemanticResult) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO semantic_results (run_id, class_name, total_cases, true_positives,
             false_positives, false_negatives, detection_rate, precision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                result.run_id,
                result.class_name,
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

    /// Insert a per-case outcome (TP/FP/FN) for a specific CWE.
    pub fn insert_case_outcome(&self, outcome: &CaseOutcome) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO case_outcomes (run_id, case_id, outcome, cwe)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                outcome.run_id,
                outcome.case_id,
                outcome.outcome.to_string(),
                outcome.cwe
            ],
        )?;
        Ok(())
    }

    /// Load the N most recent runs.
    pub fn recent_runs(&self, limit: u32) -> anyhow::Result<Vec<BenchmarkRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, suite, skwaq_commit, run_metadata_json,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives,
                    COALESCE(benchmark_disagreements, 0)
              FROM runs ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit], |row| {
            let metadata_json = row
                .get::<_, Option<String>>(5)?
                .unwrap_or_else(|| "{}".to_string());
            Ok(BenchmarkRun {
                id: row.get(0)?,
                started_at: row.get::<_, String>(1)?.parse().unwrap_or_default(),
                finished_at: row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| s.parse().ok()),
                suite: row.get(3)?,
                skwaq_commit: row.get(4)?,
                metadata: serde_json::from_str(&metadata_json).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?,
                precision: row.get(6)?,
                recall: row.get(7)?,
                f1: row.get(8)?,
                true_positives: row.get(9)?,
                false_positives: row.get(10)?,
                false_negatives: row.get(11)?,
                true_negatives: row.get(12)?,
                benchmark_disagreements: row.get(13)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Load the N most recent completed runs.
    pub fn recent_finished_runs(&self, limit: u32) -> anyhow::Result<Vec<BenchmarkRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, suite, skwaq_commit, run_metadata_json,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives,
                    COALESCE(benchmark_disagreements, 0)
              FROM runs
              WHERE finished_at IS NOT NULL
              ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit], |row| {
            let metadata_json = row
                .get::<_, Option<String>>(5)?
                .unwrap_or_else(|| "{}".to_string());
            Ok(BenchmarkRun {
                id: row.get(0)?,
                started_at: row.get::<_, String>(1)?.parse().unwrap_or_default(),
                finished_at: row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| s.parse().ok()),
                suite: row.get(3)?,
                skwaq_commit: row.get(4)?,
                metadata: serde_json::from_str(&metadata_json).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?,
                precision: row.get(6)?,
                recall: row.get(7)?,
                f1: row.get(8)?,
                true_positives: row.get(9)?,
                false_positives: row.get(10)?,
                false_negatives: row.get(11)?,
                true_negatives: row.get(12)?,
                benchmark_disagreements: row.get(13)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Load the N most recent completed runs for a specific suite.
    pub fn recent_finished_runs_for_suite(
        &self,
        suite: &str,
        limit: u32,
    ) -> anyhow::Result<Vec<BenchmarkRun>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, suite, skwaq_commit, run_metadata_json,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives,
                    COALESCE(benchmark_disagreements, 0)
              FROM runs
              WHERE finished_at IS NOT NULL AND suite = ?1
              ORDER BY started_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![suite, limit], |row| {
            let metadata_json = row
                .get::<_, Option<String>>(5)?
                .unwrap_or_else(|| "{}".to_string());
            Ok(BenchmarkRun {
                id: row.get(0)?,
                started_at: row.get::<_, String>(1)?.parse().unwrap_or_default(),
                finished_at: row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| s.parse().ok()),
                suite: row.get(3)?,
                skwaq_commit: row.get(4)?,
                metadata: serde_json::from_str(&metadata_json).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?,
                precision: row.get(6)?,
                recall: row.get(7)?,
                f1: row.get(8)?,
                true_positives: row.get(9)?,
                false_positives: row.get(10)?,
                false_negatives: row.get(11)?,
                true_negatives: row.get(12)?,
                benchmark_disagreements: row.get(13)?,
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
            self.add_run_metadata_column()?;
        }
        Ok(())
    }

    fn add_run_metadata_column(&self) -> anyhow::Result<()> {
        match self.conn.execute(
            "ALTER TABLE runs ADD COLUMN run_metadata_json TEXT NOT NULL DEFAULT '{}'",
            [],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.contains("duplicate column name: run_metadata_json") =>
            {
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Add `benchmark_disagreements` column to existing runs tables (schema migration).
    fn ensure_benchmark_disagreements_column(&self) -> anyhow::Result<()> {
        match self.conn.execute(
            "ALTER TABLE runs ADD COLUMN benchmark_disagreements INTEGER DEFAULT 0",
            [],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(_, Some(ref message)))
                if message.contains("duplicate column name: benchmark_disagreements") =>
            {
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Insert a disagreement record for adjudication.
    pub fn insert_disagreement(&self, record: &DisagreementRecord) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO disagreements
             (id, run_id, suite, case_id, detected_cwes, finding_id,
              adjudication, adjudicated_at, adjudicated_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                record.id,
                record.run_id,
                record.suite,
                record.case_id,
                record.detected_cwes,
                record.finding_id,
                record.adjudication,
                record.adjudicated_at,
                record.adjudicated_by,
            ],
        )?;
        Ok(())
    }

    /// Load pending (unadjudicated) disagreement records for a run.
    pub fn pending_disagreements(&self, run_id: &str) -> anyhow::Result<Vec<DisagreementRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, suite, case_id, detected_cwes, finding_id,
                    adjudication, adjudicated_at, adjudicated_by
             FROM disagreements
             WHERE run_id = ?1 AND adjudication IS NULL
             ORDER BY case_id",
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |row| {
            Ok(DisagreementRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                suite: row.get(2)?,
                case_id: row.get(3)?,
                detected_cwes: row.get(4)?,
                finding_id: row.get(5)?,
                adjudication: row.get(6)?,
                adjudicated_at: row.get(7)?,
                adjudicated_by: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Insert a proof-of-compromise result.
    pub fn insert_poc_result(&self, result: &crate::poc::ProofOfCompromise) -> anyhow::Result<()> {
        let id = format!("poc-{}-{}", result.case_id, result.cwe);
        let disproof_json = serde_json::to_string(&result.disproof_evidence)?;
        let proof_json = serde_json::to_string(&result.proof_evidence)?;
        let tools_json = serde_json::to_string(&result.tools_used)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO poc_results
             (id, disagreement_id, case_id, cwe, strategy, verdict,
              evidence_score, disproof_evidence_json, proof_evidence_json,
              exploit_sketch, reasoning, tools_used_json, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                id,
                format!("bd-{}-{}", result.case_id, result.cwe),
                result.case_id,
                result.cwe,
                result.strategy,
                result.verdict.to_string(),
                result.evidence_score.to_string(),
                disproof_json,
                proof_json,
                result.exploit_sketch,
                result.reasoning,
                tools_json,
                result.duration_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// Adjudicate a disagreement record (set verdict to TP or FP).
    pub fn adjudicate_disagreement(
        &self,
        disagreement_id: &str,
        adjudication: &str,
        adjudicated_by: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE disagreements SET adjudication = ?1, adjudicated_at = ?2, adjudicated_by = ?3
             WHERE id = ?4",
            rusqlite::params![adjudication, now, adjudicated_by, disagreement_id],
        )?;
        Ok(())
    }

    /// Load PoC results for a specific run (via disagreement join).
    pub fn poc_results_for_run(
        &self,
        run_id: &str,
    ) -> anyhow::Result<Vec<crate::poc::ProofOfCompromise>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.case_id, p.cwe, p.strategy, p.verdict, p.evidence_score,
                    p.disproof_evidence_json, p.proof_evidence_json,
                    p.exploit_sketch, p.reasoning, p.tools_used_json, p.duration_ms
             FROM poc_results p
             JOIN disagreements d ON p.disagreement_id = d.id
             WHERE d.run_id = ?1
             ORDER BY p.case_id",
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |row| {
            let verdict_str: String = row.get(3)?;
            let score_str: String = row.get(4)?;
            let disproof_json: String = row.get(5)?;
            let proof_json: String = row.get(6)?;
            let tools_json: String = row.get(9)?;

            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                verdict_str,
                score_str,
                disproof_json,
                proof_json,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                tools_json,
                row.get::<_, i64>(10)?,
            ))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (
                case_id,
                cwe,
                strategy,
                verdict_str,
                score_str,
                disproof_json,
                proof_json,
                exploit_sketch,
                reasoning,
                tools_json,
                duration_ms,
            ) = row?;

            let verdict = match verdict_str.as_str() {
                "PROVEN" => crate::poc::PocVerdict::Proven,
                "DISPROVEN" => crate::poc::PocVerdict::Disproven,
                _ => crate::poc::PocVerdict::Inconclusive,
            };
            let evidence_score = match score_str.as_str() {
                "strong" => crate::poc::EvidenceScore::Strong,
                "moderate" => crate::poc::EvidenceScore::Moderate,
                "disproven" => crate::poc::EvidenceScore::Disproven,
                _ => crate::poc::EvidenceScore::Insufficient,
            };

            results.push(crate::poc::ProofOfCompromise {
                case_id,
                cwe,
                strategy,
                verdict,
                evidence_score,
                disproof_evidence: serde_json::from_str(&disproof_json).unwrap_or_default(),
                proof_evidence: serde_json::from_str(&proof_json).unwrap_or_default(),
                exploit_sketch,
                reasoning,
                tools_used: serde_json::from_str(&tools_json).unwrap_or_default(),
                duration_ms: duration_ms as u64,
            });
        }
        Ok(results)
    }

    /// Load per-case results for a run.
    pub fn case_results_for_run(&self, run_id: &str) -> anyhow::Result<Vec<CaseResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id, suite, case_id, expected_cwes, detected_cwes,
                    matched_finding_ids, unmatched_finding_ids, classification
             FROM case_results WHERE run_id = ?1 ORDER BY case_id",
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |row| {
            let expected_json: String = row.get(3)?;
            let detected_json: String = row.get(4)?;
            let matched_json: String = row.get(5)?;
            let unmatched_json: String = row.get(6)?;
            Ok(CaseResult {
                run_id: row.get(0)?,
                suite: row.get(1)?,
                case_id: row.get(2)?,
                expected_cwes: serde_json::from_str(&expected_json).unwrap_or_default(),
                detected_cwes: serde_json::from_str(&detected_json).unwrap_or_default(),
                matched_finding_ids: serde_json::from_str(&matched_json).unwrap_or_default(),
                unmatched_finding_ids: serde_json::from_str(&unmatched_json).unwrap_or_default(),
                classification: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Load all case outcomes for a run.
    pub fn case_outcomes_for_run(&self, run_id: &str) -> anyhow::Result<Vec<CaseOutcome>> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id, case_id, outcome, cwe
             FROM case_outcomes WHERE run_id = ?1 ORDER BY case_id, cwe",
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |row| {
            let run_id: String = row.get(0)?;
            let case_id: String = row.get(1)?;
            let outcome_str: String = row.get(2)?;
            let cwe: u32 = row.get(3)?;
            let outcome = outcome_str.parse().unwrap_or_else(|err| {
                tracing::warn!(
                    "Invalid case outcome '{}' for run {} case {} CWE-{}: {}. Defaulting to FN.",
                    outcome_str,
                    run_id,
                    case_id,
                    cwe,
                    err
                );
                CaseOutcomeKind::FalseNegative
            });
            Ok(CaseOutcome {
                run_id,
                case_id,
                outcome,
                cwe,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Compare two runs and return per-case deltas (improvements and regressions).
    pub fn compare_case_outcomes(
        &self,
        baseline_run_id: &str,
        new_run_id: &str,
    ) -> anyhow::Result<Vec<CaseDelta>> {
        let baseline = self.case_outcomes_for_run(baseline_run_id)?;
        let new = self.case_outcomes_for_run(new_run_id)?;

        let baseline_map: std::collections::HashMap<(String, u32), CaseOutcomeKind> = baseline
            .into_iter()
            .map(|outcome| ((outcome.case_id, outcome.cwe), outcome.outcome))
            .collect();
        let new_map: std::collections::HashMap<(String, u32), CaseOutcomeKind> = new
            .into_iter()
            .map(|outcome| ((outcome.case_id, outcome.cwe), outcome.outcome))
            .collect();

        let mut deltas = Vec::new();
        let mut all_keys: std::collections::HashSet<(String, u32)> =
            baseline_map.keys().cloned().collect();
        all_keys.extend(new_map.keys().cloned());

        for key in all_keys {
            let old = baseline_map.get(&key);
            let new_outcome = new_map.get(&key);
            match (old, new_outcome) {
                (Some(CaseOutcomeKind::FalseNegative), Some(CaseOutcomeKind::TruePositive)) => {
                    deltas.push(CaseDelta::Improved {
                        case_id: key.0,
                        cwe: key.1,
                    });
                }
                (Some(CaseOutcomeKind::TruePositive), Some(CaseOutcomeKind::FalseNegative)) => {
                    deltas.push(CaseDelta::Regressed {
                        case_id: key.0,
                        cwe: key.1,
                    });
                }
                (None, Some(CaseOutcomeKind::FalsePositive)) => {
                    deltas.push(CaseDelta::NewFalsePositive {
                        case_id: key.0,
                        cwe: key.1,
                    });
                }
                (Some(CaseOutcomeKind::FalsePositive), None) => {
                    deltas.push(CaseDelta::FixedFalsePositive {
                        case_id: key.0,
                        cwe: key.1,
                    });
                }
                _ => {}
            }
        }

        deltas.sort_by(|a, b| {
            let a_key = match a {
                CaseDelta::Improved { case_id, cwe }
                | CaseDelta::Regressed { case_id, cwe }
                | CaseDelta::NewFalsePositive { case_id, cwe }
                | CaseDelta::FixedFalsePositive { case_id, cwe } => (case_id.clone(), *cwe),
            };
            let b_key = match b {
                CaseDelta::Improved { case_id, cwe }
                | CaseDelta::Regressed { case_id, cwe }
                | CaseDelta::NewFalsePositive { case_id, cwe }
                | CaseDelta::FixedFalsePositive { case_id, cwe } => (case_id.clone(), *cwe),
            };
            a_key.cmp(&b_key)
        });

        Ok(deltas)
    }

    /// Find per-case regressions between two runs.
    ///
    /// Returns cases that were detected (TP) in the baseline run but missed (FN)
    /// in the new run. This identifies specific cases that got worse.
    pub fn case_regressions(
        &self,
        baseline_run_id: &str,
        new_run_id: &str,
    ) -> anyhow::Result<Vec<CaseRegression>> {
        let baseline_cases = self.case_results_for_run(baseline_run_id)?;
        let new_cases = self.case_results_for_run(new_run_id)?;

        let new_by_id: std::collections::HashMap<&str, &CaseResult> =
            new_cases.iter().map(|c| (c.case_id.as_str(), c)).collect();

        let mut regressions = Vec::new();
        for baseline in &baseline_cases {
            if baseline.classification != "TP" {
                continue;
            }
            if let Some(new) = new_by_id.get(baseline.case_id.as_str()) {
                if new.classification == "FN" {
                    regressions.push(CaseRegression {
                        case_id: baseline.case_id.clone(),
                        suite: baseline.suite.clone(),
                        expected_cwes: baseline.expected_cwes.clone(),
                        baseline_detected: baseline.detected_cwes.clone(),
                        new_detected: new.detected_cwes.clone(),
                    });
                }
            }
        }

        Ok(regressions)
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

    /// Load per-semantic-class results for a run.
    pub fn semantic_results_for_run(&self, run_id: &str) -> anyhow::Result<Vec<SemanticResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id, class_name, total_cases, true_positives, false_positives,
                    false_negatives, detection_rate, precision
             FROM semantic_results WHERE run_id = ?1 ORDER BY class_name",
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |row| {
            Ok(SemanticResult {
                run_id: row.get(0)?,
                class_name: row.get(1)?,
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

    fn insert_run_with_metadata_json(db: &HistoryDb, id: &str, metadata_json: &str) {
        db.conn
            .execute(
                "INSERT INTO runs (
                    id, started_at, suite, skwaq_commit, run_metadata_json,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives
                ) VALUES (?1, ?2, ?3, ?4, ?5, 0.0, 0.0, 0.0, 0, 0, 0, 0)",
                rusqlite::params![
                    id,
                    Utc::now().to_rfc3339(),
                    "fixtures",
                    "abc123",
                    metadata_json,
                ],
            )
            .unwrap();
    }

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
            profile: None,
            total_prompt_tokens: 1000,
            total_completion_tokens: 500,
            estimated_cost_usd: 0.0525,
            is_capped: true,
            sampling_strategy: "stratified".to_string(),
            suite_name: "fixtures".to_string(),
            scheduled_cases: 5,
            scored_cases: 5,
            unscored_cases: 0,
            scored_negative_cases: 0,
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
            benchmark_disagreements: 1,
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

        db.insert_semantic_result(&SemanticResult {
            run_id: run_id.clone(),
            class_name: "buffer_overflow".to_string(),
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

        let semantics = db.semantic_results_for_run(&run_id).unwrap();
        assert_eq!(semantics.len(), 1);
        assert_eq!(semantics[0].class_name, "buffer_overflow");
    }

    #[test]
    fn test_recent_runs_loads_legacy_empty_metadata() {
        let db = HistoryDb::in_memory().unwrap();
        insert_run_with_metadata_json(&db, "legacy-run", "{}");

        let runs = db.recent_runs(1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, "legacy-run");
        assert_eq!(runs[0].metadata, RunMetadata::default());
    }

    #[test]
    fn test_recent_runs_loads_partial_metadata() {
        let db = HistoryDb::in_memory().unwrap();
        insert_run_with_metadata_json(
            &db,
            "partial-run",
            r#"{"llm_backend":"copilot","binary_mode":true,"concurrency":4}"#,
        );

        let runs = db.recent_runs(1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, "partial-run");
        assert_eq!(runs[0].metadata.llm_backend, "copilot");
        assert_eq!(runs[0].metadata.llm_model, "");
        assert_eq!(runs[0].metadata.run_mode, "");
        assert!(runs[0].metadata.binary_mode);
        assert_eq!(runs[0].metadata.concurrency, 4);
        assert_eq!(runs[0].metadata.skip, 0);
        assert_eq!(runs[0].metadata.max_cases, None);
    }

    #[test]
    fn test_recent_runs_loads_null_metadata() {
        let db = HistoryDb::in_memory().unwrap();
        db.conn.execute("DROP TABLE runs", []).unwrap();
        db.conn
            .execute_batch(
                "
                CREATE TABLE runs (
                    id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    suite TEXT NOT NULL,
                    skwaq_commit TEXT NOT NULL,
                    run_metadata_json TEXT DEFAULT '{}',
                    precision REAL DEFAULT 0.0,
                    recall REAL DEFAULT 0.0,
                    f1 REAL DEFAULT 0.0,
                    true_positives INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    false_negatives INTEGER DEFAULT 0,
                    true_negatives INTEGER DEFAULT 0,
                    benchmark_disagreements INTEGER DEFAULT 0
                );
                ",
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO runs (
                    id, started_at, suite, skwaq_commit, run_metadata_json,
                    precision, recall, f1, true_positives, false_positives,
                    false_negatives, true_negatives
                ) VALUES (?1, ?2, ?3, ?4, NULL, 0.5, 0.4, 0.444, 2, 1, 3, 0)",
                rusqlite::params!["null-run", "2026-03-13T00:00:00Z", "fixtures", "deadbeef"],
            )
            .unwrap();

        let runs = db.recent_runs(1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, "null-run");
        assert_eq!(runs[0].metadata, RunMetadata::default());
    }

    #[test]
    fn test_recent_runs_rejects_invalid_metadata_json() {
        let db = HistoryDb::in_memory().unwrap();
        insert_run_with_metadata_json(&db, "bad-run", "{not-json");

        assert!(db.recent_runs(1).is_err());
    }

    #[test]
    fn test_case_results_roundtrip() {
        let db = HistoryDb::in_memory().unwrap();
        let run_id = db
            .start_run("fixtures", "abc123", &RunMetadata::default())
            .unwrap();

        let case = CaseResult {
            run_id: run_id.clone(),
            suite: "fixtures".to_string(),
            case_id: "buffer_overflow".to_string(),
            expected_cwes: vec![121, 134],
            detected_cwes: vec![119],
            matched_finding_ids: vec!["f1".to_string()],
            unmatched_finding_ids: vec![],
            classification: "TP".to_string(),
        };
        db.insert_case_result(&case).unwrap();

        let results = db.case_results_for_run(&run_id).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].case_id, "buffer_overflow");
        assert_eq!(results[0].expected_cwes, vec![121, 134]);
        assert_eq!(results[0].detected_cwes, vec![119]);
        assert_eq!(results[0].classification, "TP");
    }

    #[test]
    fn test_case_outcomes_roundtrip() {
        let db = HistoryDb::in_memory().unwrap();
        let run_id = db
            .start_run("fixtures", "abc123", &RunMetadata::default())
            .unwrap();

        db.insert_case_outcome(&CaseOutcome {
            run_id: run_id.clone(),
            case_id: "case1".to_string(),
            outcome: CaseOutcomeKind::TruePositive,
            cwe: 121,
        })
        .unwrap();
        db.insert_case_outcome(&CaseOutcome {
            run_id: run_id.clone(),
            case_id: "case2".to_string(),
            outcome: CaseOutcomeKind::FalseNegative,
            cwe: 78,
        })
        .unwrap();

        let outcomes = db.case_outcomes_for_run(&run_id).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].outcome, CaseOutcomeKind::TruePositive);
        assert_eq!(outcomes[1].outcome, CaseOutcomeKind::FalseNegative);
    }

    #[test]
    fn test_case_outcomes_invalid_kind_defaults_false_negative() {
        let db = HistoryDb::in_memory().unwrap();
        let run_id = db
            .start_run("fixtures", "abc123", &RunMetadata::default())
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO case_outcomes (run_id, case_id, outcome, cwe) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![run_id, "case1", "BAD", 121],
            )
            .unwrap();

        let outcomes = db.case_outcomes_for_run(&run_id).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, CaseOutcomeKind::FalseNegative);
    }

    #[test]
    fn test_compare_case_outcomes() {
        let db = HistoryDb::in_memory().unwrap();
        let meta = RunMetadata::default();
        let run1 = db.start_run("fixtures", "aaa111", &meta).unwrap();
        let run2 = db.start_run("fixtures", "bbb222", &meta).unwrap();

        db.insert_case_outcome(&CaseOutcome {
            run_id: run1.clone(),
            case_id: "case1".to_string(),
            outcome: CaseOutcomeKind::FalseNegative,
            cwe: 121,
        })
        .unwrap();
        db.insert_case_outcome(&CaseOutcome {
            run_id: run1.clone(),
            case_id: "case2".to_string(),
            outcome: CaseOutcomeKind::TruePositive,
            cwe: 78,
        })
        .unwrap();
        db.insert_case_outcome(&CaseOutcome {
            run_id: run1.clone(),
            case_id: "case3".to_string(),
            outcome: CaseOutcomeKind::FalsePositive,
            cwe: 89,
        })
        .unwrap();

        db.insert_case_outcome(&CaseOutcome {
            run_id: run2.clone(),
            case_id: "case1".to_string(),
            outcome: CaseOutcomeKind::TruePositive,
            cwe: 121,
        })
        .unwrap();
        db.insert_case_outcome(&CaseOutcome {
            run_id: run2.clone(),
            case_id: "case2".to_string(),
            outcome: CaseOutcomeKind::FalseNegative,
            cwe: 78,
        })
        .unwrap();
        db.insert_case_outcome(&CaseOutcome {
            run_id: run2.clone(),
            case_id: "case4".to_string(),
            outcome: CaseOutcomeKind::FalsePositive,
            cwe: 134,
        })
        .unwrap();

        let deltas = db.compare_case_outcomes(&run1, &run2).unwrap();
        assert_eq!(deltas.len(), 4);
        assert!(deltas.iter().any(
            |delta| matches!(delta, CaseDelta::Improved { case_id, .. } if case_id == "case1")
        ));
        assert!(deltas.iter().any(
            |delta| matches!(delta, CaseDelta::Regressed { case_id, .. } if case_id == "case2")
        ));
        assert!(deltas
            .iter()
            .any(|delta| matches!(delta, CaseDelta::FixedFalsePositive { case_id, .. } if case_id == "case3")));
        assert!(deltas
            .iter()
            .any(|delta| matches!(delta, CaseDelta::NewFalsePositive { case_id, .. } if case_id == "case4")));
    }

    #[test]
    fn test_case_regressions() {
        let db = HistoryDb::in_memory().unwrap();
        let meta = RunMetadata::default();

        // Baseline run: case detected (TP).
        let run1 = db.start_run("fixtures", "aaa111", &meta).unwrap();
        db.insert_case_result(&CaseResult {
            run_id: run1.clone(),
            suite: "fixtures".to_string(),
            case_id: "overflow".to_string(),
            expected_cwes: vec![121],
            detected_cwes: vec![119],
            matched_finding_ids: vec!["f1".to_string()],
            unmatched_finding_ids: vec![],
            classification: "TP".to_string(),
        })
        .unwrap();

        // New run: same case missed (FN).
        let run2 = db.start_run("fixtures", "bbb222", &meta).unwrap();
        db.insert_case_result(&CaseResult {
            run_id: run2.clone(),
            suite: "fixtures".to_string(),
            case_id: "overflow".to_string(),
            expected_cwes: vec![121],
            detected_cwes: vec![],
            matched_finding_ids: vec![],
            unmatched_finding_ids: vec![],
            classification: "FN".to_string(),
        })
        .unwrap();

        let regressions = db.case_regressions(&run1, &run2).unwrap();
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].case_id, "overflow");
        assert_eq!(regressions[0].baseline_detected, vec![119]);
        assert!(regressions[0].new_detected.is_empty());
    }

    #[test]
    fn test_add_run_metadata_column_tolerates_duplicate_column_race() {
        let db = HistoryDb::in_memory().unwrap();
        db.conn.execute("DROP TABLE runs", []).unwrap();
        db.conn
            .execute_batch(
                "
                CREATE TABLE runs (
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
                ",
            )
            .unwrap();

        db.add_run_metadata_column().unwrap();
        db.add_run_metadata_column().unwrap();

        let mut stmt = db.conn.prepare("PRAGMA table_info(runs)").unwrap();
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(columns.iter().any(|column| column == "run_metadata_json"));
    }

    #[test]
    fn test_recent_finished_runs_excludes_unfinished_rows_and_abandon_run_deletes_them() {
        let db = HistoryDb::in_memory().unwrap();
        let metadata = RunMetadata::default();

        let unfinished = db.start_run("fixtures", "abc123", &metadata).unwrap();
        let finished = db.start_run("fixtures", "def456", &metadata).unwrap();
        db.finish_run(&BenchmarkRun {
            id: finished.clone(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "fixtures".to_string(),
            skwaq_commit: "def456".to_string(),
            metadata,
            precision: 1.0,
            recall: 1.0,
            f1: 1.0,
            true_positives: 1,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 0,
            benchmark_disagreements: 0,
        })
        .unwrap();

        let runs = db.recent_finished_runs(10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, finished);

        db.abandon_run(&unfinished).unwrap();
        let unfinished_rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM runs WHERE id = ?1",
                rusqlite::params![unfinished],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unfinished_rows, 0);
    }

    #[test]
    fn test_recent_finished_runs_for_suite_filters_other_suites() {
        let db = HistoryDb::in_memory().unwrap();
        let metadata = RunMetadata::default();

        let fixtures_old = db.start_run("fixtures", "aaa111", &metadata).unwrap();
        db.finish_run(&BenchmarkRun {
            id: fixtures_old.clone(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "fixtures".to_string(),
            skwaq_commit: "aaa111".to_string(),
            metadata: metadata.clone(),
            precision: 0.5,
            recall: 0.5,
            f1: 0.5,
            true_positives: 1,
            false_positives: 1,
            false_negatives: 1,
            true_negatives: 0,
            benchmark_disagreements: 1,
        })
        .unwrap();

        let juliet = db.start_run("juliet", "bbb222", &metadata).unwrap();
        db.finish_run(&BenchmarkRun {
            id: juliet,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "juliet".to_string(),
            skwaq_commit: "bbb222".to_string(),
            metadata: metadata.clone(),
            precision: 0.8,
            recall: 0.8,
            f1: 0.8,
            true_positives: 4,
            false_positives: 1,
            false_negatives: 1,
            true_negatives: 0,
            benchmark_disagreements: 1,
        })
        .unwrap();

        let fixtures_new = db.start_run("fixtures", "ccc333", &metadata).unwrap();
        db.finish_run(&BenchmarkRun {
            id: fixtures_new.clone(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "fixtures".to_string(),
            skwaq_commit: "ccc333".to_string(),
            metadata,
            precision: 0.9,
            recall: 0.9,
            f1: 0.9,
            true_positives: 9,
            false_positives: 1,
            false_negatives: 1,
            true_negatives: 0,
            benchmark_disagreements: 1,
        })
        .unwrap();

        let runs = db.recent_finished_runs_for_suite("fixtures", 2).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].id, fixtures_new);
        assert_eq!(runs[1].id, fixtures_old);
        assert!(runs.iter().all(|run| run.suite == "fixtures"));
    }
}
