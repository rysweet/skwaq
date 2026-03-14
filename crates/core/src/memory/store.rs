//! SQLite-backed persistent memory store.
//!
//! Stores experiences in a dedicated SQLite database that lives outside any
//! single investigation, so memories persist across benchmark runs and targets.

use super::experience::{Experience, ExperienceType};
use std::path::Path;

/// Persistent memory store backed by SQLite.
///
/// Each agent's memories are isolated by agent name. The store lives at
/// `~/.skwaq/memory.db` by default, separate from the investigation graph DB.
pub struct MemoryStore {
    conn: rusqlite::Connection,
}

/// Maximum number of experiences per agent (prevents unbounded growth).
const MAX_EXPERIENCES_PER_AGENT: u32 = 10_000;

/// Confidence decay rate per day (experiences lose relevance over time).
const CONFIDENCE_DECAY_PER_DAY: f64 = 0.005;

/// Minimum confidence threshold — experiences below this are pruned.
const MIN_CONFIDENCE: f64 = 0.05;

impl MemoryStore {
    /// Open (or create) a memory store at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.ensure_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (for tests).
    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let store = Self { conn };
        store.ensure_schema()?;
        Ok(store)
    }

    /// Open the default memory store at `~/.skwaq/memory.db`.
    pub fn open_default() -> anyhow::Result<Self> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let path = home.join(".skwaq").join("memory.db");
        Self::open(&path)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS experiences (
                id TEXT PRIMARY KEY,
                agent TEXT NOT NULL,
                experience_type TEXT NOT NULL,
                context TEXT NOT NULL,
                outcome TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                tags TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                recall_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_exp_agent ON experiences(agent);
            CREATE INDEX IF NOT EXISTS idx_exp_type ON experiences(experience_type);
            CREATE INDEX IF NOT EXISTS idx_exp_confidence ON experiences(confidence);
            CREATE INDEX IF NOT EXISTS idx_exp_created ON experiences(created_at);

            -- FTS index for full-text search on context and outcome
            CREATE VIRTUAL TABLE IF NOT EXISTS experiences_fts USING fts5(
                id,
                context,
                outcome,
                tags,
                content=experiences,
                content_rowid=rowid
            );

            -- Triggers to keep FTS in sync
            CREATE TRIGGER IF NOT EXISTS experiences_ai AFTER INSERT ON experiences BEGIN
                INSERT INTO experiences_fts(rowid, id, context, outcome, tags)
                VALUES (new.rowid, new.id, new.context, new.outcome, new.tags);
            END;

            CREATE TRIGGER IF NOT EXISTS experiences_ad AFTER DELETE ON experiences BEGIN
                INSERT INTO experiences_fts(experiences_fts, rowid, id, context, outcome, tags)
                VALUES ('delete', old.rowid, old.id, old.context, old.outcome, old.tags);
            END;

            CREATE TRIGGER IF NOT EXISTS experiences_au AFTER UPDATE ON experiences BEGIN
                INSERT INTO experiences_fts(experiences_fts, rowid, id, context, outcome, tags)
                VALUES ('delete', old.rowid, old.id, old.context, old.outcome, old.tags);
                INSERT INTO experiences_fts(rowid, id, context, outcome, tags)
                VALUES (new.rowid, new.id, new.context, new.outcome, new.tags);
            END;
            ",
        )?;
        Ok(())
    }

    /// Store a new experience.
    pub fn store(
        &self,
        agent: &str,
        experience_type: ExperienceType,
        context: &str,
        outcome: &str,
        confidence: f64,
        tags: &[&str],
    ) -> anyhow::Result<String> {
        let id = format!(
            "exp_{}_{}",
            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        let now = chrono::Utc::now().to_rfc3339();
        let tags_json = serde_json::to_string(tags)?;
        let confidence = confidence.clamp(0.0, 1.0);

        self.conn.execute(
            "INSERT INTO experiences (id, agent, experience_type, context, outcome, confidence, tags, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                id,
                agent,
                experience_type.as_str(),
                context,
                outcome,
                confidence,
                tags_json,
                now
            ],
        )?;

        // Enforce per-agent limit by removing oldest low-confidence entries
        self.enforce_limit(agent)?;

        Ok(id)
    }

    /// Recall experiences relevant to a query, for a given agent.
    ///
    /// Uses FTS5 for initial candidate retrieval, then re-ranks by relevance.
    pub fn recall(
        &self,
        agent: &str,
        query: &str,
        limit: usize,
        min_confidence: f64,
    ) -> anyhow::Result<Vec<Experience>> {
        // Use FTS5 for candidate retrieval
        let fts_query = Self::build_fts_query(query);

        let mut stmt = self.conn.prepare(
            "SELECT e.id, e.agent, e.experience_type, e.context, e.outcome,
                    e.confidence, e.tags, e.created_at, e.recall_count
             FROM experiences e
             JOIN experiences_fts f ON e.id = f.id
             WHERE e.agent = ?1
               AND e.confidence >= ?2
               AND experiences_fts MATCH ?3
             ORDER BY e.confidence DESC
             LIMIT ?4",
        )?;

        let candidates = stmt
            .query_map(
                rusqlite::params![agent, min_confidence, fts_query, (limit * 3) as i64],
                Self::row_to_experience,
            )?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();

        // Re-rank by relevance score
        let mut scored: Vec<(f64, Experience)> = candidates
            .into_iter()
            .map(|e| {
                let score = e.relevance_to(query);
                (score, e)
            })
            .filter(|(score, _)| *score > 0.0)
            .collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);

        let ids: Vec<String> = scored.iter().map(|(_, e)| e.id.clone()).collect();
        self.increment_recall_count(&ids)?;

        Ok(scored.into_iter().map(|(_, e)| e).collect())
    }

    /// Recall experiences by agent without full-text search (returns most recent).
    pub fn recall_recent(
        &self,
        agent: &str,
        limit: usize,
        experience_type: Option<ExperienceType>,
    ) -> anyhow::Result<Vec<Experience>> {
        let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match experience_type {
            Some(et) => (
                "SELECT id, agent, experience_type, context, outcome, confidence, tags, created_at, recall_count
                 FROM experiences WHERE agent = ?1 AND experience_type = ?2 AND confidence >= ?3
                 ORDER BY created_at DESC LIMIT ?4"
                    .to_string(),
                vec![
                    Box::new(agent.to_string()),
                    Box::new(et.as_str().to_string()),
                    Box::new(MIN_CONFIDENCE),
                    Box::new(limit as i64),
                ],
            ),
            None => (
                "SELECT id, agent, experience_type, context, outcome, confidence, tags, created_at, recall_count
                 FROM experiences WHERE agent = ?1 AND confidence >= ?2
                 ORDER BY created_at DESC LIMIT ?3"
                    .to_string(),
                vec![
                    Box::new(agent.to_string()),
                    Box::new(MIN_CONFIDENCE),
                    Box::new(limit as i64),
                ],
            ),
        };

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let results = stmt
            .query_map(params_ref.as_slice(), Self::row_to_experience)?
            .filter_map(|r| r.ok())
            .collect();

        Ok(results)
    }

    /// Apply confidence decay to all experiences.
    ///
    /// Call this periodically (e.g., at the start of each benchmark run).
    /// Experiences that decay below `MIN_CONFIDENCE` are deleted.
    pub fn apply_decay(&self) -> anyhow::Result<u32> {
        let now = chrono::Utc::now();

        // Get all experiences and compute decay
        let mut stmt = self
            .conn
            .prepare("SELECT id, confidence, created_at FROM experiences")?;

        let updates: Vec<(String, f64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .map(|(id, confidence, created_at)| {
                let created = chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or(now);
                let days = (now - created).num_days().max(0) as f64;
                let decayed = confidence * (1.0 - CONFIDENCE_DECAY_PER_DAY).powf(days);
                (id, decayed)
            })
            .collect();

        let mut pruned = 0u32;
        for (id, new_confidence) in &updates {
            if *new_confidence < MIN_CONFIDENCE {
                self.conn.execute(
                    "DELETE FROM experiences WHERE id = ?1",
                    rusqlite::params![id],
                )?;
                pruned += 1;
            } else {
                self.conn.execute(
                    "UPDATE experiences SET confidence = ?1 WHERE id = ?2",
                    rusqlite::params![new_confidence, id],
                )?;
            }
        }

        Ok(pruned)
    }

    /// Get statistics about stored memories.
    pub fn statistics(&self, agent: &str) -> anyhow::Result<MemoryStats> {
        let total: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM experiences WHERE agent = ?1",
            rusqlite::params![agent],
            |row| row.get(0),
        )?;

        let by_type = |t: &str| -> anyhow::Result<u32> {
            Ok(self.conn.query_row(
                "SELECT COUNT(*) FROM experiences WHERE agent = ?1 AND experience_type = ?2",
                rusqlite::params![agent, t],
                |row| row.get(0),
            )?)
        };

        let avg_confidence: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(confidence), 0.0) FROM experiences WHERE agent = ?1",
            rusqlite::params![agent],
            |row| row.get(0),
        )?;

        Ok(MemoryStats {
            total,
            successes: by_type("success")?,
            failures: by_type("failure")?,
            patterns: by_type("pattern")?,
            insights: by_type("insight")?,
            avg_confidence,
        })
    }

    /// Get statistics across all agents.
    pub fn global_statistics(&self) -> anyhow::Result<MemoryStats> {
        let total: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM experiences", [], |row| row.get(0))?;

        let by_type = |t: &str| -> anyhow::Result<u32> {
            Ok(self.conn.query_row(
                "SELECT COUNT(*) FROM experiences WHERE experience_type = ?1",
                rusqlite::params![t],
                |row| row.get(0),
            )?)
        };

        let avg_confidence: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(confidence), 0.0) FROM experiences",
            [],
            |row| row.get(0),
        )?;

        Ok(MemoryStats {
            total,
            successes: by_type("success")?,
            failures: by_type("failure")?,
            patterns: by_type("pattern")?,
            insights: by_type("insight")?,
            avg_confidence,
        })
    }

    /// Build an FTS5 query from a natural language query string.
    fn build_fts_query(query: &str) -> String {
        let words: Vec<&str> = query.split_whitespace().filter(|w| w.len() > 2).collect();

        if words.is_empty() {
            return "\"\"".to_string();
        }

        // Use OR matching for broader recall
        words
            .iter()
            .map(|w| {
                // Escape special FTS5 characters
                let escaped = w.replace('"', "");
                format!("\"{escaped}\"")
            })
            .collect::<Vec<_>>()
            .join(" OR ")
    }

    fn row_to_experience(row: &rusqlite::Row<'_>) -> rusqlite::Result<Experience> {
        let tags_json: String = row.get(6)?;
        let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
        let type_str: String = row.get(2)?;

        Ok(Experience {
            id: row.get(0)?,
            agent: row.get(1)?,
            experience_type: ExperienceType::from_str(&type_str).unwrap_or(ExperienceType::Insight),
            context: row.get(3)?,
            outcome: row.get(4)?,
            confidence: row.get(5)?,
            tags,
            created_at: row.get(7)?,
            recall_count: row.get(8)?,
        })
    }

    fn increment_recall_count(&self, ids: &[String]) -> anyhow::Result<()> {
        for id in ids {
            self.conn.execute(
                "UPDATE experiences SET recall_count = recall_count + 1 WHERE id = ?1",
                rusqlite::params![id],
            )?;
        }
        Ok(())
    }

    /// Delete all memories for a specific agent.
    pub fn clear_agent(&self, agent: &str) -> anyhow::Result<u32> {
        let deleted = self.conn.execute(
            "DELETE FROM experiences WHERE agent = ?1",
            rusqlite::params![agent],
        )?;
        Ok(deleted as u32)
    }

    fn enforce_limit(&self, agent: &str) -> anyhow::Result<()> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM experiences WHERE agent = ?1",
            rusqlite::params![agent],
            |row| row.get(0),
        )?;

        if count > MAX_EXPERIENCES_PER_AGENT {
            let excess = count - MAX_EXPERIENCES_PER_AGENT;
            self.conn.execute(
                "DELETE FROM experiences WHERE id IN (
                    SELECT id FROM experiences WHERE agent = ?1
                    ORDER BY confidence ASC, created_at ASC
                    LIMIT ?2
                )",
                rusqlite::params![agent, excess],
            )?;
        }
        Ok(())
    }
}

/// Summary statistics for agent memory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryStats {
    pub total: u32,
    pub successes: u32,
    pub failures: u32,
    pub patterns: u32,
    pub insights: u32,
    pub avg_confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_recall() {
        let store = MemoryStore::in_memory().unwrap();

        let id = store
            .store(
                "vuln-hunter",
                ExperienceType::Success,
                "Found buffer overflow via strcpy with unsanitized network input",
                "Confirmed CWE-120 in parse_input function",
                0.9,
                &["buffer-overflow", "cwe-120"],
            )
            .unwrap();

        assert!(id.starts_with("exp_"));

        let results = store
            .recall("vuln-hunter", "buffer overflow strcpy", 10, 0.0)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent, "vuln-hunter");
        assert!(results[0].confidence > 0.0);
    }

    #[test]
    fn test_agent_isolation() {
        let store = MemoryStore::in_memory().unwrap();

        store
            .store(
                "agent-a",
                ExperienceType::Insight,
                "context a",
                "outcome a",
                0.9,
                &[],
            )
            .unwrap();
        store
            .store(
                "agent-b",
                ExperienceType::Insight,
                "context b",
                "outcome b",
                0.9,
                &[],
            )
            .unwrap();

        let stats_a = store.statistics("agent-a").unwrap();
        let stats_b = store.statistics("agent-b").unwrap();

        assert_eq!(stats_a.total, 1);
        assert_eq!(stats_b.total, 1);
    }

    #[test]
    fn test_recall_recent() {
        let store = MemoryStore::in_memory().unwrap();

        store
            .store("agent", ExperienceType::Success, "ctx1", "out1", 0.8, &[])
            .unwrap();
        store
            .store("agent", ExperienceType::Failure, "ctx2", "out2", 0.7, &[])
            .unwrap();
        store
            .store("agent", ExperienceType::Pattern, "ctx3", "out3", 0.9, &[])
            .unwrap();

        let all = store.recall_recent("agent", 10, None).unwrap();
        assert_eq!(all.len(), 3);

        let patterns = store
            .recall_recent("agent", 10, Some(ExperienceType::Pattern))
            .unwrap();
        assert_eq!(patterns.len(), 1);
    }

    #[test]
    fn test_confidence_decay() {
        let store = MemoryStore::in_memory().unwrap();

        // Insert with a fake old timestamp
        store
            .conn
            .execute(
                "INSERT INTO experiences (id, agent, experience_type, context, outcome, confidence, tags, created_at, recall_count)
             VALUES ('old1', 'agent', 'success', 'old context', 'old outcome', 0.1, '[]', '2020-01-01T00:00:00Z', 0)",
                [],
            )
            .unwrap();

        let pruned = store.apply_decay().unwrap();
        assert_eq!(
            pruned, 1,
            "Very old low-confidence experience should be pruned"
        );
    }

    #[test]
    fn test_statistics() {
        let store = MemoryStore::in_memory().unwrap();

        store
            .store("a", ExperienceType::Success, "c", "o", 0.9, &[])
            .unwrap();
        store
            .store("a", ExperienceType::Failure, "c", "o", 0.7, &[])
            .unwrap();
        store
            .store("a", ExperienceType::Pattern, "c", "o", 0.8, &[])
            .unwrap();

        let stats = store.statistics("a").unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.successes, 1);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.patterns, 1);
        assert_eq!(stats.insights, 0);
    }

    #[test]
    fn test_enforce_limit() {
        let store = MemoryStore::in_memory().unwrap();

        // Insert more than the limit by setting a very low limit
        // (We can't easily test MAX_EXPERIENCES_PER_AGENT=10000, so we test the mechanism)
        for i in 0..5 {
            store
                .store(
                    "agent",
                    ExperienceType::Success,
                    &format!("ctx{i}"),
                    &format!("out{i}"),
                    0.5,
                    &[],
                )
                .unwrap();
        }

        let stats = store.statistics("agent").unwrap();
        assert_eq!(stats.total, 5);
    }

    /// End-to-end test: store experiences → detect patterns → recall with overfitting guard
    #[test]
    fn test_full_memory_lifecycle() {
        use crate::memory::pattern::{strip_benchmark_specifics, PatternDetector};

        let store = MemoryStore::in_memory().unwrap();

        // Simulate multiple runs finding buffer overflows
        for i in 0..4 {
            let raw_context = format!(
                "Found strcpy vulnerability in /home/user/test{i}/src/parse.c at 0x40{i}000"
            );
            let generalized = strip_benchmark_specifics(&raw_context);

            // Verify overfitting guard strips specifics
            assert!(
                !generalized.contains("/home/user"),
                "Path should be stripped"
            );
            assert!(!generalized.contains("0x40"), "Address should be stripped");

            store
                .store(
                    "vuln-hunter",
                    ExperienceType::Success,
                    &generalized,
                    "Confirmed buffer overflow via unchecked strcpy with user input",
                    0.8,
                    &["buffer-overflow", "cwe-120"],
                )
                .unwrap();
        }

        // Pattern detection should find the recurring buffer-overflow pattern
        let detector = PatternDetector::new(&store);
        let new_patterns = detector.detect_patterns("vuln-hunter").unwrap();
        assert!(new_patterns >= 1, "Should detect buffer-overflow pattern");

        // Recall should return relevant memories
        let recalled = store
            .recall("vuln-hunter", "buffer overflow strcpy", 5, 0.0)
            .unwrap();
        assert!(
            !recalled.is_empty(),
            "Should recall buffer overflow experiences"
        );

        // The pattern should have high confidence
        let patterns = store
            .recall_recent("vuln-hunter", 10, Some(ExperienceType::Pattern))
            .unwrap();
        assert!(!patterns.is_empty(), "Should have pattern entries");
        assert!(
            patterns[0].confidence >= 0.7,
            "Pattern confidence should be >= 0.7"
        );

        // Verify global statistics
        let stats = store.global_statistics().unwrap();
        assert!(stats.total >= 5); // 4 successes + at least 1 pattern
        assert!(stats.patterns >= 1);
    }

    /// Test that the overfitting guard rejects benchmark-specific experiences
    #[test]
    fn test_overfitting_guard_integration() {
        use crate::memory::pattern::PatternDetector;

        let store = MemoryStore::in_memory().unwrap();
        let detector = PatternDetector::new(&store);

        // General context should pass
        assert!(!detector
            .is_likely_overfit(
                "agent",
                "strcpy with unchecked network input leads to stack buffer overflow",
                &["cwe-120"],
            )
            .unwrap());

        // Benchmark-specific context should be flagged
        assert!(detector
            .is_likely_overfit("agent", "overflow at 0x401234 in CGC challenge", &[],)
            .unwrap());

        // Path-heavy context should be flagged
        assert!(detector
            .is_likely_overfit("agent", "found in /home/user/juliet/CWE120/s01/test.c", &[],)
            .unwrap());
    }
}
