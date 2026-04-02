//! LadybugDB-backed persistent memory store.
//!
//! Stores agent experiences as graph nodes in LadybugDB, enabling
//! native Cypher queries for recall and relationship traversal.

use super::experience::{Experience, ExperienceType};
use crate::graph::ladybug_db::LadybugGraphDb;
use std::path::Path;

/// Persistent memory store backed by LadybugDB.
#[derive(Clone)]
pub struct MemoryStore {
    db: LadybugGraphDb,
}

/// Maximum number of experiences per agent.
const MAX_EXPERIENCES_PER_AGENT: u32 = 10_000;

/// Confidence decay rate per day.
const CONFIDENCE_DECAY_PER_DAY: f64 = 0.005;

/// Minimum confidence threshold.
const MIN_CONFIDENCE: f64 = 0.05;

impl MemoryStore {
    /// Open (or create) a memory store at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = LadybugGraphDb::open(path)?;
        let store = Self { db };
        store.ensure_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (for tests).
    pub fn in_memory() -> anyhow::Result<Self> {
        let db = LadybugGraphDb::in_memory()?;
        let store = Self { db };
        store.ensure_schema()?;
        Ok(store)
    }

    /// Open an existing memory store in read-only mode.
    ///
    /// Multiple processes can open the same store read-only simultaneously.
    /// Write operations (store, recall_count increment) are silently skipped.
    pub fn open_read_only(path: &Path) -> anyhow::Result<Self> {
        let db = LadybugGraphDb::open_read_only(path)?;
        Ok(Self { db })
    }

    /// Open the default memory store.
    pub fn open_default() -> anyhow::Result<Self> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let path = home.join(".skwaq").join("memory_graph");
        Self::open(&path)
    }

    /// Open the default memory store in read-only mode (for parallel shards).
    pub fn open_default_read_only() -> anyhow::Result<Self> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let path = home.join(".skwaq").join("memory_graph");
        Self::open_read_only(&path)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        let ddl = "CREATE NODE TABLE IF NOT EXISTS Experience(\
            id STRING PRIMARY KEY, \
            agent STRING, \
            experience_type STRING, \
            context STRING, \
            outcome STRING, \
            confidence DOUBLE DEFAULT 1.0, \
            tags STRING DEFAULT '[]', \
            created_at STRING, \
            recall_count INT64 DEFAULT 0\
        )";
        if let Err(e) = self.db.execute(ddl) {
            if !e.to_string().contains("already exists") {
                return Err(e);
            }
        }
        Ok(())
    }

    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('\'', "\\'")
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
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let tags_vec: Vec<String> = tags.iter().map(|s| s.to_string()).collect();
        let tags_json = serde_json::to_string(&tags_vec)?;

        let cypher = format!(
            "CREATE (e:Experience {{id: '{id}', agent: '{agent}', experience_type: '{etype}', \
             context: '{ctx}', outcome: '{out}', confidence: {conf}, tags: '{tgs}', \
             created_at: '{created}', recall_count: 0}})",
            id = Self::esc(&id),
            agent = Self::esc(agent),
            etype = experience_type.as_str(),
            ctx = Self::esc(context),
            out = Self::esc(outcome),
            conf = confidence,
            tgs = Self::esc(&tags_json),
            created = Self::esc(&now),
        );
        self.db.execute(&cypher)?;
        self.prune_agent(agent)?;
        Ok(id)
    }

    /// Recall experiences matching a query, ranked by relevance.
    pub fn recall(
        &self,
        agent: &str,
        query: &str,
        limit: usize,
        min_confidence: f64,
    ) -> anyhow::Result<Vec<Experience>> {
        let cypher = format!(
            "MATCH (e:Experience) WHERE e.agent = '{}' AND e.confidence >= {} \
             RETURN e.id, e.agent, e.experience_type, e.context, e.outcome, \
                    e.confidence, e.tags, e.created_at, e.recall_count \
             ORDER BY e.confidence DESC",
            Self::esc(agent),
            if min_confidence > 0.0 {
                min_confidence
            } else {
                MIN_CONFIDENCE
            }
        );

        let rows = self.db.query(&cypher)?;
        let mut experiences: Vec<Experience> = rows
            .iter()
            .filter_map(|r| self.row_to_experience(r))
            .collect();

        experiences.sort_by(|a, b| {
            b.relevance_to(query)
                .partial_cmp(&a.relevance_to(query))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        experiences.truncate(limit);

        // Increment recall_count — best-effort, silently skipped in read-only mode.
        for exp in &experiences {
            if let Err(e) = self.db.execute(&format!(
                "MATCH (e:Experience {{id: '{}'}}) SET e.recall_count = e.recall_count + 1",
                Self::esc(&exp.id)
            )) {
                tracing::trace!("recall_count update skipped (read-only?): {e}");
            }
        }

        Ok(experiences)
    }

    /// Recall the N most recent experiences for an agent.
    pub fn recall_recent(
        &self,
        agent: &str,
        limit: usize,
        experience_type: Option<ExperienceType>,
    ) -> anyhow::Result<Vec<Experience>> {
        let type_filter = match experience_type {
            Some(et) => format!("AND e.experience_type = '{}'", et.as_str()),
            None => String::new(),
        };
        let cypher = format!(
            "MATCH (e:Experience) WHERE e.agent = '{}' {} \
             RETURN e.id, e.agent, e.experience_type, e.context, e.outcome, \
                    e.confidence, e.tags, e.created_at, e.recall_count \
             ORDER BY e.created_at DESC LIMIT {}",
            Self::esc(agent),
            type_filter,
            limit
        );
        let rows = self.db.query(&cypher)?;
        Ok(rows
            .iter()
            .filter_map(|r| self.row_to_experience(r))
            .collect())
    }

    /// Apply confidence decay to all experiences.
    pub fn apply_decay(&self) -> anyhow::Result<u32> {
        let decay = 1.0 - CONFIDENCE_DECAY_PER_DAY;
        let _ = self.db.execute(&format!(
            "MATCH (e:Experience) SET e.confidence = e.confidence * {}",
            decay
        ));
        let _ = self.db.execute(&format!(
            "MATCH (e:Experience) WHERE e.confidence < {} DELETE e",
            MIN_CONFIDENCE
        ));
        Ok(0)
    }

    /// Get statistics for a specific agent.
    pub fn statistics(&self, agent: &str) -> anyhow::Result<MemoryStats> {
        let agent_esc = Self::esc(agent);
        let rows = self.db.query(&format!(
            "MATCH (e:Experience) WHERE e.agent = '{agent_esc}' \
             RETURN e.experience_type, count(e), avg(e.confidence), sum(e.recall_count)"
        ))?;
        let mut stats = MemoryStats::default();
        for row in &rows {
            let etype = LadybugGraphDb::as_str(&row[0]).unwrap_or("");
            let cnt = LadybugGraphDb::as_i64(&row[1]).unwrap_or(0) as u32;
            let avg = LadybugGraphDb::as_f64(&row[2]).unwrap_or(0.0);
            let recalls = LadybugGraphDb::as_i64(&row[3]).unwrap_or(0) as u32;
            stats.total_experiences += cnt;
            stats.total_recalls += recalls;
            stats.avg_confidence = avg;
            match etype {
                "success" => stats.successes = cnt,
                "failure" => stats.failures = cnt,
                "pattern" => stats.patterns = cnt,
                "insight" => stats.insights = cnt,
                _ => {}
            }
        }
        Ok(stats)
    }

    /// Get global statistics across all agents.
    pub fn global_statistics(&self) -> anyhow::Result<MemoryStats> {
        let rows = self.db.query(
            "MATCH (e:Experience) \
             RETURN e.experience_type, count(e), avg(e.confidence), sum(e.recall_count)",
        )?;
        let mut stats = MemoryStats::default();
        for row in &rows {
            let etype = LadybugGraphDb::as_str(&row[0]).unwrap_or("");
            let cnt = LadybugGraphDb::as_i64(&row[1]).unwrap_or(0) as u32;
            let avg = LadybugGraphDb::as_f64(&row[2]).unwrap_or(0.0);
            let recalls = LadybugGraphDb::as_i64(&row[3]).unwrap_or(0) as u32;
            stats.total_experiences += cnt;
            stats.total_recalls += recalls;
            stats.avg_confidence = avg;
            match etype {
                "success" => stats.successes = cnt,
                "failure" => stats.failures = cnt,
                "pattern" => stats.patterns = cnt,
                "insight" => stats.insights = cnt,
                _ => {}
            }
        }
        Ok(stats)
    }

    /// Clear all experiences for a specific agent.
    pub fn clear_agent(&self, agent: &str) -> anyhow::Result<u32> {
        let _ = self.db.execute(&format!(
            "MATCH (e:Experience) WHERE e.agent = '{}' DELETE e",
            Self::esc(agent)
        ));
        Ok(0)
    }

    fn prune_agent(&self, agent: &str) -> anyhow::Result<()> {
        let rows = self.db.query(&format!(
            "MATCH (e:Experience) WHERE e.agent = '{}' RETURN count(e)",
            Self::esc(agent)
        ))?;
        let count = rows
            .first()
            .and_then(|r| LadybugGraphDb::as_i64(&r[0]))
            .unwrap_or(0) as u32;
        if count > MAX_EXPERIENCES_PER_AGENT {
            let excess = count - MAX_EXPERIENCES_PER_AGENT;
            let _ = self.db.execute(&format!(
                "MATCH (e:Experience) WHERE e.agent = '{}' \
                 WITH e ORDER BY e.confidence ASC LIMIT {} DELETE e",
                Self::esc(agent),
                excess
            ));
        }
        Ok(())
    }

    fn row_to_experience(&self, row: &[lbug::Value]) -> Option<Experience> {
        if row.len() < 9 {
            return None;
        }
        Some(Experience {
            id: LadybugGraphDb::as_str(&row[0])?.to_string(),
            agent: LadybugGraphDb::as_str(&row[1])?.to_string(),
            experience_type: ExperienceType::from_str(LadybugGraphDb::as_str(&row[2])?)?,
            context: LadybugGraphDb::as_str(&row[3])?.to_string(),
            outcome: LadybugGraphDb::as_str(&row[4])?.to_string(),
            confidence: match &row[5] {
                lbug::Value::Double(d) => *d,
                _ => 1.0,
            },
            tags: serde_json::from_str(LadybugGraphDb::as_str(&row[6]).unwrap_or("[]"))
                .unwrap_or_default(),
            created_at: LadybugGraphDb::as_str(&row[7])?.to_string(),
            recall_count: LadybugGraphDb::as_i64(&row[8]).unwrap_or(0) as u32,
        })
    }
}

/// Memory store statistics.
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_experiences: u32,
    pub successes: u32,
    pub failures: u32,
    pub patterns: u32,
    pub insights: u32,
    pub avg_confidence: f64,
    pub total_recalls: u32,
}

impl MemoryStats {
    /// Alias for backward compatibility with CLI.
    pub fn total(&self) -> u32 {
        self.total_experiences
    }
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self {
            total_experiences: 0,
            successes: 0,
            failures: 0,
            patterns: 0,
            insights: 0,
            avg_confidence: 0.0,
            total_recalls: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_recall() {
        let store = MemoryStore::in_memory().unwrap();
        let id = store
            .store(
                "test-agent",
                ExperienceType::Pattern,
                "Buffer overflow in strcpy without bounds check",
                "Detected CWE-120 true positive",
                1.0,
                &["cwe-120", "buffer-overflow"],
            )
            .unwrap();
        assert!(!id.is_empty());
        let results = store
            .recall("test-agent", "buffer overflow strcpy", 10, 0.0)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].context.contains("strcpy"));
    }

    #[test]
    fn test_recall_empty() {
        let store = MemoryStore::in_memory().unwrap();
        let results = store.recall("nonexistent", "anything", 10, 0.0).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_statistics() {
        let store = MemoryStore::in_memory().unwrap();
        store
            .store("agent-a", ExperienceType::Success, "ctx", "out", 1.0, &[])
            .unwrap();
        store
            .store("agent-a", ExperienceType::Failure, "ctx2", "out2", 1.0, &[])
            .unwrap();
        let stats = store.statistics("agent-a").unwrap();
        assert_eq!(stats.total_experiences, 2);
    }

    #[test]
    fn test_clear_agent() {
        let store = MemoryStore::in_memory().unwrap();
        store
            .store("agent-a", ExperienceType::Pattern, "ctx", "out", 1.0, &[])
            .unwrap();
        store.clear_agent("agent-a").unwrap();
        let stats = store.statistics("agent-a").unwrap();
        assert_eq!(stats.total_experiences, 0);
    }
}
