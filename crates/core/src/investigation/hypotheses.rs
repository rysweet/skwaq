//! Hypothesis tracking for investigations.
//!
//! `HypothesisManager` creates and updates hypotheses that the analyst
//! or AI agents propose during an investigation.

use crate::graph::GraphDb;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Manages hypothesis records in the graph.
pub struct HypothesisManager<'a> {
    db: &'a GraphDb,
}

/// A single hypothesis record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub statement: String,
    pub status: String,
    pub confidence: f64,
    pub created_at: String,
}

impl<'a> HypothesisManager<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Create a new hypothesis attached to an investigation.
    pub fn create(
        &self,
        investigation_id: &str,
        statement: &str,
        confidence: f64,
    ) -> anyhow::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let evidence = format!("confidence={}", confidence);
        self.db.execute(
            "INSERT INTO hypotheses (id, description, status, evidence, timestamp, investigation_id) \
             VALUES (?1, ?2, 'pending', ?3, ?4, ?5)",
            &[&id.as_str(), &statement, &evidence.as_str(), &now.as_str(), &investigation_id],
        )?;
        Ok(id)
    }

    /// Update the status and confidence of a hypothesis.
    pub fn update(
        &self,
        hypothesis_id: &str,
        status: &str,
        confidence: f64,
    ) -> anyhow::Result<()> {
        let evidence = format!("confidence={}", confidence);
        let rows = self.db.execute(
            "UPDATE hypotheses SET status = ?1, evidence = ?2 WHERE id = ?3",
            &[&status, &evidence.as_str(), &hypothesis_id],
        )?;
        if rows == 0 {
            anyhow::bail!("hypothesis not found: {}", hypothesis_id);
        }
        Ok(())
    }

    /// List hypotheses for an investigation.
    pub fn list(&self, investigation_id: &str) -> anyhow::Result<Vec<Hypothesis>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, description, status, evidence, timestamp FROM hypotheses \
             WHERE investigation_id = ?1 ORDER BY timestamp DESC"
        )?;
        let rows = stmt.query_map([investigation_id], |row| {
            let evidence: String = row.get(3)?;
            let confidence = evidence
                .strip_prefix("confidence=")
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0);
            Ok(Hypothesis {
                id: row.get(0)?,
                statement: row.get(1)?,
                status: row.get(2)?,
                confidence,
                created_at: row.get(4)?,
            })
        })?;
        let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
        Ok(results)
    }
}
