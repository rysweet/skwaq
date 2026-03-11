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
        self.db.execute(
            "INSERT INTO hypotheses (id, description, status, confidence, timestamp, investigation_id) \
             VALUES (?1, ?2, 'pending', ?3, ?4, ?5)",
            &[
                &id.as_str() as &dyn rusqlite::types::ToSql,
                &statement,
                &confidence as &dyn rusqlite::types::ToSql,
                &now.as_str(),
                &investigation_id,
            ],
        )?;
        Ok(id)
    }

    /// Update the status and confidence of a hypothesis.
    pub fn update(&self, hypothesis_id: &str, status: &str, confidence: f64) -> anyhow::Result<()> {
        let rows = self.db.execute(
            "UPDATE hypotheses SET status = ?1, confidence = ?2 WHERE id = ?3",
            &[
                &status as &dyn rusqlite::types::ToSql,
                &confidence as &dyn rusqlite::types::ToSql,
                &hypothesis_id,
            ],
        )?;
        if rows == 0 {
            anyhow::bail!("hypothesis not found: {}", hypothesis_id);
        }
        Ok(())
    }

    /// List hypotheses for an investigation.
    pub fn list(&self, investigation_id: &str) -> anyhow::Result<Vec<Hypothesis>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, description, status, confidence, timestamp FROM hypotheses \
             WHERE investigation_id = ?1 ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map([investigation_id], |row| {
            Ok(Hypothesis {
                id: row.get(0)?,
                statement: row.get(1)?,
                status: row.get(2)?,
                confidence: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_investigation(db: &GraphDb) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
             VALUES (?1, ?2, '', 'active', ?3, ?3)",
            &[
                &id.as_str() as &dyn rusqlite::types::ToSql,
                &"test",
                &now.as_str(),
            ],
        )
        .unwrap();
        id
    }

    #[test]
    fn test_create_and_list() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = setup_investigation(&db);
        let mgr = HypothesisManager::new(&db);

        let h_id = mgr
            .create(&inv_id, "buffer overflow possible", 0.8)
            .unwrap();
        assert!(!h_id.is_empty());

        let list = mgr.list(&inv_id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].statement, "buffer overflow possible");
        assert_eq!(list[0].status, "pending");
        assert!((list[0].confidence - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_update() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = setup_investigation(&db);
        let mgr = HypothesisManager::new(&db);

        let h_id = mgr.create(&inv_id, "test hypothesis", 0.5).unwrap();
        mgr.update(&h_id, "confirmed", 0.95).unwrap();

        let list = mgr.list(&inv_id).unwrap();
        assert_eq!(list[0].status, "confirmed");
        assert!((list[0].confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_list_empty() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = setup_investigation(&db);
        let mgr = HypothesisManager::new(&db);

        let list = mgr.list(&inv_id).unwrap();
        assert!(list.is_empty());
    }
}
