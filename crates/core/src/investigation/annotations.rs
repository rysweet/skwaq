//! Annotation management for investigations.
//!
//! `AnnotationManager` creates and retrieves free-text annotations
//! attached to investigation records in the database.

use crate::graph::GraphDb;
use chrono::Utc;
use uuid::Uuid;

/// Manages annotation records in the graph.
pub struct AnnotationManager<'a> {
    db: &'a GraphDb,
}

/// A single annotation record.
#[derive(Debug, Clone)]
pub struct Annotation {
    pub id: String,
    pub content: String,
    pub author: String,
    pub created_at: String,
}

impl<'a> AnnotationManager<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Add an annotation to an investigation.
    pub fn add(
        &self,
        investigation_id: &str,
        content: &str,
        author: &str,
    ) -> anyhow::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
            "INSERT INTO annotations (id, target_address, text, author, timestamp, investigation_id) \
             VALUES (?1, '', ?2, ?3, ?4, ?5)",
            &[&id.as_str(), &content, &author, &now.as_str(), &investigation_id],
        )?;
        Ok(id)
    }

    /// List annotations for an investigation.
    pub fn list(&self, investigation_id: &str) -> anyhow::Result<Vec<Annotation>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, text, author, timestamp FROM annotations \
             WHERE investigation_id = ?1 ORDER BY timestamp DESC"
        )?;
        let rows = stmt.query_map([investigation_id], |row| {
            Ok(Annotation {
                id: row.get(0)?,
                content: row.get(1)?,
                author: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}
