//! Annotation management for investigations.
//!
//! `AnnotationManager` creates and retrieves free-text annotations
//! attached to investigation records in the database.

use crate::graph::GraphDb;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Manages annotation records in the graph.
pub struct AnnotationManager<'a> {
    db: &'a GraphDb,
}

/// A single annotation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
             WHERE investigation_id = ?1 ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map([investigation_id], |row| {
            Ok(Annotation {
                id: row.get(0)?,
                content: row.get(1)?,
                author: row.get(2)?,
                created_at: row.get(3)?,
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
    fn test_add_and_list() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = setup_investigation(&db);
        let mgr = AnnotationManager::new(&db);

        let a_id = mgr
            .add(&inv_id, "suspicious pattern in parse_input", "analyst")
            .unwrap();
        assert!(!a_id.is_empty());

        let list = mgr.list(&inv_id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].content, "suspicious pattern in parse_input");
        assert_eq!(list[0].author, "analyst");
    }

    #[test]
    fn test_list_empty() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = setup_investigation(&db);
        let mgr = AnnotationManager::new(&db);

        let list = mgr.list(&inv_id).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn test_add_multiple() {
        let db = GraphDb::in_memory().unwrap();
        let inv_id = setup_investigation(&db);
        let mgr = AnnotationManager::new(&db);

        mgr.add(&inv_id, "note one", "user1").unwrap();
        mgr.add(&inv_id, "note two", "user2").unwrap();

        let list = mgr.list(&inv_id).unwrap();
        assert_eq!(list.len(), 2);
    }
}
