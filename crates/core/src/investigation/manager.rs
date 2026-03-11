//! Investigation lifecycle management.
//!
//! `InvestigationManager` creates, lists, retrieves, and resumes
//! investigations stored in the SQLite graph database.

use crate::graph::GraphDb;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Manages investigation records in the graph.
pub struct InvestigationManager<'a> {
    db: &'a GraphDb,
}

/// Summary of an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
}

impl<'a> InvestigationManager<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Create a new investigation and return its id.
    pub fn create(&self, name: &str) -> anyhow::Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        self.db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
             VALUES (?1, ?2, '', 'active', ?3, ?3)",
            &[&id.as_str(), &name, &now.as_str()],
        )?;
        Ok(id)
    }

    /// List all investigations.
    pub fn list(&self) -> anyhow::Result<Vec<InvestigationSummary>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT id, name, status, created_at FROM investigations \
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(InvestigationSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                status: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
        Ok(results)
    }

    /// Retrieve a single investigation by id.
    pub fn get(&self, id: &str) -> anyhow::Result<Option<InvestigationSummary>> {
        let result = self.db.conn().query_row(
            "SELECT id, name, status, created_at FROM investigations WHERE id = ?1",
            [id],
            |row| {
                Ok(InvestigationSummary {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    status: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        );
        match result {
            Ok(summary) => Ok(Some(summary)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Resume an investigation by setting its status back to 'active'.
    pub fn resume(&self, id: &str) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        let rows = self.db.execute(
            "UPDATE investigations SET status = 'active', updated_at = ?1 WHERE id = ?2",
            &[&now.as_str(), &id],
        )?;
        if rows == 0 {
            anyhow::bail!("investigation not found: {}", id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get() {
        let db = GraphDb::in_memory().unwrap();
        let mgr = InvestigationManager::new(&db);

        let id = mgr.create("test investigation").unwrap();
        let inv = mgr.get(&id).unwrap().expect("should exist");
        assert_eq!(inv.name, "test investigation");
        assert_eq!(inv.status, "active");
    }

    #[test]
    fn test_list() {
        let db = GraphDb::in_memory().unwrap();
        let mgr = InvestigationManager::new(&db);

        assert!(mgr.list().unwrap().is_empty());

        mgr.create("inv-a").unwrap();
        mgr.create("inv-b").unwrap();

        let list = mgr.list().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_get_not_found() {
        let db = GraphDb::in_memory().unwrap();
        let mgr = InvestigationManager::new(&db);

        let result = mgr.get("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resume() {
        let db = GraphDb::in_memory().unwrap();
        let mgr = InvestigationManager::new(&db);

        let id = mgr.create("resume test").unwrap();
        // Mark as completed first
        db.execute(
            "UPDATE investigations SET status = 'completed' WHERE id = ?1",
            &[&id.as_str() as &dyn rusqlite::types::ToSql],
        )
        .unwrap();

        mgr.resume(&id).unwrap();
        let inv = mgr.get(&id).unwrap().expect("should exist");
        assert_eq!(inv.status, "active");
    }

    #[test]
    fn test_resume_not_found() {
        let db = GraphDb::in_memory().unwrap();
        let mgr = InvestigationManager::new(&db);

        let err = mgr.resume("nonexistent").unwrap_err();
        assert!(err.to_string().contains("investigation not found"));
    }
}
