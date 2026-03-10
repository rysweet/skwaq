//! Investigation lifecycle management.
//!
//! `InvestigationManager` creates, lists, retrieves, and resumes
//! investigations stored as nodes in the Kùzu graph database.

use crate::graph::GraphDb;
use chrono::Utc;
use uuid::Uuid;

/// Manages investigation nodes in the graph.
pub struct InvestigationManager<'a> {
    db: &'a GraphDb,
}

/// Summary of an investigation.
#[derive(Debug, Clone)]
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
        let cypher = format!(
            "CREATE (i:Investigation {{id: '{id}', name: '{name}', status: 'active', \
             created_at: '{now}', updated_at: '{now}'}})"
        );
        self.db.mutate(&cypher)?;
        Ok(id)
    }

    /// List all investigations.
    pub fn list(&self) -> anyhow::Result<Vec<InvestigationSummary>> {
        let _result = self.db.query(
            "MATCH (i:Investigation) RETURN i.id, i.name, i.status, i.created_at \
             ORDER BY i.created_at DESC",
        )?;
        // TODO: iterate rows and collect into Vec<InvestigationSummary>
        Ok(Vec::new())
    }

    /// Retrieve a single investigation by id.
    pub fn get(&self, id: &str) -> anyhow::Result<Option<InvestigationSummary>> {
        let _result = self.db.query(&format!(
            "MATCH (i:Investigation {{id: '{id}'}}) \
             RETURN i.id, i.name, i.status, i.created_at"
        ))?;
        // TODO: parse single row
        Ok(None)
    }

    /// Resume an investigation by setting its status back to 'active'.
    pub fn resume(&self, id: &str) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.db.mutate(&format!(
            "MATCH (i:Investigation {{id: '{id}'}}) \
             SET i.status = 'active', i.updated_at = '{now}'"
        ))
    }
}
