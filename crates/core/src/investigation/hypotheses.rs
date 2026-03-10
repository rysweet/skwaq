//! Hypothesis tracking for investigations.
//!
//! `HypothesisManager` creates and updates hypotheses that the analyst
//! or AI agents propose during an investigation.

use crate::graph::GraphDb;

/// Manages hypothesis nodes in the graph.
pub struct HypothesisManager<'a> {
    db: &'a GraphDb,
}

/// A single hypothesis record.
#[derive(Debug, Clone)]
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
        _investigation_id: &str,
        _statement: &str,
        _confidence: f64,
    ) -> anyhow::Result<String> {
        let _ = self.db;
        todo!("hypothesis creation not yet implemented")
    }

    /// Update the status and confidence of a hypothesis.
    pub fn update(
        &self,
        _hypothesis_id: &str,
        _status: &str,
        _confidence: f64,
    ) -> anyhow::Result<()> {
        let _ = self.db;
        todo!("hypothesis update not yet implemented")
    }

    /// List hypotheses for an investigation.
    pub fn list(&self, _investigation_id: &str) -> anyhow::Result<Vec<Hypothesis>> {
        let _ = self.db;
        todo!("hypothesis listing not yet implemented")
    }
}
