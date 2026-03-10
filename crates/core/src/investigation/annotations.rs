//! Annotation management for investigations.
//!
//! `AnnotationManager` creates and retrieves free-text annotations
//! attached to investigation nodes in the graph.

use crate::graph::GraphDb;

/// Manages annotation nodes in the graph.
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
        _investigation_id: &str,
        _content: &str,
        _author: &str,
    ) -> anyhow::Result<String> {
        let _ = self.db;
        todo!("annotation creation not yet implemented")
    }

    /// List annotations for an investigation.
    pub fn list(&self, _investigation_id: &str) -> anyhow::Result<Vec<Annotation>> {
        let _ = self.db;
        todo!("annotation listing not yet implemented")
    }
}
