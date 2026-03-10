//! Attack surface analysis.
//!
//! `AttackSurfaceAnalyzer` identifies externally-reachable entry points
//! (exported functions, network listeners, IPC handlers) and scores
//! them by exposure risk.

use crate::graph::GraphDb;

/// Identifies and scores attack surface entry points.
pub struct AttackSurfaceAnalyzer<'a> {
    db: &'a GraphDb,
}

impl<'a> AttackSurfaceAnalyzer<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Enumerate externally-reachable functions and score exposure risk.
    pub fn analyze(&self) -> anyhow::Result<Vec<SurfaceEntry>> {
        let _ = self.db;
        todo!("attack surface analysis not yet implemented")
    }
}

/// A single entry point on the attack surface.
#[derive(Debug, Clone)]
pub struct SurfaceEntry {
    pub function_name: String,
    pub entry_type: String,
    pub risk_score: f64,
}
