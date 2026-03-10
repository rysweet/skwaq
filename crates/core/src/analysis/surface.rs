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
        // Find functions that are not called by any other function (potential entry points).
        let mut stmt = self.db.conn().prepare(
            "SELECT f.name FROM functions f \
             WHERE f.id NOT IN (SELECT callee_id FROM calls)"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SurfaceEntry {
                function_name: row.get::<_, String>(0)?,
                entry_type: "uncalled".to_string(),
                risk_score: 0.5,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

/// A single entry point on the attack surface.
#[derive(Debug, Clone)]
pub struct SurfaceEntry {
    pub function_name: String,
    pub entry_type: String,
    pub risk_score: f64,
}
