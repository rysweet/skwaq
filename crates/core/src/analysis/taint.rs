//! Taint analysis via graph traversal.
//!
//! `TaintAnalyzer` queries the SQLite graph for data-flow paths from
//! sources to sinks that lack sanitisation, producing candidate
//! vulnerability findings.

use crate::graph::GraphDb;

/// Performs taint analysis over the property graph.
pub struct TaintAnalyzer<'a> {
    db: &'a GraphDb,
    _max_depth: u32,
}

impl<'a> TaintAnalyzer<'a> {
    pub fn new(db: &'a GraphDb, max_depth: u32) -> Self {
        Self { db, _max_depth: max_depth }
    }

    /// Find data-flow paths from sources to sinks where no sanitiser
    /// appears along the path.
    pub fn find_unsanitized_paths(&self) -> anyhow::Result<Vec<TaintPath>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT s.name, k.name, tf.path FROM taint_flows tf \
             JOIN data_sources s ON tf.source_id = s.id \
             JOIN data_sinks k ON tf.sink_id = k.id \
             WHERE tf.sanitized = 0"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaintPath {
                source: row.get::<_, String>(0)?,
                sink: row.get::<_, String>(1)?,
                hops: row.get::<_, String>(2)?
                    .split("->")
                    .map(|s| s.trim().to_string())
                    .collect(),
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

/// A single unsanitized taint path from source to sink.
#[derive(Debug, Clone)]
pub struct TaintPath {
    pub source: String,
    pub sink: String,
    pub hops: Vec<String>,
}
