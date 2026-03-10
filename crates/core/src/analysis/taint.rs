//! Taint analysis via graph traversal.
//!
//! `TaintAnalyzer` queries the Kùzu graph for data-flow paths from
//! sources to sinks that lack sanitisation, producing candidate
//! vulnerability findings.

use crate::graph::GraphDb;

/// Performs taint analysis over the property graph.
pub struct TaintAnalyzer<'a> {
    db: &'a GraphDb,
    max_depth: u32,
}

impl<'a> TaintAnalyzer<'a> {
    pub fn new(db: &'a GraphDb, max_depth: u32) -> Self {
        Self { db, max_depth }
    }

    /// Find data-flow paths from sources to sinks where no sanitiser
    /// appears along the path.
    pub fn find_unsanitized_paths(&self) -> anyhow::Result<Vec<TaintPath>> {
        let cypher = format!(
            "MATCH path = (src:DataSource)-[:TAINT_FLOW*1..{depth}]->(snk:DataSink) \
             RETURN src.name, snk.name",
            depth = self.max_depth,
        );
        let _result = self.db.query(&cypher)?;
        // TODO: iterate result rows and build TaintPath values
        Ok(Vec::new())
    }
}

/// A single unsanitized taint path from source to sink.
#[derive(Debug, Clone)]
pub struct TaintPath {
    pub source: String,
    pub sink: String,
    pub hops: Vec<String>,
}
