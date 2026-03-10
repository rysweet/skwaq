//! Variant analysis.
//!
//! `VariantAnalyzer` searches the graph for code patterns structurally
//! similar to a known vulnerability, detecting potential variant bugs
//! elsewhere in the binary.

use crate::graph::GraphDb;

/// Searches for structural variants of known vulnerabilities.
pub struct VariantAnalyzer<'a> {
    db: &'a GraphDb,
}

impl<'a> VariantAnalyzer<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Find code patterns similar to `pattern_id` across the graph.
    pub fn find_variants(&self, _pattern_id: &str) -> anyhow::Result<Vec<VariantHit>> {
        let _ = self.db;
        todo!("variant analysis not yet implemented")
    }
}

/// A potential variant of a known vulnerability.
#[derive(Debug, Clone)]
pub struct VariantHit {
    pub function_name: String,
    pub similarity: f64,
    pub description: String,
}
