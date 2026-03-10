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
    ///
    /// Looks up the vulnerability identified by `pattern_id`, then searches
    /// for other functions with similar call patterns.
    pub fn find_variants(&self, pattern_id: &str) -> anyhow::Result<Vec<VariantHit>> {
        // Look up the function associated with the vulnerability pattern.
        let func_name: Option<String> = self.db.conn().query_row(
            "SELECT f.name FROM vulnerabilities v \
             JOIN functions f ON v.function_id = f.id \
             WHERE v.id = ?1",
            [pattern_id],
            |row| row.get(0),
        ).ok();

        let func_name = match func_name {
            Some(n) => n,
            None => return Ok(Vec::new()),
        };

        // Find other functions that call the same callees as the pattern function.
        let mut stmt = self.db.conn().prepare(
            "SELECT DISTINCT f2.name FROM calls c1 \
             JOIN calls c2 ON c1.callee_id = c2.callee_id \
             JOIN functions f1 ON c1.caller_id = f1.id \
             JOIN functions f2 ON c2.caller_id = f2.id \
             WHERE f1.name = ?1 AND f2.name != ?1"
        )?;
        let rows = stmt.query_map([&func_name], |row| {
            Ok(VariantHit {
                function_name: row.get::<_, String>(0)?,
                similarity: 0.5,
                description: format!("Shares callee pattern with {}", func_name),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

/// A potential variant of a known vulnerability.
#[derive(Debug, Clone)]
pub struct VariantHit {
    pub function_name: String,
    pub similarity: f64,
    pub description: String,
}
