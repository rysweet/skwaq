//! Variant analysis.
//!
//! `VariantAnalyzer` searches the graph for code patterns structurally
//! similar to a known vulnerability, detecting potential variant bugs
//! elsewhere in the binary.

use std::collections::HashSet;

use crate::graph::GraphDb;

/// Searches for structural variants of known vulnerabilities.
pub struct VariantAnalyzer<'a> {
    db: &'a GraphDb,
}

impl<'a> VariantAnalyzer<'a> {
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Get the set of callee names for a given function name.
    fn get_callees(&self, func_name: &str) -> anyhow::Result<HashSet<String>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT f2.name FROM calls c \
             JOIN functions f1 ON c.caller_id = f1.id \
             JOIN functions f2 ON c.callee_id = f2.id \
             WHERE f1.name = ?1",
        )?;
        let rows = stmt.query_map([func_name], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<HashSet<_>, _>>()?)
    }

    /// Find code patterns similar to `pattern_id` across the graph.
    ///
    /// Looks up the vulnerability identified by `pattern_id`, then searches
    /// for other functions with similar call patterns using Jaccard similarity
    /// of callee sets.
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

        // Get callees of the pattern function.
        let pattern_callees = self.get_callees(&func_name)?;
        if pattern_callees.is_empty() {
            return Ok(Vec::new());
        }

        // Find other functions that share at least one callee with the pattern function.
        let mut stmt = self.db.conn().prepare(
            "SELECT DISTINCT f2.name FROM calls c1 \
             JOIN calls c2 ON c1.callee_id = c2.callee_id \
             JOIN functions f1 ON c1.caller_id = f1.id \
             JOIN functions f2 ON c2.caller_id = f2.id \
             WHERE f1.name = ?1 AND f2.name != ?1"
        )?;
        let candidate_names: Vec<String> = stmt
            .query_map([&func_name], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Compute Jaccard similarity for each candidate.
        let mut hits = Vec::new();
        for candidate_name in candidate_names {
            let candidate_callees = self.get_callees(&candidate_name)?;
            let intersection = pattern_callees.intersection(&candidate_callees).count();
            let union = pattern_callees.union(&candidate_callees).count();
            let similarity = if union > 0 {
                intersection as f64 / union as f64
            } else {
                0.0
            };

            hits.push(VariantHit {
                function_name: candidate_name,
                similarity,
                description: format!("Shares callee pattern with {} (Jaccard: {:.2})", func_name, similarity),
            });
        }

        // Sort by similarity descending.
        hits.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));

        Ok(hits)
    }
}

/// A potential variant of a known vulnerability.
#[derive(Debug, Clone)]
pub struct VariantHit {
    pub function_name: String,
    pub similarity: f64,
    pub description: String,
}
