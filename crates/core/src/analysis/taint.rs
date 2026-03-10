//! Taint analysis via graph traversal.
//!
//! `TaintAnalyzer` queries the SQLite graph for data-flow paths from
//! sources to sinks that lack sanitisation, producing candidate
//! vulnerability findings.
//!
//! Two strategies are used:
//! 1. Pre-computed taint flows (from the `taint_flows` table populated
//!    during ingestion).
//! 2. On-the-fly call-chain traversal using a recursive CTE to discover
//!    paths from data sources to data sinks through the call graph.

use crate::graph::GraphDb;
use serde::{Deserialize, Serialize};

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
    ///
    /// First checks pre-computed `taint_flows`, then uses a recursive CTE
    /// to discover additional paths through the call graph.
    pub fn find_unsanitized_paths(&self) -> anyhow::Result<Vec<TaintPath>> {
        let mut results = Vec::new();

        // Strategy 1: Pre-computed taint flows from ingestion
        results.extend(self.query_precomputed_flows()?);

        // Strategy 2: On-the-fly discovery via recursive CTE
        results.extend(self.discover_paths_via_call_graph()?);

        // Deduplicate by (source, sink) pair
        results.sort_by(|a, b| (&a.source, &a.sink).cmp(&(&b.source, &b.sink)));
        results.dedup_by(|a, b| a.source == b.source && a.sink == b.sink);

        Ok(results)
    }

    /// Query the pre-computed taint_flows table.
    fn query_precomputed_flows(&self) -> anyhow::Result<Vec<TaintPath>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT s.name, k.name, tf.path FROM taint_flows tf \
             JOIN data_sources s ON tf.source_id = s.id \
             JOIN data_sinks k ON tf.sink_id = k.id \
             WHERE tf.sanitized = 0",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaintPath {
                source: row.get::<_, String>(0)?,
                sink: row.get::<_, String>(1)?,
                hops: row
                    .get::<_, String>(2)?
                    .split("->")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                sanitized: false,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Use a recursive CTE to trace call chains from functions matching
    /// data source names to functions matching data sink names.
    fn discover_paths_via_call_graph(&self) -> anyhow::Result<Vec<TaintPath>> {
        let max_depth = self.max_depth;

        // Get all data source function names
        let mut src_stmt = self
            .db
            .conn()
            .prepare("SELECT DISTINCT name FROM data_sources")?;
        let sources: Vec<String> = src_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Get all data sink function names
        let mut sink_stmt = self
            .db
            .conn()
            .prepare("SELECT DISTINCT name FROM data_sinks")?;
        let sinks: Vec<String> = sink_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        if sources.is_empty() || sinks.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();

        // For each source, trace call chains and see if any reach a sink
        for source in &sources {
            // Find the function id(s) matching this source name
            let mut id_stmt = self
                .db
                .conn()
                .prepare("SELECT id FROM functions WHERE name = ?1")?;
            let source_ids: Vec<String> = id_stmt
                .query_map([source.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;

            for source_id in &source_ids {
                // Recursive CTE to walk the call graph
                let sql = "WITH RECURSIVE call_chain(func_id, func_name, path, depth) AS ( \
                         SELECT f.id, f.name, f.name, 0 \
                         FROM functions f WHERE f.id = ?1 \
                         UNION ALL \
                         SELECT f2.id, f2.name, cc.path || ' -> ' || f2.name, cc.depth + 1 \
                         FROM calls c \
                         JOIN call_chain cc ON c.caller_id = cc.func_id \
                         JOIN functions f2 ON c.callee_id = f2.id \
                         WHERE cc.depth < ?2 \
                     ) \
                     SELECT func_name, path FROM call_chain WHERE depth > 0";

                let mut cte_stmt = self.db.conn().prepare(sql)?;
                let rows = cte_stmt.query_map(rusqlite::params![source_id.as_str(), max_depth], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;

                for row in rows {
                    let (func_name, path) = row?;
                    if sinks.contains(&func_name) {
                        results.push(TaintPath {
                            source: source.clone(),
                            sink: func_name,
                            hops: path
                                .split(" -> ")
                                .map(|s| s.trim().to_string())
                                .collect(),
                            sanitized: false,
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

/// A single unsanitized taint path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: String,
    pub sink: String,
    pub hops: Vec<String>,
    pub sanitized: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precomputed_flows() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type, danger_level) VALUES ('sink1', 'strcpy', 'memory', 'critical')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv -> process -> strcpy', 0)",
            &[],
        )
        .unwrap();

        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source, "recv");
        assert_eq!(paths[0].sink, "strcpy");
        assert_eq!(paths[0].hops.len(), 3);
    }

    #[test]
    fn test_call_graph_discovery() {
        let db = GraphDb::in_memory().unwrap();

        // Set up a call chain: recv -> process -> strcpy
        db.execute("INSERT INTO functions (id, name) VALUES ('f1', 'recv')", &[]).unwrap();
        db.execute("INSERT INTO functions (id, name) VALUES ('f2', 'process')", &[]).unwrap();
        db.execute("INSERT INTO functions (id, name) VALUES ('f3', 'strcpy')", &[]).unwrap();
        db.execute("INSERT INTO calls (caller_id, callee_id) VALUES ('f1', 'f2')", &[]).unwrap();
        db.execute("INSERT INTO calls (caller_id, callee_id) VALUES ('f2', 'f3')", &[]).unwrap();

        // Register source and sink
        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type) VALUES ('sink1', 'strcpy', 'memory')",
            &[],
        )
        .unwrap();

        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert!(!paths.is_empty());
        let path = &paths[0];
        assert_eq!(path.source, "recv");
        assert_eq!(path.sink, "strcpy");
    }

    #[test]
    fn test_no_paths_when_empty() {
        let db = GraphDb::in_memory().unwrap();
        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_sanitized_flows_excluded() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO data_sinks (id, name, sink_type) VALUES ('sink1', 'strcpy', 'memory')",
            &[],
        )
        .unwrap();
        // This flow IS sanitized — should be excluded
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv -> validate -> strcpy', 1)",
            &[],
        )
        .unwrap();

        let analyzer = TaintAnalyzer::new(&db, 10);
        let paths = analyzer.find_unsanitized_paths().unwrap();
        assert!(paths.is_empty());
    }
}
