//! LadybugDB graph database backend for the code property graph.
//!
//! Provides native Cypher queries for graph traversals, replacing the
//! SQLite recursive CTEs and Cypher→SQL translator. LadybugDB (formerly
//! Kuzu) is an embeddable property graph database optimized for complex
//! analytical workloads on large graphs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// LadybugDB-backed graph database.
#[derive(Clone)]
pub struct LadybugGraphDb {
    db: Arc<lbug::Database>,
    #[allow(dead_code)] // Used in Phase 2 for db path discovery
    path: PathBuf,
}

impl LadybugGraphDb {
    /// Open or create a LadybugDB database at the given path.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path)?;
        let db_path = path.join("skwaq_graph");
        let db = Arc::new(
            lbug::Database::new(&db_path, lbug::SystemConfig::default())
                .map_err(|e| anyhow::anyhow!("Failed to open LadybugDB: {e}"))?,
        );
        let gdb = Self { db, path: db_path };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Create a temporary LadybugDB database (for tests).
    pub fn in_memory() -> anyhow::Result<Self> {
        let tmp = tempfile::tempdir()?;
        let db_path = tmp.path().join("ladybug_test");
        let db = Arc::new(
            lbug::Database::new(&db_path, lbug::SystemConfig::default())
                .map_err(|e| anyhow::anyhow!("Failed to open LadybugDB: {e}"))?,
        );
        let gdb = Self { db, path: db_path };
        gdb.ensure_schema()?;
        std::mem::forget(tmp);
        Ok(gdb)
    }

    fn conn(&self) -> anyhow::Result<lbug::Connection<'_>> {
        lbug::Connection::new(&self.db)
            .map_err(|e| anyhow::anyhow!("Failed to create connection: {e}"))
    }

    /// Execute a Cypher query and return all rows.
    pub fn query(&self, cypher: &str) -> anyhow::Result<Vec<Vec<lbug::Value>>> {
        let conn = self.conn()?;
        let result = conn
            .query(cypher)
            .map_err(|e| anyhow::anyhow!("Query failed: {e}\nCypher: {cypher}"))?;
        Ok(result.collect())
    }

    /// Execute a Cypher statement (no results needed).
    pub fn execute(&self, cypher: &str) -> anyhow::Result<()> {
        self.conn()?
            .query(cypher)
            .map_err(|e| anyhow::anyhow!("Execute failed: {e}\nCypher: {cypher}"))?;
        Ok(())
    }

    /// Extract a string from a Value.
    pub fn as_str(val: &lbug::Value) -> Option<&str> {
        match val {
            lbug::Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extract an i64 from a Value.
    pub fn as_i64(val: &lbug::Value) -> Option<i64> {
        match val {
            lbug::Value::Int64(n) => Some(*n),
            _ => None,
        }
    }

    /// Extract a float from a LadybugDB Value.
    pub fn as_f64(val: &lbug::Value) -> Option<f64> {
        match val {
            lbug::Value::Double(d) => Some(*d),
            lbug::Value::Int64(n) => Some(*n as f64),
            _ => None,
        }
    }

    /// Create the graph schema.
    fn ensure_schema(&self) -> anyhow::Result<()> {
        let stmts = [
            // Node tables
            "CREATE NODE TABLE IF NOT EXISTS Function(id STRING PRIMARY KEY, name STRING, address STRING DEFAULT '', decompiled STRING DEFAULT '', confidence DOUBLE DEFAULT 0.0, language STRING DEFAULT '', is_reconstructed INT64 DEFAULT 0, investigation_id STRING DEFAULT '', parameter_count INT64 DEFAULT 0)",
            "CREATE NODE TABLE IF NOT EXISTS DataSource(id STRING PRIMARY KEY, name STRING, source_type STRING DEFAULT '', location STRING DEFAULT '', investigation_id STRING DEFAULT '')",
            "CREATE NODE TABLE IF NOT EXISTS DataSink(id STRING PRIMARY KEY, name STRING, sink_type STRING DEFAULT '', danger_level STRING DEFAULT 'medium', location STRING DEFAULT '', investigation_id STRING DEFAULT '')",
            "CREATE NODE TABLE IF NOT EXISTS Symbol(id STRING PRIMARY KEY, name STRING, address STRING DEFAULT '', symbol_type STRING DEFAULT '', binding STRING DEFAULT '', investigation_id STRING DEFAULT '')",
            "CREATE NODE TABLE IF NOT EXISTS Finding(id STRING PRIMARY KEY, title STRING DEFAULT '', evidence STRING DEFAULT '', agent STRING DEFAULT '', timestamp STRING DEFAULT '', investigation_id STRING DEFAULT '', status STRING DEFAULT 'new', cycle_discovered INT64 DEFAULT 0, cycle_last_updated INT64 DEFAULT 0, severity STRING DEFAULT '', category STRING DEFAULT '')",
            "CREATE NODE TABLE IF NOT EXISTS StringLiteral(id STRING PRIMARY KEY, value STRING DEFAULT '', offset STRING DEFAULT '', investigation_id STRING DEFAULT '')",
            "CREATE NODE TABLE IF NOT EXISTS Investigation(id STRING PRIMARY KEY, name STRING DEFAULT '', target STRING DEFAULT '', status STRING DEFAULT '', created_at STRING DEFAULT '', updated_at STRING DEFAULT '')",
            // Relationship tables
            "CREATE REL TABLE IF NOT EXISTS CALLS(FROM Function TO Function)",
            "CREATE REL TABLE IF NOT EXISTS TAINT_FLOW(FROM DataSource TO DataSink, path STRING DEFAULT '', sanitized INT64 DEFAULT 0)",
            "CREATE REL TABLE IF NOT EXISTS FLOWS_TO(FROM Function TO Function, flow_type STRING DEFAULT '')",
            "CREATE REL TABLE IF NOT EXISTS HAS_SOURCE(FROM Function TO DataSource)",
            "CREATE REL TABLE IF NOT EXISTS HAS_SINK(FROM Function TO DataSink)",
            "CREATE REL TABLE IF NOT EXISTS REFERENCES_STRING(FROM Function TO StringLiteral)",
        ];

        for ddl in &stmts {
            if let Err(e) = self.execute(ddl) {
                if !e.to_string().contains("already exists") {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_and_schema() {
        let db = LadybugGraphDb::in_memory().unwrap();
        let rows = db.query("MATCH (n:Function) RETURN count(n)").unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn test_insert_and_query() {
        let db = LadybugGraphDb::in_memory().unwrap();
        db.execute("CREATE (f:Function {id: 'fn1', name: 'main', address: '0x1000'})")
            .unwrap();
        let rows = db
            .query("MATCH (f:Function {id: 'fn1'}) RETURN f.name")
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(LadybugGraphDb::as_str(&rows[0][0]), Some("main"));
    }

    #[test]
    fn test_call_graph_traversal() {
        let db = LadybugGraphDb::in_memory().unwrap();
        db.execute("CREATE (f:Function {id: 'main', name: 'main'})")
            .unwrap();
        db.execute("CREATE (f:Function {id: 'helper', name: 'helper'})")
            .unwrap();
        db.execute("CREATE (f:Function {id: 'sink', name: 'dangerous_sink'})")
            .unwrap();
        db.execute(
            "MATCH (a:Function {id: 'main'}), (b:Function {id: 'helper'}) CREATE (a)-[:CALLS]->(b)",
        )
        .unwrap();
        db.execute(
            "MATCH (a:Function {id: 'helper'}), (b:Function {id: 'sink'}) CREATE (a)-[:CALLS]->(b)",
        )
        .unwrap();

        // Native Cypher variable-length path — replaces recursive CTEs
        let rows = db
            .query("MATCH (s:Function {id: 'main'})-[:CALLS*1..5]->(t:Function) RETURN t.name")
            .unwrap();
        let names: Vec<&str> = rows
            .iter()
            .filter_map(|r| LadybugGraphDb::as_str(&r[0]))
            .collect();
        assert!(names.contains(&"helper"));
        assert!(names.contains(&"dangerous_sink"));
    }

    #[test]
    fn test_taint_flow() {
        let db = LadybugGraphDb::in_memory().unwrap();
        db.execute("CREATE (s:DataSource {id: 'src1', name: 'recv', source_type: 'network'})")
            .unwrap();
        db.execute("CREATE (k:DataSink {id: 'sink1', name: 'strcpy', danger_level: 'critical'})")
            .unwrap();
        db.execute("MATCH (s:DataSource {id: 'src1'}), (k:DataSink {id: 'sink1'}) CREATE (s)-[:TAINT_FLOW {path: 'recv -> strcpy', sanitized: 0}]->(k)").unwrap();

        let rows = db.query("MATCH (s:DataSource)-[t:TAINT_FLOW]->(k:DataSink) WHERE t.sanitized = 0 RETURN s.name, k.name, t.path").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(LadybugGraphDb::as_str(&rows[0][0]), Some("recv"));
        assert_eq!(LadybugGraphDb::as_str(&rows[0][1]), Some("strcpy"));
    }
}
