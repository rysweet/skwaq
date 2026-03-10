//! Kùzu-backed graph database for storing analysis artifacts.
//!
//! `GraphDb` owns a Kùzu `Database` handle and provides typed helpers
//! for running Cypher queries and mutations against the schema defined
//! in [`super::types`].

use kuzu::{Connection, Database, SystemConfig};
use std::path::Path;

/// Wrapper around a Kùzu embedded graph database.
pub struct GraphDb {
    db: Database,
}

impl GraphDb {
    /// Open (or create) a Kùzu database at `path` and ensure the schema
    /// tables exist.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = Database::new(path, SystemConfig::default())?;
        let gdb = Self { db };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Return a new connection to the underlying database.
    pub fn connection(&self) -> anyhow::Result<Connection<'_>> {
        let conn = Connection::new(&self.db)?;
        Ok(conn)
    }

    /// Execute a read-only Cypher query and return the raw result.
    pub fn query(&self, cypher: &str) -> anyhow::Result<kuzu::QueryResult<'_>> {
        let conn = self.connection()?;
        let result = conn.query(cypher)?;
        Ok(result)
    }

    /// Execute a mutating Cypher statement (CREATE, MERGE, DELETE, etc.).
    pub fn mutate(&self, cypher: &str) -> anyhow::Result<()> {
        let conn = self.connection()?;
        conn.query(cypher)?;
        Ok(())
    }

    // ----------------------------------------------------------------
    // Schema bootstrap
    // ----------------------------------------------------------------

    fn ensure_schema(&self) -> anyhow::Result<()> {
        let conn = self.connection()?;

        // Node tables
        let node_ddl = [
            "CREATE NODE TABLE IF NOT EXISTS Function(
                id STRING, name STRING, address STRING, file STRING,
                start_line INT64, end_line INT64, decompiled STRING,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS BasicBlock(
                id STRING, address STRING, size INT64,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS DataSource(
                id STRING, name STRING, kind STRING,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS DataSink(
                id STRING, name STRING, kind STRING,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS Vulnerability(
                id STRING, title STRING, severity STRING,
                description STRING, file STRING, line INT64,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS CWE(
                id STRING, cwe_id STRING, name STRING, description STRING,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS Investigation(
                id STRING, name STRING, status STRING,
                created_at STRING, updated_at STRING,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS Annotation(
                id STRING, content STRING, author STRING, created_at STRING,
                PRIMARY KEY(id)
            )",
            "CREATE NODE TABLE IF NOT EXISTS Hypothesis(
                id STRING, statement STRING, status STRING,
                confidence DOUBLE, created_at STRING,
                PRIMARY KEY(id)
            )",
        ];

        for ddl in &node_ddl {
            conn.query(ddl)?;
        }

        // Relationship tables
        let rel_ddl = [
            "CREATE REL TABLE IF NOT EXISTS CALLS(FROM Function TO Function)",
            "CREATE REL TABLE IF NOT EXISTS CONTAINS(FROM Function TO BasicBlock)",
            "CREATE REL TABLE IF NOT EXISTS FLOWS_TO(FROM BasicBlock TO BasicBlock)",
            "CREATE REL TABLE IF NOT EXISTS LOCATED_IN(FROM Vulnerability TO Function)",
            "CREATE REL TABLE IF NOT EXISTS MATCHES(FROM Vulnerability TO CWE)",
            "CREATE REL TABLE IF NOT EXISTS TAINT_FLOW(FROM DataSource TO DataSink, path STRING)",
        ];

        for ddl in &rel_ddl {
            conn.query(ddl)?;
        }

        Ok(())
    }
}
