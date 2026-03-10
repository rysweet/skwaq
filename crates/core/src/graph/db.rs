//! Graph database for storing analysis artifacts.
//!
//! Uses SQLite with a graph-like schema as the default backend.
//! Designed to be swappable to LadybugDB/Kuzu when native linking
//! issues are resolved (kuzu and lbug crates have CXX-bridge linking
//! problems in downstream consumers as of March 2026).
//!
//! The schema uses Cypher-inspired naming so migration to LadybugDB
//! will be straightforward: node tables become NODE TABLEs, relationships
//! become REL TABLEs, and queries become Cypher.

use std::path::Path;

/// Wrapper around the graph database.
///
/// Currently backed by SQLite tables that model a property graph.
/// Will migrate to LadybugDB (lbug crate) when CXX-bridge linking
/// issues are resolved.
pub struct GraphDb {
    conn: rusqlite::Connection,
}

impl GraphDb {
    /// Open (or create) a database at `path` and ensure the schema exists.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path)?;
        let db_file = path.join("skwaq.db");
        let conn = rusqlite::Connection::open(&db_file)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let gdb = Self { conn };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Open an in-memory database (for tests).
    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let gdb = Self { conn };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Execute a write statement.
    pub fn execute(&self, sql: &str, params: &[&dyn rusqlite::types::ToSql]) -> anyhow::Result<usize> {
        Ok(self.conn.execute(sql, params)?)
    }

    /// Execute a write statement with no params. Convenience for schema DDL.
    pub fn mutate(&self, sql: &str) -> anyhow::Result<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Get a reference to the underlying connection for complex queries.
    pub fn conn(&self) -> &rusqlite::Connection {
        &self.conn
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "
            -- Node tables
            CREATE TABLE IF NOT EXISTS functions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT DEFAULT '',
                decompiled TEXT DEFAULT '',
                confidence REAL DEFAULT 0.0,
                language TEXT DEFAULT 'unknown',
                is_reconstructed INTEGER DEFAULT 0,
                investigation_id TEXT DEFAULT '',
                parameter_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS basic_blocks (
                id TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                function_id TEXT DEFAULT '',
                FOREIGN KEY (function_id) REFERENCES functions(id)
            );

            CREATE TABLE IF NOT EXISTS data_sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_type TEXT DEFAULT '',
                location TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS data_sinks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                sink_type TEXT DEFAULT '',
                danger_level TEXT DEFAULT 'medium',
                location TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT DEFAULT 'medium',
                cvss REAL DEFAULT 0.0,
                cwe_id TEXT DEFAULT '',
                function_id TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                confidence REAL DEFAULT 0.0,
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                evidence TEXT DEFAULT '',
                agent TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS cwes (
                id TEXT PRIMARY KEY,
                cwe_id TEXT DEFAULT '',
                name TEXT NOT NULL,
                description TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS annotations (
                id TEXT PRIMARY KEY,
                target_address TEXT DEFAULT '',
                text TEXT DEFAULT '',
                author TEXT DEFAULT 'user',
                timestamp TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                description TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                evidence TEXT DEFAULT '',
                confidence REAL DEFAULT 0.0,
                timestamp TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS agent_actions (
                id TEXT PRIMARY KEY,
                agent TEXT DEFAULT '',
                action TEXT DEFAULT '',
                reasoning TEXT DEFAULT '',
                timestamp TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS symbols (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT DEFAULT '',
                symbol_type TEXT DEFAULT '',
                binding TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS string_literals (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                offset TEXT DEFAULT '',
                investigation_id TEXT DEFAULT ''
            );

            -- Relationship tables (edge lists)
            CREATE TABLE IF NOT EXISTS calls (
                caller_id TEXT NOT NULL,
                callee_id TEXT NOT NULL,
                PRIMARY KEY (caller_id, callee_id),
                FOREIGN KEY (caller_id) REFERENCES functions(id),
                FOREIGN KEY (callee_id) REFERENCES functions(id)
            );

            CREATE TABLE IF NOT EXISTS contains_block (
                function_id TEXT NOT NULL,
                block_id TEXT NOT NULL,
                PRIMARY KEY (function_id, block_id)
            );

            CREATE TABLE IF NOT EXISTS flows_to (
                from_block TEXT NOT NULL,
                to_block TEXT NOT NULL,
                PRIMARY KEY (from_block, to_block)
            );

            CREATE TABLE IF NOT EXISTS taint_flows (
                source_id TEXT NOT NULL,
                sink_id TEXT NOT NULL,
                path TEXT DEFAULT '',
                sanitized INTEGER DEFAULT 0,
                PRIMARY KEY (source_id, sink_id)
            );

            CREATE TABLE IF NOT EXISTS func_references_string (
                function_id TEXT NOT NULL,
                string_id TEXT NOT NULL,
                PRIMARY KEY (function_id, string_id)
            );

            -- Indexes for common queries
            CREATE INDEX IF NOT EXISTS idx_functions_investigation ON functions(investigation_id);
            CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
            CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);
            CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_id);
            CREATE INDEX IF NOT EXISTS idx_taint_source ON taint_flows(source_id);
            CREATE INDEX IF NOT EXISTS idx_taint_sink ON taint_flows(sink_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_investigation ON vulnerabilities(investigation_id);
            "
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let db = GraphDb::in_memory().unwrap();
        // Schema should exist
        let count: i64 = db.conn()
            .query_row("SELECT count(*) FROM functions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_open_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db = GraphDb::open(dir.path()).unwrap();
        drop(db);
        // Reopen should work
        let _db2 = GraphDb::open(dir.path()).unwrap();
    }

    #[test]
    fn test_insert_and_query_function() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO functions (id, name, address, decompiled, confidence, investigation_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[&"func1", &"main", &"0x401000", &"int main() { return 0; }", &0.95_f64 as &dyn rusqlite::types::ToSql, &"inv1"],
        ).unwrap();

        let name: String = db.conn()
            .query_row("SELECT name FROM functions WHERE id = 'func1'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(name, "main");
    }

    #[test]
    fn test_call_relationship() {
        let db = GraphDb::in_memory().unwrap();

        db.execute("INSERT INTO functions (id, name) VALUES ('f1', 'caller')", &[]).unwrap();
        db.execute("INSERT INTO functions (id, name) VALUES ('f2', 'callee')", &[]).unwrap();
        db.execute("INSERT INTO calls (caller_id, callee_id) VALUES ('f1', 'f2')", &[]).unwrap();

        let callee: String = db.conn()
            .query_row(
                "SELECT f2.name FROM calls c \
                 JOIN functions f1 ON c.caller_id = f1.id \
                 JOIN functions f2 ON c.callee_id = f2.id \
                 WHERE f1.name = 'caller'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(callee, "callee");
    }

    #[test]
    fn test_investigation_lifecycle() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at) \
             VALUES ('inv1', 'Test', '/usr/bin/test', 'active', '2026-03-10')",
            &[],
        ).unwrap();

        let status: String = db.conn()
            .query_row("SELECT status FROM investigations WHERE id = 'inv1'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(status, "active");
    }

    #[test]
    fn test_taint_flow() {
        let db = GraphDb::in_memory().unwrap();

        db.execute("INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')", &[]).unwrap();
        db.execute("INSERT INTO data_sinks (id, name, sink_type, danger_level) VALUES ('sink1', 'strcpy', 'memory', 'critical')", &[]).unwrap();
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv->process->strcpy', 0)",
            &[],
        ).unwrap();

        let path: String = db.conn()
            .query_row(
                "SELECT tf.path FROM taint_flows tf \
                 JOIN data_sources s ON tf.source_id = s.id \
                 JOIN data_sinks k ON tf.sink_id = k.id \
                 WHERE tf.sanitized = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(path, "recv->process->strcpy");
    }
}
