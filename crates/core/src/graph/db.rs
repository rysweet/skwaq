//! Graph database for storing analysis artifacts.
//!
//! Primary backend is LadybugDB (native Cypher graph database).
//! SQLite is retained for backward compatibility during migration.
//! New graph queries should use `cypher()`, not raw SQL.

use std::path::Path;

use super::ladybug_db::LadybugGraphDb;

/// Wrapper around the graph database.
///
/// Backed by LadybugDB for native Cypher graph queries and SQLite for
/// legacy schema compatibility. LadybugDB is optional — gym eval uses
/// SQLite-only mode to avoid mmap overhead on per-case databases.
pub struct GraphDb {
    conn: rusqlite::Connection,
    /// LadybugDB backend for native Cypher queries (None in SQLite-only mode).
    ladybug: Option<LadybugGraphDb>,
}

impl GraphDb {
    /// Open (or create) a database at `path` and ensure the schema exists.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path)?;
        let db_file = path.join("skwaq.db");
        let conn = rusqlite::Connection::open(&db_file)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let ladybug = LadybugGraphDb::open(path)?;
        let gdb = Self {
            conn,
            ladybug: Some(ladybug),
        };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Open an in-memory database (for tests).
    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let ladybug = LadybugGraphDb::in_memory()?;
        let gdb = Self {
            conn,
            ladybug: Some(ladybug),
        };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Open an in-memory SQLite-only database (no LadybugDB).
    ///
    /// Used by gym eval where per-case LadybugDB is dead weight —
    /// GraphBuilder writes only to SQLite, and agent queries fall through
    /// to the SQL-based path in tool_executor. Eliminates mmap overhead.
    pub fn in_memory_sqlite_only() -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let gdb = Self {
            conn,
            ladybug: None,
        };
        gdb.ensure_schema()?;
        Ok(gdb)
    }

    /// Execute a write statement.
    pub fn execute(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::types::ToSql],
    ) -> anyhow::Result<usize> {
        Ok(self.conn.execute(sql, params)?)
    }

    /// Execute a write statement with no params. Convenience for schema DDL.
    pub fn mutate(&self, sql: &str) -> anyhow::Result<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Get a reference to the underlying SQLite connection for complex queries.
    /// Prefer `cypher()` or `cypher_query()` for graph traversals.
    pub fn conn(&self) -> &rusqlite::Connection {
        &self.conn
    }

    /// Execute a Cypher query via LadybugDB.
    /// Returns empty results when in SQLite-only mode.
    #[allow(dead_code)]
    pub fn cypher_query(&self, cypher: &str) -> anyhow::Result<Vec<Vec<lbug::Value>>> {
        match &self.ladybug {
            Some(lg) => lg.query(cypher),
            None => Ok(Vec::new()),
        }
    }

    /// Execute a Cypher statement (no results expected).
    /// No-op when in SQLite-only mode.
    #[allow(dead_code)]
    pub fn cypher_execute(&self, cypher: &str) -> anyhow::Result<()> {
        match &self.ladybug {
            Some(lg) => lg.execute(cypher),
            None => {
                let _ = cypher;
                Ok(())
            }
        }
    }

    /// Whether LadybugDB is available.
    #[allow(dead_code)]
    pub fn has_ladybug(&self) -> bool {
        self.ladybug.is_some()
    }

    /// Get the LadybugDB handle (if available).
    #[allow(dead_code)]
    pub fn ladybug(&self) -> Option<&LadybugGraphDb> {
        self.ladybug.as_ref()
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
                investigation_id TEXT DEFAULT '',
                status TEXT DEFAULT 'new',
                cycle_discovered INTEGER DEFAULT 1,
                cycle_last_updated INTEGER DEFAULT 1,
                severity TEXT DEFAULT '',
                category TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS cwes (
                id TEXT PRIMARY KEY,
                cwe_id TEXT DEFAULT '',
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                parent_cwe TEXT DEFAULT '',
                semantic_class TEXT DEFAULT '',
                danger_categories TEXT DEFAULT '',
                detection_signals TEXT DEFAULT '',
                skwaq_tools TEXT DEFAULT '',
                fn_insight TEXT DEFAULT ''
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
            ",
        )?;
        self.migrate_cwes_columns()?;
        Ok(())
    }

    /// Add CWE knowledge graph columns if they don't exist (migration for existing DBs).
    fn migrate_cwes_columns(&self) -> anyhow::Result<()> {
        // Check if the new columns exist by querying table info
        let has_column = |col: &str| -> bool {
            let sql =
                format!("SELECT COUNT(*) FROM pragma_table_info('cwes') WHERE name = '{col}'");
            self.conn
                .query_row(&sql, [], |row| row.get::<_, i64>(0))
                .unwrap_or(0)
                > 0
        };

        let new_columns = [
            ("parent_cwe", "TEXT DEFAULT ''"),
            ("semantic_class", "TEXT DEFAULT ''"),
            ("danger_categories", "TEXT DEFAULT ''"),
            ("detection_signals", "TEXT DEFAULT ''"),
            ("skwaq_tools", "TEXT DEFAULT ''"),
            ("fn_insight", "TEXT DEFAULT ''"),
        ];

        for (col, typedef) in &new_columns {
            if !has_column(col) {
                let sql = format!("ALTER TABLE cwes ADD COLUMN {col} {typedef}");
                self.conn.execute_batch(&sql)?;
            }
        }
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
        let count: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM functions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_open_in_memory_sqlite_only() {
        let db = GraphDb::in_memory_sqlite_only().unwrap();
        // Schema should exist (SQLite tables work)
        let count: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM functions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        // LadybugDB not available
        assert!(!db.has_ladybug());
        // cypher_query returns empty (not error)
        let rows = db.cypher_query("MATCH (n) RETURN n").unwrap();
        assert!(rows.is_empty());
        // cypher_execute is a no-op
        assert!(db.cypher_execute("CREATE (n:Test {id: '1'})").is_ok());
        // SQLite operations still work
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'test')",
            &[],
        )
        .unwrap();
        let name: String = db
            .conn()
            .query_row("SELECT name FROM functions WHERE id = 'f1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "test");
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
            &[
                &"func1",
                &"main",
                &"0x401000",
                &"int main() { return 0; }",
                &0.95_f64 as &dyn rusqlite::types::ToSql,
                &"inv1",
            ],
        )
        .unwrap();

        let name: String = db
            .conn()
            .query_row("SELECT name FROM functions WHERE id = 'func1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "main");
    }

    #[test]
    fn test_call_relationship() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'caller')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'callee')",
            &[],
        )
        .unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f1', 'f2')",
            &[],
        )
        .unwrap();

        let callee: String = db
            .conn()
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
        )
        .unwrap();

        let status: String = db
            .conn()
            .query_row(
                "SELECT status FROM investigations WHERE id = 'inv1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "active");
    }

    #[test]
    fn test_taint_flow() {
        let db = GraphDb::in_memory().unwrap();

        db.execute(
            "INSERT INTO data_sources (id, name, source_type) VALUES ('src1', 'recv', 'network')",
            &[],
        )
        .unwrap();
        db.execute("INSERT INTO data_sinks (id, name, sink_type, danger_level) VALUES ('sink1', 'strcpy', 'memory', 'critical')", &[]).unwrap();
        db.execute(
            "INSERT INTO taint_flows (source_id, sink_id, path, sanitized) VALUES ('src1', 'sink1', 'recv->process->strcpy', 0)",
            &[],
        ).unwrap();

        let path: String = db
            .conn()
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
