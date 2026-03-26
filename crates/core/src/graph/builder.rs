//! Graph construction helpers for populating the SQLite database with
//! analysis artifacts such as functions, call edges, and extracted strings.
//!
//! The actual build methods are split across submodules:
//! - `builder_binary`: populates from parsed binary info (goblin)
//! - `builder_ghidra`: enriches with Ghidra decompilation
//! - `builder_source`: populates from parsed source files

use super::db::GraphDb;
use super::ladybug_db::LadybugGraphDb;
use serde::Serialize;

/// Counts of nodes inserted by `build_from_binary_info`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InsertCounts {
    pub functions: usize,
    pub imports: usize,
    pub strings: usize,
    pub sources: usize,
    pub sinks: usize,
}

/// Counts of nodes updated/inserted by Ghidra analysis enrichment.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GhidraInsertCounts {
    pub functions_updated: usize,
    pub functions_added: usize,
    pub calls_added: usize,
}

/// Counts of nodes inserted by `build_from_source`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceInsertCounts {
    pub files: usize,
    pub functions: usize,
    pub calls: usize,
    pub strings: usize,
    pub imports: usize,
    pub sources: usize,
    pub sinks: usize,
    pub data_flows: usize,
}

/// Fluent builder for inserting analysis data into the graph.
pub struct GraphBuilder<'a> {
    db: &'a GraphDb,
    /// Optional LadybugDB backend for dual-write during migration.
    ladybug: Option<&'a LadybugGraphDb>,
}

impl<'a> GraphBuilder<'a> {
    /// Create a new builder backed by SQLite only.
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db, ladybug: None }
    }

    /// Create a builder that writes to both SQLite and LadybugDB.
    pub fn with_ladybug(db: &'a GraphDb, ladybug: &'a LadybugGraphDb) -> Self {
        Self {
            db,
            ladybug: Some(ladybug),
        }
    }

    /// Access the underlying SQLite database handle.
    pub(crate) fn db(&self) -> &GraphDb {
        self.db
    }

    /// Access the LadybugDB handle (if configured).
    #[allow(dead_code)]
    pub(crate) fn ladybug(&self) -> Option<&LadybugGraphDb> {
        self.ladybug
    }

    /// Insert a function node into the graph.
    pub fn insert_function(
        &self,
        id: &str,
        name: &str,
        address: &str,
        _file: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO functions (id, name, address, decompiled, confidence) \
             VALUES (?1, ?2, ?3, '', 0.0)",
            &[&id, &name, &address],
        )?;
        if let Some(lg) = &self.ladybug {
            let cypher = format!(
                "CREATE (f:Function {{id: '{}', name: '{}', address: '{}'}})",
                id.replace('\'', "\\'"),
                name.replace('\'', "\\'"),
                address.replace('\'', "\\'"),
            );
            if let Err(e) = lg.execute(&cypher) {
                // Log but don't fail — LadybugDB is secondary during migration
                tracing::debug!("LadybugDB insert_function failed (non-fatal): {e}");
            }
        }
        Ok(())
    }

    /// Insert a CALLS relationship between two functions.
    pub fn insert_call(&self, caller_id: &str, callee_id: &str) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&caller_id, &callee_id],
        )?;
        if let Some(lg) = &self.ladybug {
            let cypher = format!(
                "MATCH (a:Function {{id: '{}'}}), (b:Function {{id: '{}'}}) CREATE (a)-[:CALLS]->(b)",
                caller_id.replace('\'', "\\'"),
                callee_id.replace('\'', "\\'"),
            );
            if let Err(e) = lg.execute(&cypher) {
                tracing::debug!("LadybugDB insert_call failed (non-fatal): {e}");
            }
        }
        Ok(())
    }

    /// Insert a DataSource node representing an extracted string or input.
    pub fn insert_string_source(&self, id: &str, name: &str, kind: &str) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO data_sources (id, name, source_type) VALUES (?1, ?2, ?3)",
            &[&id, &name, &kind],
        )?;
        if let Some(lg) = &self.ladybug {
            let cypher = format!(
                "CREATE (s:DataSource {{id: '{}', name: '{}', source_type: '{}'}})",
                id.replace('\'', "\\'"),
                name.replace('\'', "\\'"),
                kind.replace('\'', "\\'"),
            );
            if let Err(e) = lg.execute(&cypher) {
                tracing::debug!("LadybugDB insert_string_source failed (non-fatal): {e}");
            }
        }
        Ok(())
    }

    /// Insert a DataSink node.
    pub fn insert_data_sink(&self, id: &str, name: &str, kind: &str) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO data_sinks (id, name, sink_type) VALUES (?1, ?2, ?3)",
            &[&id, &name, &kind],
        )?;
        if let Some(lg) = &self.ladybug {
            let cypher = format!(
                "CREATE (k:DataSink {{id: '{}', name: '{}', sink_type: '{}'}})",
                id.replace('\'', "\\'"),
                name.replace('\'', "\\'"),
                kind.replace('\'', "\\'"),
            );
            if let Err(e) = lg.execute(&cypher) {
                tracing::debug!("LadybugDB insert_data_sink failed (non-fatal): {e}");
            }
        }
        Ok(())
    }

    /// Insert a taint flow relationship between a source and sink.
    pub fn insert_taint_flow(
        &self,
        source_id: &str,
        sink_id: &str,
        path: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO taint_flows (source_id, sink_id, path, sanitized) \
             VALUES (?1, ?2, ?3, 0)",
            &[&source_id, &sink_id, &path],
        )?;
        if let Some(lg) = &self.ladybug {
            let cypher = format!(
                "MATCH (s:DataSource {{id: '{}'}}), (k:DataSink {{id: '{}'}}) \
                 CREATE (s)-[:TAINT_FLOW {{path: '{}', sanitized: 0}}]->(k)",
                source_id.replace('\'', "\\'"),
                sink_id.replace('\'', "\\'"),
                path.replace('\'', "\\'"),
            );
            if let Err(e) = lg.execute(&cypher) {
                tracing::debug!("LadybugDB insert_taint_flow failed (non-fatal): {e}");
            }
        }
        Ok(())
    }
}
