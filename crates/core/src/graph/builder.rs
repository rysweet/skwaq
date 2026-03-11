//! Graph construction helpers for populating the SQLite database with
//! analysis artifacts such as functions, call edges, and extracted strings.
//!
//! The actual build methods are split across submodules:
//! - `builder_binary`: populates from parsed binary info (goblin)
//! - `builder_ghidra`: enriches with Ghidra decompilation
//! - `builder_source`: populates from parsed source files

use super::db::GraphDb;
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
}

/// Fluent builder for inserting analysis data into the graph.
pub struct GraphBuilder<'a> {
    db: &'a GraphDb,
}

impl<'a> GraphBuilder<'a> {
    /// Create a new builder backed by `db`.
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Access the underlying database handle.
    pub(crate) fn db(&self) -> &GraphDb {
        self.db
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
        Ok(())
    }

    /// Insert a CALLS relationship between two functions.
    pub fn insert_call(&self, caller_id: &str, callee_id: &str) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO calls (caller_id, callee_id) VALUES (?1, ?2)",
            &[&caller_id, &callee_id],
        )?;
        Ok(())
    }

    /// Insert a DataSource node representing an extracted string or input.
    pub fn insert_string_source(
        &self,
        id: &str,
        name: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO data_sources (id, name, source_type) VALUES (?1, ?2, ?3)",
            &[&id, &name, &kind],
        )?;
        Ok(())
    }

    /// Insert a DataSink node.
    pub fn insert_data_sink(
        &self,
        id: &str,
        name: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO data_sinks (id, name, sink_type) VALUES (?1, ?2, ?3)",
            &[&id, &name, &kind],
        )?;
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
        Ok(())
    }
}
