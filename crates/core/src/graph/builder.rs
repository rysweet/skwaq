//! Graph construction helpers for populating the Kùzu database with
//! analysis artifacts such as functions, call edges, and extracted strings.

use super::db::GraphDb;

/// Fluent builder for inserting analysis data into the graph.
pub struct GraphBuilder<'a> {
    db: &'a GraphDb,
}

impl<'a> GraphBuilder<'a> {
    /// Create a new builder backed by `db`.
    pub fn new(db: &'a GraphDb) -> Self {
        Self { db }
    }

    /// Insert a function node into the graph.
    pub fn insert_function(
        &self,
        id: &str,
        name: &str,
        address: &str,
        file: &str,
    ) -> anyhow::Result<()> {
        let cypher = format!(
            "CREATE (f:Function {{id: '{id}', name: '{name}', address: '{address}', \
             file: '{file}', start_line: 0, end_line: 0, decompiled: ''}})"
        );
        self.db.mutate(&cypher)
    }

    /// Insert a CALLS relationship between two functions.
    pub fn insert_call(&self, caller_id: &str, callee_id: &str) -> anyhow::Result<()> {
        let cypher = format!(
            "MATCH (a:Function {{id: '{caller_id}'}}), (b:Function {{id: '{callee_id}'}}) \
             CREATE (a)-[:CALLS]->(b)"
        );
        self.db.mutate(&cypher)
    }

    /// Insert a DataSource node representing an extracted string or input.
    pub fn insert_string_source(
        &self,
        id: &str,
        name: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        let cypher = format!(
            "CREATE (s:DataSource {{id: '{id}', name: '{name}', kind: '{kind}'}})"
        );
        self.db.mutate(&cypher)
    }

    /// Insert a DataSink node.
    pub fn insert_data_sink(
        &self,
        id: &str,
        name: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        let cypher = format!(
            "CREATE (s:DataSink {{id: '{id}', name: '{name}', kind: '{kind}'}})"
        );
        self.db.mutate(&cypher)
    }

    /// Insert a TAINT_FLOW relationship between a source and sink.
    pub fn insert_taint_flow(
        &self,
        source_id: &str,
        sink_id: &str,
        path: &str,
    ) -> anyhow::Result<()> {
        let cypher = format!(
            "MATCH (src:DataSource {{id: '{source_id}'}}), (snk:DataSink {{id: '{sink_id}'}}) \
             CREATE (src)-[:TAINT_FLOW {{path: '{path}'}}]->(snk)"
        );
        self.db.mutate(&cypher)
    }
}
