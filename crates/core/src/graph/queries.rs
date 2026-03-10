//! Common Cypher query helpers for reading analysis data from the graph.

use super::db::GraphDb;

/// Return all function nodes.
pub fn get_functions(db: &GraphDb) -> anyhow::Result<kuzu::QueryResult<'_>> {
    db.query("MATCH (f:Function) RETURN f.id, f.name, f.file")
}

/// Return the call graph as (caller, callee) pairs.
pub fn get_call_graph(db: &GraphDb) -> anyhow::Result<kuzu::QueryResult<'_>> {
    db.query(
        "MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.name, b.name",
    )
}

/// Return taint flow paths from sources to sinks.
pub fn get_taint_paths(db: &GraphDb) -> anyhow::Result<kuzu::QueryResult<'_>> {
    db.query(
        "MATCH (src:DataSource)-[t:TAINT_FLOW]->(snk:DataSink) \
         RETURN src.name, snk.name, t.path",
    )
}

/// Return all vulnerabilities with their matched CWE.
pub fn get_vulnerabilities(db: &GraphDb) -> anyhow::Result<kuzu::QueryResult<'_>> {
    db.query(
        "MATCH (v:Vulnerability)-[:MATCHES]->(c:CWE) \
         RETURN v.id, v.title, v.severity, c.cwe_id, c.name",
    )
}

/// Get all investigations ordered by creation time.
pub fn get_investigations(db: &GraphDb) -> anyhow::Result<kuzu::QueryResult<'_>> {
    db.query(
        "MATCH (i:Investigation) RETURN i.id, i.name, i.status, i.created_at \
         ORDER BY i.created_at DESC",
    )
}

/// Return functions that call a known dangerous API.
pub fn get_dangerous_calls<'a>(
    db: &'a GraphDb,
    dangerous_names: &[&str],
) -> anyhow::Result<kuzu::QueryResult<'a>> {
    let name_list: String = dangerous_names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let cypher = format!(
        "MATCH (caller:Function)-[:CALLS]->(callee:Function) \
         WHERE callee.name IN [{name_list}] \
         RETURN caller.name, callee.name, caller.file"
    );
    db.query(&cypher)
}
