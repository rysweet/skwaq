//! Common query helpers for reading analysis data from the graph.

use super::db::GraphDb;

/// Return all function names and addresses for an investigation.
pub fn get_functions(db: &GraphDb, investigation_id: &str) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, name, address FROM functions WHERE investigation_id = ?1 ORDER BY name"
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Return the call graph as (caller_name, callee_name) pairs.
pub fn get_call_graph(db: &GraphDb, investigation_id: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.investigation_id = ?1"
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Return unsanitized taint flow paths.
pub fn get_taint_paths(db: &GraphDb) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Return all vulnerabilities with severity.
pub fn get_vulnerabilities(db: &GraphDb, investigation_id: &str) -> anyhow::Result<Vec<(String, String, String, f64)>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, title, severity, confidence FROM vulnerabilities \
         WHERE investigation_id = ?1 ORDER BY confidence DESC"
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, f64>(3)?,
        ))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Get all investigations.
pub fn get_investigations(db: &GraphDb) -> anyhow::Result<Vec<(String, String, String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, name, status, created_at FROM investigations ORDER BY created_at DESC"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Return functions that call known dangerous APIs.
pub fn get_dangerous_calls(
    db: &GraphDb,
    dangerous_names: &[&str],
    investigation_id: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    let placeholders: String = dangerous_names.iter()
        .map(|n| format!("'{}'", n))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name IN ({}) AND f1.investigation_id = ?1",
        placeholders
    );
    let mut stmt = db.conn().prepare(&sql)?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}
