//! Common query helpers for reading analysis data from the graph.

use super::db::GraphDb;

/// Return all function names and addresses for an investigation.
pub fn get_functions(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, name, address FROM functions WHERE investigation_id = ?1 ORDER BY name",
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
    Ok(results)
}

/// Return the call graph as (caller_name, callee_name) pairs.
pub fn get_call_graph(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.investigation_id = ?1 AND f2.investigation_id = ?1",
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
    Ok(results)
}

/// Return unsanitized taint flow paths for a given investigation.
pub fn get_taint_paths(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT s.name, k.name, tf.path FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id \
         WHERE tf.sanitized = 0 AND s.investigation_id = ?1",
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
    Ok(results)
}

/// Return all vulnerabilities with severity.
pub fn get_vulnerabilities(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<Vec<(String, String, String, f64)>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, title, severity, confidence FROM vulnerabilities \
         WHERE investigation_id = ?1 ORDER BY confidence DESC",
    )?;
    let rows = stmt.query_map([investigation_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, f64>(3)?,
        ))
    })?;
    let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
    Ok(results)
}

/// Get all investigations.
pub fn get_investigations(db: &GraphDb) -> anyhow::Result<Vec<(String, String, String, String)>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, name, status, created_at FROM investigations ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
    Ok(results)
}

/// Return functions that call known dangerous APIs.
pub fn get_dangerous_calls(
    db: &GraphDb,
    dangerous_names: &[&str],
    investigation_id: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    if dangerous_names.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders: String = (0..dangerous_names.len())
        .map(|i| format!("?{}", i + 2)) // ?1 is investigation_id
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT f1.name, f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name IN ({placeholders}) AND f1.investigation_id = ?1"
    );
    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    all_params.push(Box::new(investigation_id.to_string()));
    for name in dangerous_names {
        all_params.push(Box::new(name.to_string()));
    }
    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();
    let mut stmt = db.conn().prepare(&sql)?;
    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let results = rows.collect::<Result<Vec<_>, rusqlite::Error>>()?;
    Ok(results)
}
