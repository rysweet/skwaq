//! Shared helpers used by multiple command modules.

use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;

/// Open the graph database using the configured database path.
pub fn open_db() -> anyhow::Result<GraphDb> {
    let db_dir = Config::load()?.database_path();
    if !db_dir.join("skwaq.db").exists() {
        anyhow::bail!("No database found. Run `skwaq ingest binary <path>` first.");
    }
    GraphDb::open(&db_dir)
}

/// Return the ID of the most recent investigation in the database.
pub fn most_recent_investigation(db: &GraphDb) -> anyhow::Result<String> {
    let id: String = db
        .conn()
        .query_row(
            "SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Query returned no rows") {
                anyhow::anyhow!("No investigations found. Run `skwaq ingest binary <path>` first.")
            } else {
                anyhow::anyhow!("Failed to query investigations: {e}")
            }
        })?;
    Ok(id)
}
