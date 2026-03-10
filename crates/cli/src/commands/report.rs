//! `skwaq report` - generate analysis reports.
//!
//! Queries all findings for an investigation and outputs them in the
//! requested format: JSON (default), SARIF, or Markdown.

use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;
use skwaq_core::reporting::{
    generate_markdown_for_investigation, generate_report_for_investigation,
    generate_sarif_for_investigation,
};
use std::path::PathBuf;

/// Run the report command.
///
/// If `investigation_id` is `None`, uses the most recent investigation.
pub fn run(
    investigation_id: Option<&str>,
    json: bool,
    sarif: bool,
    markdown: bool,
    output: Option<&PathBuf>,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let db = GraphDb::open(&db_path)?;

    // Resolve investigation ID
    let inv_id = match investigation_id {
        Some(id) => id.to_string(),
        None => {
            let id: String = db
                .conn()
                .query_row(
                    "SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    anyhow::anyhow!(
                        "No investigations found. Run `skwaq analyze --quick` first."
                    )
                })?;
            id
        }
    };

    let report = if sarif {
        generate_sarif_for_investigation(&db, &inv_id)?
    } else if markdown || (!json && !sarif) {
        // Default to Markdown if no format specified
        generate_markdown_for_investigation(&db, &inv_id)?
    } else {
        generate_report_for_investigation(&db, &inv_id)?
    };

    match output {
        Some(path) => {
            std::fs::write(path, &report)?;
            let format_name = if sarif {
                "SARIF"
            } else if json {
                "JSON"
            } else {
                "Markdown"
            };
            println!("{format_name} report written to {}", path.display());
        }
        None => {
            println!("{report}");
        }
    }

    Ok(())
}
