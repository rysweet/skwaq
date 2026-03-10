//! `skwaq report` - generate analysis reports.
//!
//! Queries all findings for an investigation and outputs them in the
//! requested format (JSON by default, SARIF and Markdown planned).

use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;
use skwaq_core::reporting::generate_report_for_investigation;
use std::path::PathBuf;

/// Run the report command.
///
/// If `investigation_id` is `None`, uses the most recent investigation.
pub fn run(
    investigation_id: Option<&str>,
    json: bool,
    sarif: bool,
    output: Option<&PathBuf>,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let db = GraphDb::open(&db_path)?;

    // Resolve investigation ID
    let inv_id = match investigation_id {
        Some(id) => id.to_string(),
        None => {
            // Find the most recent investigation
            let id: String = db
                .conn()
                .query_row(
                    "SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    anyhow::anyhow!("No investigations found. Run `skwaq analyze --quick` first.")
                })?;
            id
        }
    };

    if sarif {
        println!("SARIF report generation is not yet implemented.");
        println!("Use --json for JSON output.");
        return Ok(());
    }

    // Default to JSON if --json is set, or if no specific format requested
    if json || !sarif {
        let report = generate_report_for_investigation(&db, &inv_id)?;

        match output {
            Some(path) => {
                std::fs::write(path, &report)?;
                println!("Report written to {}", path.display());
            }
            None => {
                println!("{report}");
            }
        }
    }

    Ok(())
}
