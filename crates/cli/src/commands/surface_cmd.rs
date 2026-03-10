//! `skwaq surface` - display attack surface information.

use super::common::{most_recent_investigation, open_db};

pub fn run() -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    println!("Attack surface for investigation: {inv_id}\n");

    // Data sources (entry points)
    let mut stmt = db.conn().prepare(
        "SELECT name, source_type, location FROM data_sources \
         WHERE investigation_id = ?1 ORDER BY source_type, name",
    )?;
    let sources: Vec<(String, String, String)> = stmt
        .query_map([inv_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if sources.is_empty() {
        println!("  No data sources (entry points) found.");
    } else {
        println!("ENTRY POINTS (data sources):");
        println!("  {:<30} {:<15} {}", "NAME", "TYPE", "LOCATION");
        println!("  {}", "-".repeat(65));
        for (name, stype, loc) in &sources {
            let loc_display = if loc.is_empty() { "-" } else { loc.as_str() };
            println!("  {:<30} {:<15} {}", name, stype, loc_display);
        }
        println!("\n  {} entry point(s)\n", sources.len());
    }

    // Data sinks (dangerous functions)
    let mut stmt = db.conn().prepare(
        "SELECT name, sink_type, danger_level, location FROM data_sinks \
         WHERE investigation_id = ?1 ORDER BY danger_level DESC, name",
    )?;
    let sinks: Vec<(String, String, String, String)> = stmt
        .query_map([inv_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if sinks.is_empty() {
        println!("  No data sinks (dangerous functions) found.");
    } else {
        println!("DANGEROUS SINKS:");
        println!(
            "  {:<30} {:<15} {:<10} {}",
            "NAME", "TYPE", "DANGER", "LOCATION"
        );
        println!("  {}", "-".repeat(75));
        for (name, stype, danger, loc) in &sinks {
            let loc_display = if loc.is_empty() { "-" } else { loc.as_str() };
            println!("  {:<30} {:<15} {:<10} {}", name, stype, danger, loc_display);
        }
        println!("\n  {} dangerous sink(s)", sinks.len());
    }

    Ok(())
}
