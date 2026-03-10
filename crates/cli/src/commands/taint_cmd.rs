//! `skwaq taint` - display taint flow analysis.

use super::common::open_db;

pub fn run(source_filter: Option<&str>, sink_filter: Option<&str>) -> anyhow::Result<()> {
    let db = open_db()?;

    // Query taint_flows
    let mut stmt = db.conn().prepare(
        "SELECT s.name, k.name, tf.path, tf.sanitized FROM taint_flows tf \
         JOIN data_sources s ON tf.source_id = s.id \
         JOIN data_sinks k ON tf.sink_id = k.id",
    )?;
    let flows: Vec<(String, String, String, bool)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    if flows.is_empty() {
        println!("No taint flows found.");
        println!("Run `skwaq analyze --quick` to discover taint paths.");
        return Ok(());
    }

    // Apply filters
    let filtered: Vec<_> = flows
        .iter()
        .filter(|(src, snk, _, _)| {
            let src_match = source_filter.map_or(true, |f| src.contains(f));
            let snk_match = sink_filter.map_or(true, |f| snk.contains(f));
            src_match && snk_match
        })
        .collect();

    println!(
        "Taint flows ({} total, {} shown):\n",
        flows.len(),
        filtered.len()
    );
    println!(
        "  {:<20} {:<20} {:<10} {}",
        "SOURCE", "SINK", "SANITIZED", "PATH"
    );
    println!("  {}", "-".repeat(80));

    for (src, snk, path, sanitized) in &filtered {
        let san_str = if *sanitized { "yes" } else { "NO" };
        println!("  {:<20} {:<20} {:<10} {}", src, snk, san_str, path);
    }

    let unsanitized = filtered.iter().filter(|(_, _, _, s)| !s).count();
    println!("\n  {} unsanitized flow(s) found.", unsanitized);
    Ok(())
}
