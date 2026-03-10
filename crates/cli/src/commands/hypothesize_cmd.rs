//! `skwaq hypothesize` - create vulnerability hypotheses.

use super::common::{most_recent_investigation, open_db};

pub fn run(focus: Option<&str>) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    let description = focus.unwrap_or("General vulnerability hypothesis");
    let hyp_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO hypotheses (id, description, status, evidence, timestamp, investigation_id) \
         VALUES (?1, ?2, 'pending', '', ?3, ?4)",
        &[
            &hyp_id.as_str(),
            &description,
            &now.as_str(),
            &inv_id.as_str(),
        ],
    )?;

    println!("Hypothesis created for investigation {inv_id}");
    println!("  Description: {description}");
    println!("  Status:      pending");
    println!("  ID:          {hyp_id}");
    Ok(())
}
