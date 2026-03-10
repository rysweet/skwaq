//! `skwaq annotate` - add annotations to investigation targets.

use super::common::{most_recent_investigation, open_db};

pub fn run(target: &str, text: &str) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    let ann_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    db.execute(
        "INSERT INTO annotations (id, target_address, text, author, timestamp, investigation_id) \
         VALUES (?1, ?2, ?3, 'user', ?4, ?5)",
        &[
            &ann_id.as_str(),
            &target,
            &text,
            &now.as_str(),
            &inv_id.as_str(),
        ],
    )?;

    println!("Annotation added to investigation {inv_id}");
    println!("  Target: {target}");
    println!("  Text:   {text}");
    println!("  ID:     {ann_id}");
    Ok(())
}
