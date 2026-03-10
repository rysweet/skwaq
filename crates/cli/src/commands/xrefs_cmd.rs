//! `skwaq xrefs` - cross-reference lookup.

use super::common::{most_recent_investigation, open_db};

pub fn run(function: &str) -> anyhow::Result<()> {
    let db = open_db()?;
    let inv_id = most_recent_investigation(&db)?;

    // Find callers of this function
    let mut stmt = db.conn().prepare(
        "SELECT f1.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f2.name = ?1 AND f1.investigation_id = ?2",
    )?;
    let callers: Vec<String> = stmt
        .query_map([function, inv_id.as_str()], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    // Find callees of this function
    let mut stmt = db.conn().prepare(
        "SELECT f2.name FROM calls c \
         JOIN functions f1 ON c.caller_id = f1.id \
         JOIN functions f2 ON c.callee_id = f2.id \
         WHERE f1.name = ?1 AND f1.investigation_id = ?2",
    )?;
    let callees: Vec<String> = stmt
        .query_map([function, inv_id.as_str()], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    println!(
        "Cross-references for '{}' (investigation {}):\n",
        function, inv_id
    );

    if callers.is_empty() && callees.is_empty() {
        println!("  No cross-references found for '{function}'.");
        println!("  Make sure the function name matches exactly (case-sensitive).");
        return Ok(());
    }

    if !callers.is_empty() {
        println!("  Called by ({}):", callers.len());
        for c in &callers {
            println!("    <- {c}");
        }
    }

    if !callees.is_empty() {
        println!("  Calls ({}):", callees.len());
        for c in &callees {
            println!("    -> {c}");
        }
    }

    Ok(())
}
