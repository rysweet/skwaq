//! `skwaq kb` - knowledge base operations.

use super::common::open_db;

pub fn run_init() -> anyhow::Result<()> {
    let db = open_db().or_else(|_| {
        // Create the DB if it doesn't exist using the configured path
        let db_dir = skwaq_core::config::Config::load()?.database_path();
        skwaq_core::graph::GraphDb::open(&db_dir)
    })?;

    // Insert some well-known CWEs into the cwes table
    let cwes = [
        (
            "CWE-119",
            "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "Buffer overflow/underflow vulnerabilities",
        ),
        (
            "CWE-120",
            "Buffer Copy without Checking Size of Input",
            "Classic buffer overflow from unbounded copy operations",
        ),
        (
            "CWE-125",
            "Out-of-bounds Read",
            "Reading data past the end of an allocated buffer",
        ),
        (
            "CWE-134",
            "Use of Externally-Controlled Format String",
            "Format string vulnerabilities from user-controlled format specifiers",
        ),
        (
            "CWE-190",
            "Integer Overflow or Wraparound",
            "Integer arithmetic that wraps leading to unexpected values",
        ),
        (
            "CWE-416",
            "Use After Free",
            "Accessing memory after it has been freed",
        ),
        (
            "CWE-476",
            "NULL Pointer Dereference",
            "Dereferencing a NULL pointer leading to crash",
        ),
        (
            "CWE-78",
            "Improper Neutralization of Special Elements used in an OS Command",
            "OS command injection",
        ),
        (
            "CWE-787",
            "Out-of-bounds Write",
            "Writing data past the end of an allocated buffer",
        ),
        (
            "CWE-798",
            "Use of Hard-coded Credentials",
            "Credentials embedded directly in source code",
        ),
        (
            "CWE-20",
            "Improper Input Validation",
            "Failure to validate user-supplied input",
        ),
        (
            "CWE-22",
            "Improper Limitation of a Pathname to a Restricted Directory",
            "Path traversal",
        ),
        (
            "CWE-77",
            "Improper Neutralization of Special Elements used in a Command",
            "Command injection",
        ),
        (
            "CWE-89",
            "Improper Neutralization of Special Elements used in an SQL Command",
            "SQL injection",
        ),
        (
            "CWE-362",
            "Concurrent Execution using Shared Resource with Improper Synchronization",
            "Race conditions",
        ),
    ];

    let mut inserted = 0;
    for (cwe_id, name, description) in &cwes {
        let id = cwe_id.to_lowercase().replace('-', "_");
        let result = db.execute(
            "INSERT OR IGNORE INTO cwes (id, cwe_id, name, description) VALUES (?1, ?2, ?3, ?4)",
            &[&id.as_str(), cwe_id, name, description],
        )?;
        if result > 0 {
            inserted += 1;
        }
    }

    println!(
        "Knowledge base initialized: {inserted} CWE entries added ({} total in catalog).",
        cwes.len()
    );
    Ok(())
}

pub fn run_search(query: &str) -> anyhow::Result<()> {
    let db = open_db()?;

    let pattern = format!("%{}%", query.to_lowercase());
    let mut stmt = db.conn().prepare(
        "SELECT cwe_id, name, description FROM cwes \
         WHERE lower(cwe_id) LIKE ?1 OR lower(name) LIKE ?1 OR lower(description) LIKE ?1 \
         ORDER BY cwe_id",
    )?;
    let results: Vec<(String, String, String)> = stmt
        .query_map([pattern.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if results.is_empty() {
        println!("No CWE entries matching '{query}'.");
        println!("Try `skwaq kb init` to populate the knowledge base.");
        return Ok(());
    }

    println!("CWE entries matching '{query}':\n");
    for (cwe_id, name, desc) in &results {
        println!("  {:<10} {}", cwe_id, name);
        println!("            {}\n", desc);
    }

    println!("{} result(s).", results.len());
    Ok(())
}
