//! `skwaq investigate` - investigation management.

use super::InvestigateSub;
use skwaq_core::graph::db::GraphDb;
use skwaq_core::graph::queries::get_investigations;
use std::path::PathBuf;

pub fn run(sub: &InvestigateSub) -> anyhow::Result<()> {
    match sub {
        InvestigateSub::New { name } => {
            println!("skwaq investigate new: coming soon ({name})");
        }
        InvestigateSub::Resume { id } => {
            println!("skwaq investigate resume: coming soon ({id})");
        }
        InvestigateSub::List => {
            list_investigations()?;
        }
        InvestigateSub::Export { id, output } => {
            let out = output
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "stdout".into());
            println!("skwaq investigate export: coming soon ({id} -> {out})");
        }
    }
    Ok(())
}

fn list_investigations() -> anyhow::Result<()> {
    let db_dir = graph_db_path()?;
    if !db_dir.join("skwaq.db").exists() {
        println!("No investigations found. Run `skwaq ingest binary <path>` first.");
        return Ok(());
    }

    let db = GraphDb::open(&db_dir)?;
    let investigations = get_investigations(&db)?;

    if investigations.is_empty() {
        println!("No investigations found. Run `skwaq ingest binary <path>` first.");
        return Ok(());
    }

    // Print table header.
    println!(
        "{:<20} {:<30} {:<10} {}",
        "ID", "NAME", "STATUS", "CREATED"
    );
    println!("{}", "-".repeat(80));

    for (id, name, status, created) in &investigations {
        println!("{:<20} {:<30} {:<10} {}", id, name, status, created);
    }

    println!("\n{} investigation(s) found.", investigations.len());

    Ok(())
}

fn graph_db_path() -> anyhow::Result<PathBuf> {
    let dir = std::env::current_dir()?.join(".skwaq").join("graph");
    Ok(dir)
}
