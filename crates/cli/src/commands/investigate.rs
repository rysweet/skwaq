//! `skwaq investigate` - investigation management.

use super::common::open_db;
use super::InvestigateSub;
use skwaq_core::graph::queries::get_investigations;
use skwaq_core::investigation::InvestigationManager;

pub fn run(sub: &InvestigateSub) -> anyhow::Result<()> {
    match sub {
        InvestigateSub::New { name } => {
            let db = open_db()?;
            let mgr = InvestigationManager::new(&db);
            let id = mgr.create(name)?;
            println!("Created investigation '{name}' with ID: {id}");
        }
        InvestigateSub::Resume { id } => {
            let db = open_db()?;
            let mgr = InvestigationManager::new(&db);
            mgr.resume(id)?;
            println!("Resumed investigation {id}.");
        }
        InvestigateSub::List => {
            list_investigations()?;
        }
    }
    Ok(())
}

fn list_investigations() -> anyhow::Result<()> {
    let db = open_db()?;
    let investigations = get_investigations(&db)?;

    if investigations.is_empty() {
        println!("No investigations found. Run `skwaq ingest binary <path>` first.");
        return Ok(());
    }

    // Print table header.
    println!("{:<20} {:<30} {:<10} CREATED", "ID", "NAME", "STATUS");
    println!("{}", "-".repeat(80));

    for (id, name, status, created) in &investigations {
        println!("{:<20} {:<30} {:<10} {}", id, name, status, created);
    }

    println!("\n{} investigation(s) found.", investigations.len());

    Ok(())
}
