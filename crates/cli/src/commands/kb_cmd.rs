//! `skwaq kb` - knowledge base operations.

use super::common::open_db;
use skwaq_core::{config::Config, graph::GraphDb};

pub fn run_init() -> anyhow::Result<()> {
    let db = open_db().or_else(|_| {
        // Create the DB if it doesn't exist using the configured path
        let db_dir = skwaq_core::config::Config::load()?.database_path();
        skwaq_core::graph::GraphDb::open(&db_dir)
    })?;

    let summary = skwaq_core::knowledge::initialize_cwe_catalog(&db)?;

    println!(
        "Knowledge base initialized: {} CWE entries added ({} total in catalog, {} knowledge pack files available).",
        summary.inserted_cwes,
        summary.total_seed_cwes,
        summary.knowledge_packs_found
    );
    Ok(())
}

pub fn run_search(query: &str, json: bool) -> anyhow::Result<()> {
    let db = open_search_db()?;
    let results = skwaq_core::knowledge::search_knowledge(db.as_ref(), query)?;

    if results.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "no_results",
                    "query": query,
                    "hint": "Try `skwaq kb init` to populate CWE entries, or search for methodology / memory / cwe-* topics."
                })
            );
            return Ok(());
        }
        println!("No KB entries matching '{query}'.");
        println!("Try `skwaq kb init` to populate CWE entries.");
        return Ok(());
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "query": query,
                "results": results,
            }))?
        );
        return Ok(());
    }

    println!("KB entries matching '{query}':\n");
    for result in &results {
        println!("  [{}] {}", result.source, result.title);
        println!("        topic: {}", result.topic);
        println!("        {}\n", result.content);
    }

    println!("{} result(s).", results.len());
    Ok(())
}

fn open_search_db() -> anyhow::Result<Option<GraphDb>> {
    let db_dir = Config::load()?.database_path();
    let db_file = db_dir.join("skwaq.db");
    if !db_file.exists() {
        return Ok(None);
    }
    Ok(Some(GraphDb::open(&db_dir)?))
}
