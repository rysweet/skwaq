//! `skwaq analyze` - vulnerability analysis command.

use skwaq_core::analysis::{DangerousApiDetector, TaintAnalyzer};
use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;
use uuid::Uuid;

pub fn run(investigation_id: Option<&str>, quick: bool, budget: Option<u64>) -> anyhow::Result<()> {
    if !quick {
        let budget_str = budget
            .map(|b| format!(" (budget: {b} tokens)"))
            .unwrap_or_default();
        println!(
            "AI analysis requires LLM configuration{budget_str}. \
             Run with --quick for pattern-based analysis."
        );
        return Ok(());
    }

    println!("Running quick analysis (pattern detection + taint analysis)...\n");

    let config = Config::load()?;
    let db_path = config.database_path();
    let db = GraphDb::open(&db_path)?;

    // Use provided investigation or find the most recent one
    let inv_id = match investigation_id {
        Some(id) => {
            // Verify it exists
            let count: i64 = db.conn().query_row(
                "SELECT count(*) FROM investigations WHERE id = ?1",
                [id],
                |row| row.get(0),
            )?;
            if count == 0 {
                anyhow::bail!("Investigation '{}' not found. Run `skwaq investigate list`.", id);
            }
            id.to_string()
        }
        None => {
            // Find most recent investigation
            let result: Result<String, _> = db.conn().query_row(
                "SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            );
            match result {
                Ok(id) => {
                    println!("Using most recent investigation: {id}\n");
                    id
                }
                Err(_) => {
                    anyhow::bail!(
                        "No investigations found. Run `skwaq ingest binary <path>` first."
                    );
                }
            }
        }
    };

    let now = chrono::Utc::now().to_rfc3339();

    // Phase 1: Dangerous API detection
    println!("Phase 1: Dangerous API detection");
    let detector = DangerousApiDetector::new();
    let api_hits = detector.detect(&db)?;

    if api_hits.is_empty() {
        println!("  No dangerous API usage detected.\n");
    } else {
        println!("  Found {} dangerous API usage(s):\n", api_hits.len());
        println!(
            "  {:<25} {:<15} {:<10} {}",
            "FUNCTION", "CATEGORY", "SEVERITY", "REASON"
        );
        println!("  {}", "-".repeat(85));
        for hit in &api_hits {
            println!(
                "  {:<25} {:<15} {:<10} {}",
                hit.function_name, hit.danger_category, hit.severity, hit.reason
            );
        }
        println!();

        for hit in &api_hits {
            let finding_id = Uuid::new_v4().to_string();
            db.execute(
                "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
                 VALUES (?1, ?2, ?3, 'pattern-detector', ?4, ?5)",
                &[
                    &finding_id.as_str(),
                    &format!("Dangerous API: {}", hit.function_name).as_str(),
                    &format!(
                        "category={}, severity={}, reason={}",
                        hit.danger_category, hit.severity, hit.reason
                    )
                    .as_str(),
                    &now.as_str(),
                    &inv_id.as_str(),
                ],
            )?;
        }
    }

    // Phase 2: Taint analysis
    println!("Phase 2: Taint analysis");
    let max_depth = config.analysis.max_taint_depth;
    let taint = TaintAnalyzer::new(&db, max_depth);
    let taint_paths = taint.find_unsanitized_paths()?;

    if taint_paths.is_empty() {
        println!("  No unsanitized taint paths detected.\n");
    } else {
        println!("  Found {} unsanitized taint path(s):\n", taint_paths.len());
        println!("  {:<20} {:<20} {}", "SOURCE", "SINK", "PATH");
        println!("  {}", "-".repeat(70));
        for tp in &taint_paths {
            println!(
                "  {:<20} {:<20} {}",
                tp.source,
                tp.sink,
                tp.hops.join(" -> ")
            );
        }
        println!();

        for tp in &taint_paths {
            let finding_id = Uuid::new_v4().to_string();
            db.execute(
                "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id) \
                 VALUES (?1, ?2, ?3, 'taint-analyzer', ?4, ?5)",
                &[
                    &finding_id.as_str(),
                    &format!("Unsanitized flow: {} -> {}", tp.source, tp.sink).as_str(),
                    &format!("path: {}", tp.hops.join(" -> ")).as_str(),
                    &now.as_str(),
                    &inv_id.as_str(),
                ],
            )?;
        }
    }

    let total = api_hits.len() + taint_paths.len();
    println!("Analysis complete: {} finding(s) stored.", total);
    println!("Investigation: {inv_id}");
    println!("Run `skwaq report {inv_id} --json` to export results.");

    Ok(())
}
