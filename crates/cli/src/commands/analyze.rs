//! `skwaq analyze` - vulnerability analysis command.

use skwaq_core::analysis::{AnalysisOrchestrator, FindingStatus};
use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;

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

    println!("Running multi-cycle analysis...\n");

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

    let max_cycles = 5;
    let orchestrator = AnalysisOrchestrator::new(&db, max_cycles);
    let cycles = orchestrator.run_quick_analysis(&inv_id)?;

    // Display cycle-by-cycle progress
    for cycle in &cycles {
        let label = match cycle.cycle_number {
            1 => "Pattern Detection + Taint Analysis",
            2 => "Data Flow Validation",
            _ => "Context Analysis",
        };
        println!("Cycle {}: {}", cycle.cycle_number, label);

        if cycle.cycle_number == 1 {
            println!("  Found {} potential issues\n", cycle.new_findings);
        } else {
            let confirmed = cycle
                .findings
                .iter()
                .filter(|f| f.status == FindingStatus::Confirmed)
                .count();
            let challenged = cycle
                .findings
                .iter()
                .filter(|f| f.status == FindingStatus::Challenged)
                .count();
            let invalidated = cycle
                .findings
                .iter()
                .filter(|f| f.status == FindingStatus::Invalidated)
                .count();

            let mut parts = Vec::new();
            if confirmed > 0 {
                parts.push(format!("confirmed {}", confirmed));
            }
            if challenged > 0 {
                parts.push(format!("challenged {}", challenged));
            }
            if invalidated > 0 {
                parts.push(format!("invalidated {}", invalidated));
            }
            if cycle.new_findings > 0 {
                parts.push(format!("{} new findings", cycle.new_findings));
            }
            if parts.is_empty() {
                parts.push("no changes".to_string());
            }
            println!("  {}\n", parts.join(", "));
        }
    }

    // Summary
    let total_cycles = cycles.len();
    if let Some(last) = cycles.last() {
        let confirmed = last
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Confirmed)
            .count();
        let invalidated = last
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Invalidated)
            .count();
        let still_new = last
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::New)
            .count();
        let active = confirmed + still_new;

        println!("Analysis converged after {} cycle(s).", total_cycles);
        println!(
            "Final: {} confirmed finding(s), {} invalidated (false positives filtered)",
            active, invalidated
        );

        // Show detailed findings
        let active_findings: Vec<_> = last
            .findings
            .iter()
            .filter(|f| f.status != FindingStatus::Invalidated)
            .collect();

        if !active_findings.is_empty() {
            println!();
            println!(
                "  {:<35} {:<15} {:<10} {}",
                "FINDING", "CATEGORY", "SEVERITY", "STATUS"
            );
            println!("  {}", "-".repeat(85));
            for finding in &active_findings {
                println!(
                    "  {:<35} {:<15} {:<10} {}",
                    truncate(&finding.title, 35),
                    finding.category,
                    finding.severity,
                    finding.status,
                );
            }
            println!();
        }
    }

    println!("Investigation: {inv_id}");
    println!("Run `skwaq report {inv_id} --json` to export results.");

    Ok(())
}

/// Truncate a string to fit in a column width.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
