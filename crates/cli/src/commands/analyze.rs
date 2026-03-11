//! `skwaq analyze` - vulnerability analysis command.
//!
//! When `--quick` is given, runs fast pattern-based analysis (no LLM).
//! Without `--quick`, drives the dynamic agent pipeline through real LLM calls.
//! Use `--agents` or `--agent` to override which agents run.

use super::common::resolve_investigation;
use skwaq_core::agents::{default_pipeline, pipeline_from_names};
use skwaq_core::analysis::{AnalysisOrchestrator, FindingStatus};
use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;

/// Entry point for the analyze command. Delegates to the appropriate
/// analysis mode based on the `quick` flag.
pub async fn run(
    investigation_id: Option<&str>,
    quick: bool,
    budget: Option<u64>,
    agents: Option<&str>,
    agent: Option<&str>,
) -> anyhow::Result<()> {
    if quick {
        run_quick_analysis(investigation_id)
    } else {
        run_ai_analysis(investigation_id, budget, agents, agent).await
    }
}

/// Run the LLM-driven agent pipeline for deep analysis.
async fn run_ai_analysis(
    investigation_id: Option<&str>,
    budget: Option<u64>,
    agents_flag: Option<&str>,
    agent_flag: Option<&str>,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path();
    let db = GraphDb::open(&db_path)?;

    let inv_id = resolve_investigation(&db, investigation_id)?;

    // Get the target name for the prompt
    let target: String = db
        .conn()
        .query_row(
            "SELECT COALESCE(target, name) FROM investigations WHERE id = ?1",
            [&inv_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| inv_id.clone());

    let budget_amount = budget.unwrap_or(config.analysis.default_token_budget);
    // Model is determined per-agent from their markdown definitions

    // Build the pipeline based on flags
    let pipeline = if let Some(single) = agent_flag {
        pipeline_from_names(&[single.to_string()])
    } else if let Some(names) = agents_flag {
        let names: Vec<String> = names.split(',').map(|s| s.trim().to_string()).collect();
        pipeline_from_names(&names)
    } else {
        default_pipeline()
    };

    let stage_names: Vec<&str> = pipeline
        .stages
        .iter()
        .map(|s| s.agent_name.as_str())
        .collect();

    // Show model from first agent (each agent specifies its own model in frontmatter)
    let display_model = pipeline
        .stages
        .first()
        .and_then(|s| skwaq_core::agents::definition::load_agent(&s.agent_name).ok())
        .map(|a| a.model)
        .unwrap_or_else(|| config.llm.copilot.model.clone());

    eprintln!("Running AI vulnerability analysis...");
    eprintln!("  Investigation: {inv_id}");
    eprintln!("  Model: {display_model}");
    eprintln!("  Token budget: {budget_amount}");
    eprintln!("  Pipeline: {}", stage_names.join(" -> "));
    println!();

    // Create the LLM client (delegates to RustyClawd)
    let llm_client = skwaq_core::llm::create_client(&config.llm).await?;

    let mut token_budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    let results = pipeline
        .run(&target, &inv_id, &db, llm_client, &mut token_budget)
        .await?;

    // Print results from each agent
    for result in &results {
        println!("--- {} ---", result.agent_name);
        println!("{}", result.output);
        println!();
    }

    // Query findings created by the agents
    let mut stmt = db.conn().prepare(
        "SELECT title, severity, category, evidence FROM findings \
         WHERE investigation_id = ?1 \
         ORDER BY CASE severity \
           WHEN 'critical' THEN 0 \
           WHEN 'high' THEN 1 \
           WHEN 'medium' THEN 2 \
           WHEN 'low' THEN 3 \
           ELSE 4 END",
    )?;

    let findings: Vec<(String, String, String, String)> = stmt
        .query_map([&inv_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if findings.is_empty() {
        println!("No findings recorded.");
    } else {
        println!("{} finding(s) recorded:\n", findings.len());
        println!("  {:<40} {:<10} CATEGORY", "TITLE", "SEVERITY");
        println!("  {}", "-".repeat(70));
        for (title, severity, category, _evidence) in &findings {
            println!(
                "  {:<40} {:<10} {}",
                truncate(title, 40),
                severity,
                category,
            );
        }
        println!();
    }

    println!("Total tokens used: {}", token_budget.used);
    println!("Investigation: {inv_id}");
    println!("Run `skwaq report {inv_id} --json` to export results.");

    Ok(())
}

/// Run quick pattern-based analysis (no LLM calls).
fn run_quick_analysis(investigation_id: Option<&str>) -> anyhow::Result<()> {
    println!("Running multi-cycle analysis...\n");

    let config = Config::load()?;
    let db_path = config.database_path();
    let db = GraphDb::open(&db_path)?;

    let inv_id = resolve_investigation(&db, investigation_id)?;

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
                "  {:<35} {:<15} {:<10} STATUS",
                "FINDING", "CATEGORY", "SEVERITY"
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
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        let truncated: String = chars[..max.saturating_sub(3)].iter().collect();
        format!("{truncated}...")
    }
}
