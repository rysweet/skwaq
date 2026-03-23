//! `skwaq analyze` - vulnerability analysis command.
//!
//! When `--quick` is given, runs fast pattern-based analysis only (no LLM).
//! Without `--quick` (the default), runs BOTH pattern-based analysis AND
//! the AI agent pipeline, synthesizing results from both for maximum coverage.
//! Use `--agents` or `--agent` to override which agents run in AI mode.

use super::common::resolve_investigation;
use skwaq_core::agents::{
    default_pipeline_for_target, pipeline_from_names, source_pipeline_for_target, PipelineClients,
};
use skwaq_core::analysis::{
    extract_function_from_title, AnalysisOrchestrator, FindingStatus, SemanticPatternClassifier,
};
use skwaq_core::config::Config;
use skwaq_core::graph::GraphDb;
use skwaq_core::memory::MemoryStore;

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
        run_combined_analysis(investigation_id, budget, agents, agent).await
    }
}

/// Run combined analysis: pattern detection + multi-cycle orchestrator + AI agents.
///
/// This synthesizes results from both the fast pattern-based analysis and the
/// LLM agent pipeline. Pattern findings anchor precision; AI findings add recall.
/// Only non-invalidated findings from both sources are reported.
async fn run_combined_analysis(
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
    let (target, investigation_name): (String, String) = db
        .conn()
        .query_row(
            "SELECT COALESCE(target, name), name FROM investigations WHERE id = ?1",
            [&inv_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|_| (inv_id.clone(), inv_id.clone()));

    // --- Phase 1: Pattern detection + multi-cycle orchestrator ---
    eprintln!("Phase 1: Running pattern detection + data flow analysis...");
    let orchestrator = AnalysisOrchestrator::new(&db, 5);
    let cycles = orchestrator.run_quick_analysis(&inv_id)?;

    let pattern_finding_count: usize = cycles
        .last()
        .map(|c| {
            c.findings
                .iter()
                .filter(|f| f.status != FindingStatus::Invalidated)
                .count()
        })
        .unwrap_or(0);

    eprintln!(
        "  Pattern analysis: {} active finding(s) after {} cycle(s)",
        pattern_finding_count,
        cycles.len()
    );

    // --- Phase 2: AI agent pipeline ---
    let budget_amount = budget.unwrap_or(config.analysis.default_token_budget);

    let source_investigation = investigation_name.starts_with("source:");
    let pipeline = if let Some(single) = agent_flag {
        pipeline_from_names(&[single.to_string()])
    } else if let Some(names) = agents_flag {
        let names: Vec<String> = names.split(',').map(|s| s.trim().to_string()).collect();
        pipeline_from_names(&names)
    } else if source_investigation {
        source_pipeline_for_target(&target)
    } else {
        default_pipeline_for_target(&target)
    };

    let stage_names: Vec<&str> = pipeline
        .stages
        .iter()
        .map(|s| s.agent_name.as_str())
        .collect();

    let display_model = pipeline
        .stages
        .first()
        .and_then(|s| skwaq_core::agents::definition::load_agent(&s.agent_name).ok())
        .map(|a| a.model)
        .unwrap_or_else(|| config.llm.copilot.model.clone());

    eprintln!("Phase 2: Running AI agent pipeline...");
    eprintln!("  Model: {display_model}");
    eprintln!("  Token budget: {budget_amount}");
    eprintln!("  Pipeline: {}", stage_names.join(" -> "));
    println!();

    let (reasoning_client, decompilation_client) = skwaq_core::llm::create_pipeline_clients(
        &config.llm,
        pipeline.requires_reasoning_client(),
        pipeline.requires_decompilation_client(),
    )
    .await?;
    let mut token_budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    // Open durable memory for cross-run learning
    let memory = MemoryStore::open_default()?;

    let results = pipeline
        .run_with_memory(
            &target,
            &inv_id,
            &db,
            PipelineClients::from_optional(reasoning_client, decompilation_client),
            &mut token_budget,
            &memory,
        )
        .await?;

    for result in &results {
        println!("--- {} ---", result.agent_name);
        println!("{}", result.output);
        if let Some(parse_error) = &result.parsed_output_error {
            eprintln!(
                "warning: {} returned output that did not match schema {}: {}",
                result.agent_name,
                result
                    .context_frame
                    .output_schema
                    .as_deref()
                    .unwrap_or("unknown"),
                parse_error
            );
        }
        println!();
    }

    // --- Phase 3: Synthesize all findings ---
    // Query ALL findings from both pattern analysis and AI agents
    let mut stmt = db.conn().prepare(
        "SELECT title, severity, category, evidence, agent FROM findings \
         WHERE investigation_id = ?1 AND status != 'invalidated' \
         ORDER BY CASE severity \
           WHEN 'critical' THEN 0 \
           WHEN 'high' THEN 1 \
           WHEN 'medium' THEN 2 \
           WHEN 'low' THEN 3 \
           ELSE 4 END",
    )?;

    let findings: Vec<(String, String, String, String, String)> = stmt
        .query_map([&inv_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4).unwrap_or_default(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if findings.is_empty() {
        println!("No findings recorded.");
    } else {
        println!("{} finding(s) from combined analysis:\n", findings.len());
        println!(
            "  {:<36} {:<10} {:<15} {:<22} SOURCE",
            "TITLE", "SEVERITY", "CATEGORY", "SEMANTIC"
        );
        println!("  {}", "-".repeat(110));
        for (title, severity, category, _evidence, agent) in &findings {
            let source = if agent.contains("pattern") || agent.contains("taint") {
                "pattern"
            } else {
                "AI agent"
            };
            let semantic =
                semantic_classes_text(category, title, extract_function_from_title(title));
            println!(
                "  {:<36} {:<10} {:<15} {:<22} {}",
                truncate(title, 36),
                severity,
                category,
                truncate(&semantic, 22),
                source,
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

        let discovered_findings: Vec<_> = cycle
            .findings
            .iter()
            .filter(|finding| finding.cycle_discovered == cycle.cycle_number)
            .collect();
        if !discovered_findings.is_empty() {
            println!(
                "  {:<30} {:<15} {:<10} {:<22} STATUS",
                "FINDING", "CATEGORY", "SEVERITY", "SEMANTIC"
            );
            println!("  {}", "-".repeat(110));
            for finding in discovered_findings {
                let semantic = semantic_classes_text(
                    &finding.category,
                    &finding.title,
                    finding.location.function.clone(),
                );
                println!(
                    "  {:<30} {:<15} {:<10} {:<22} {}",
                    truncate(&finding.title, 30),
                    finding.category,
                    finding.severity,
                    truncate(&semantic, 22),
                    finding.status,
                );
            }
            println!();
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

        println!();
        println!(
            "  {:<30} {:<15} {:<10} {:<22} STATUS",
            "FINDING", "CATEGORY", "SEVERITY", "SEMANTIC"
        );
        println!("  {}", "-".repeat(110));
        if active_findings.is_empty() {
            println!("  (no active findings)");
        } else {
            for finding in &active_findings {
                let semantic = semantic_classes_text(
                    &finding.category,
                    &finding.title,
                    finding.location.function.clone(),
                );
                println!(
                    "  {:<30} {:<15} {:<10} {:<22} {}",
                    truncate(&finding.title, 30),
                    finding.category,
                    finding.severity,
                    truncate(&semantic, 22),
                    finding.status,
                );
            }
        }
        println!();
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

fn semantic_classes_text(category: &str, title: &str, function_name: String) -> String {
    let classes = SemanticPatternClassifier::new()
        .classify(category, title, &function_name)
        .into_iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>();
    if classes.is_empty() {
        "-".to_string()
    } else {
        classes.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_classes_text_reports_buffer_overflow() {
        let semantic = semantic_classes_text(
            "memory",
            "Dangerous pattern: strcpy (foo.c:10)",
            "strcpy".into(),
        );

        assert_eq!(semantic, "buffer_overflow,unsafe_api_usage");
    }

    #[test]
    fn semantic_classes_text_falls_back_to_dash() {
        let semantic = semantic_classes_text(
            "memory",
            "Suspicious memory corruption risk",
            "parse_packet".into(),
        );

        assert_eq!(semantic, "-");
    }

    #[test]
    fn extract_function_from_title_handles_pattern_titles() {
        assert_eq!(
            extract_function_from_title("Dangerous pattern: strcpy (foo.c:10)"),
            "strcpy"
        );
    }
}
