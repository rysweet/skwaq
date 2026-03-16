//! `skwaq investigate-binary <binary>` — binary investigation with AI agents.
//!
//! Ingests the binary, runs Ghidra decompilation, pattern analysis,
//! and the full AI agent pipeline. Errors propagate — no silent fallbacks.

use std::path::Path;

/// Run investigation on a binary.
pub async fn run(binary: &Path) -> anyhow::Result<()> {
    use skwaq_core::binary::native::parse_binary;
    use skwaq_core::graph::builder::GraphBuilder;
    use skwaq_core::graph::GraphDb;

    println!("Investigating binary: {}", binary.display());

    // Parse binary
    let binary_info = parse_binary(binary)?;
    println!(
        "  Format: {:?}, {} symbols, {} imports",
        binary_info.format,
        binary_info.symbols.len(),
        binary_info.imports.len()
    );

    // Create investigation
    let db = GraphDb::in_memory()?;
    let inv_id = format!("inv-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let target = binary.to_string_lossy().to_string();

    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &target.as_str(),
            &target.as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // Ingest binary into graph
    let builder = GraphBuilder::new(&db);
    let counts = builder.build_from_binary_info(&binary_info, &inv_id)?;
    println!(
        "  Graph: {} functions, {} imports, {} strings",
        counts.functions, counts.imports, counts.strings
    );

    // Ghidra decompilation — required
    let ghidra_path = skwaq_core::binary::ghidra::GhidraRunner::find_ghidra().ok_or_else(|| {
        anyhow::anyhow!(
            "Ghidra not found. Install from https://ghidra-sre.org/ and set GHIDRA_INSTALL_DIR"
        )
    })?;
    let ghidra_runner = skwaq_core::binary::ghidra::GhidraRunner::new(Some(ghidra_path));
    println!("  Running Ghidra decompilation...");
    let analysis = ghidra_runner.analyze(binary, 600).await?;
    let ghidra_counts = builder.build_from_ghidra_analysis(&analysis, &inv_id)?;
    println!(
        "  Ghidra: {} functions updated, {} added, {} calls",
        ghidra_counts.functions_updated, ghidra_counts.functions_added, ghidra_counts.calls_added
    );

    // Pattern analysis
    println!("  Running pattern analysis...");
    let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
    let cycles = orchestrator.run_quick_analysis(&inv_id)?;
    println!("  Pattern analysis: {} cycles completed", cycles.len());

    // LLM agent pipeline — required
    let config = skwaq_core::config::Config::load()?;

    let file_name = binary
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| target.clone());

    println!("  Running AI agent pipeline...");
    let pipeline = skwaq_core::agents::deep_pipeline_for_target(&file_name);
    let (reasoning_client, decompilation_client) = skwaq_core::llm::create_pipeline_clients(
        &config.llm,
        pipeline.requires_reasoning_client(),
        pipeline.requires_decompilation_client(),
    )
    .await?;
    let budget_amount = config.analysis.default_token_budget.min(200_000);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    // Open durable memory for cross-run learning
    let memory = skwaq_core::memory::MemoryStore::open_default()?;

    let results = pipeline
        .run_with_memory(
            &file_name,
            &inv_id,
            &db,
            skwaq_core::agents::PipelineClients::from_optional(
                reasoning_client,
                decompilation_client,
            ),
            &mut budget,
            &memory,
        )
        .await?;

    for result in &results {
        if let Some(parse_error) = &result.parsed_output_error {
            eprintln!(
                "  Warning: {} returned output that did not match schema {}: {}",
                result.agent_name,
                result
                    .context_frame
                    .output_schema
                    .as_deref()
                    .unwrap_or("unknown"),
                parse_error
            );
        }
    }

    let total_tokens: u64 = results.iter().map(|r| r.tokens_used).sum();
    println!(
        "  Agent pipeline: {} agents, {} tokens used",
        results.len(),
        total_tokens
    );

    // Print findings
    let mut stmt = db.conn().prepare(
        "SELECT title, severity, category FROM findings \
         WHERE investigation_id = ?1 AND status != 'invalidated' \
         ORDER BY CASE severity \
           WHEN 'critical' THEN 1 \
           WHEN 'high' THEN 2 \
           WHEN 'medium' THEN 3 \
           WHEN 'low' THEN 4 \
           ELSE 5 END",
    )?;

    let findings: Vec<(String, String, String)> = stmt
        .query_map([&inv_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, String>(2).unwrap_or_default(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    println!("\n======================================================================");
    println!("  INVESTIGATION FINDINGS: {} total", findings.len());
    println!("======================================================================\n");

    if findings.is_empty() {
        println!("  No vulnerabilities found.");
    } else {
        for (i, (title, severity, category)) in findings.iter().enumerate() {
            println!(
                "  {}. [{}] {} ({})",
                i + 1,
                severity.to_uppercase(),
                title,
                category
            );
        }
    }

    Ok(())
}
