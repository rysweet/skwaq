//! `skwaq investigate <binary>` — interactive binary investigation with AI agents.
//!
//! Starts a Ghidra headless session (if available), ingests the binary into the
//! graph, and runs the full agent pipeline with optional MCP tool access.

use std::path::Path;

/// Run interactive investigation on a binary.
pub async fn run(binary: &Path) -> anyhow::Result<()> {
    use skwaq_core::agents::mcp_client::McpServerRegistry;
    use skwaq_core::binary::native::parse_binary;
    use skwaq_core::graph::builder::GraphBuilder;
    use skwaq_core::graph::GraphDb;

    println!("Investigating binary: {}", binary.display());

    // Parse binary with goblin (always available)
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

    // Try Ghidra enrichment if available
    let ghidra_path = skwaq_core::binary::ghidra::GhidraRunner::find_ghidra();
    let ghidra_runner = skwaq_core::binary::ghidra::GhidraRunner::new(ghidra_path.clone());
    if ghidra_path.is_some() {
        println!("  Ghidra found — running decompilation analysis...");
        match ghidra_runner.analyze(binary, 600).await {
            Ok(analysis) => {
                let ghidra_counts = builder.build_from_ghidra_analysis(&analysis, &inv_id)?;
                println!(
                    "  Ghidra enrichment: {} functions updated, {} added, {} calls",
                    ghidra_counts.functions_updated,
                    ghidra_counts.functions_added,
                    ghidra_counts.calls_added
                );
            }
            Err(e) => {
                println!(
                    "  Ghidra analysis failed: {} (continuing without decompilation)",
                    e
                );
            }
        }
    } else {
        println!("  Ghidra not available — using native analysis only");
        println!("    Install: https://ghidra-sre.org/ and set GHIDRA_INSTALL_DIR");
    }

    // Check for GhidraMCP server availability
    let mcp_registry = McpServerRegistry::new();
    if mcp_registry.is_server_available("ghidra") {
        println!("  GhidraMCP server found — agents can decompile on-demand");
    }

    // Run pattern detection
    println!("\n  Running pattern analysis...");
    let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
    let cycles = orchestrator.run_quick_analysis(&inv_id)?;
    println!("  Pattern analysis: {} cycles completed", cycles.len());

    // Run LLM agent pipeline if available
    let config = match skwaq_core::config::Config::load() {
        Ok(c) => c,
        Err(_) => {
            println!("\n  No LLM configured. Pattern-only analysis complete.");
            print_findings(&db, &inv_id)?;
            return Ok(());
        }
    };

    let llm_client = match skwaq_core::llm::create_client(&config.llm).await {
        Ok(c) => c,
        Err(e) => {
            println!(
                "\n  LLM not available ({}). Pattern-only analysis complete.",
                e
            );
            print_findings(&db, &inv_id)?;
            return Ok(());
        }
    };

    println!("  Running AI agent pipeline...");
    let pipeline = skwaq_core::agents::deep_pipeline();
    let budget_amount = config.analysis.default_token_budget.min(200_000);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    let file_name = binary
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| target.clone());

    match tokio::time::timeout(
        std::time::Duration::from_secs(1800),
        pipeline.run(&file_name, &inv_id, &db, llm_client, &mut budget),
    )
    .await
    {
        Ok(Ok(results)) => {
            let total_tokens: u64 = results.iter().map(|r| r.tokens_used).sum();
            println!(
                "  Agent pipeline: {} agents, {} tokens used",
                results.len(),
                total_tokens
            );
        }
        Ok(Err(e)) => {
            println!("  Agent pipeline failed: {}", e);
        }
        Err(_) => {
            println!("  Agent pipeline timed out after 30 minutes");
        }
    }

    print_findings(&db, &inv_id)?;
    Ok(())
}

fn print_findings(db: &skwaq_core::graph::GraphDb, inv_id: &str) -> anyhow::Result<()> {
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
        .query_map([inv_id], |row| {
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
