//! CLI command for `skwaq diff-analyze`: compare two binary versions
//! and analyze security-relevant differences using AI agents.

use std::path::Path;

/// Run diff-analyze: ingest both binaries, diff functions, analyze with AI.
pub async fn run(v1: &Path, v2: &Path, advisory: Option<&str>) -> anyhow::Result<()> {
    use skwaq_core::binary::native::parse_binary;
    use skwaq_core::graph::builder::GraphBuilder;
    use skwaq_core::graph::GraphDb;

    println!("Analyzing differences between binaries...");
    println!("  v1: {}", v1.display());
    println!("  v2: {}", v2.display());

    // Parse both binaries
    let info_v1 = parse_binary(v1)?;
    let info_v2 = parse_binary(v2)?;

    // Compute function-level diff
    let diff = compute_function_diff(&info_v1, &info_v2);

    println!("\nFunction diff summary:");
    println!("  Added:   {} functions", diff.added.len());
    println!("  Removed: {} functions", diff.removed.len());
    println!("  Changed: {} functions", diff.changed.len());

    if diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty() {
        println!("\nNo function-level differences detected.");
        return Ok(());
    }

    // Create investigation and populate graph with both versions
    let db = GraphDb::in_memory()?;
    let inv_id = format!("diff-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();

    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &format!("diff: {} vs {}", v1.display(), v2.display()).as_str(),
            &v1.to_string_lossy().to_string().as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    // Ingest v2 (the newer version) as the primary analysis target
    let builder = GraphBuilder::new(&db);
    builder.build_from_binary_info(&info_v2, &inv_id)?;

    // Build diff context for the agent
    let mut context = String::new();
    context.push_str("# Binary Patch Diff Analysis\n\n");

    if let Some(adv) = advisory {
        context.push_str(&format!("## Security Advisory\n{}\n\n", adv));
    }

    context.push_str("## Function-Level Diff\n\n");

    if !diff.added.is_empty() {
        context.push_str("### Added Functions\n");
        for name in &diff.added {
            context.push_str(&format!("- {}\n", name));
        }
        context.push('\n');
    }

    if !diff.removed.is_empty() {
        context.push_str("### Removed Functions\n");
        for name in &diff.removed {
            context.push_str(&format!("- {}\n", name));
        }
        context.push('\n');
    }

    if !diff.changed.is_empty() {
        context.push_str("### Changed Functions\n");
        for name in &diff.changed {
            context.push_str(&format!("- {}\n", name));
        }
        context.push('\n');
    }

    context.push_str(
        "\nAnalyze the changed functions for security relevance. \
         Use read_function to examine each changed function's code, \
         then use create_finding for any security-relevant changes you discover.\n",
    );

    // Run the patch-diff-analyst agent — LLM is required
    let config = skwaq_core::config::Config::load()?;
    let llm_client = skwaq_core::llm::create_client(&config.llm).await?;

    let agent = skwaq_core::agents::definition::load_agent("patch-diff-analyst")?;

    // Inject skill context
    let budget_amount = config.analysis.default_token_budget.min(100_000);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    let runner = skwaq_core::agents::runner::AgentRunner::new(llm_client);
    let result = runner
        .run_agent_with_db(&agent, &inv_id, &context, &db, &mut budget)
        .await?;

    println!("\n{}", result.output);
    println!("\n({} tokens used)", result.tokens_used);

    // Collect and display findings
    let mut stmt = db
        .conn()
        .prepare("SELECT title, severity, category FROM findings WHERE investigation_id = ?1")?;
    let findings: Vec<(String, String, String)> = stmt
        .query_map([&inv_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, String>(2).unwrap_or_default(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if !findings.is_empty() {
        println!("\n## Security Findings\n");
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

/// Result of comparing functions between two binary versions.
struct FunctionDiff {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

/// Compare functions between two binary versions.
fn compute_function_diff(
    v1: &skwaq_core::binary::types::BinaryInfo,
    v2: &skwaq_core::binary::types::BinaryInfo,
) -> FunctionDiff {
    use std::collections::{HashMap, HashSet};

    // Build name→address maps from symbols
    let v1_funcs: HashMap<&str, u64> = v1
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "2" || s.symbol_type.contains("Func"))
        .filter(|s| !s.name.is_empty() && s.address != 0)
        .map(|s| (s.name.as_str(), s.address))
        .collect();

    let v2_funcs: HashMap<&str, u64> = v2
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "2" || s.symbol_type.contains("Func"))
        .filter(|s| !s.name.is_empty() && s.address != 0)
        .map(|s| (s.name.as_str(), s.address))
        .collect();

    let v1_names: HashSet<&str> = v1_funcs.keys().copied().collect();
    let v2_names: HashSet<&str> = v2_funcs.keys().copied().collect();

    let added: Vec<String> = v2_names
        .difference(&v1_names)
        .map(|s| s.to_string())
        .collect();

    let removed: Vec<String> = v1_names
        .difference(&v2_names)
        .map(|s| s.to_string())
        .collect();

    // "Changed" = present in both but at different addresses (recompilation shifts)
    // This is a heuristic — same name, different address suggests code change
    let changed: Vec<String> = v1_names
        .intersection(&v2_names)
        .filter(|name| {
            let a1 = v1_funcs.get(*name).unwrap_or(&0);
            let a2 = v2_funcs.get(*name).unwrap_or(&0);
            a1 != a2
        })
        .map(|s| s.to_string())
        .collect();

    FunctionDiff {
        added,
        removed,
        changed,
    }
}
