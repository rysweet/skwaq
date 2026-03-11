//! Agentic analysis: multi-layer vulnerability detection pipeline.
//!
//! Combines pattern detection, dataflow analysis, and LLM-driven agent
//! reasoning to detect vulnerabilities like a security researcher would.
//!
//! Layer 1: Pattern detection (dangerous APIs, known-bad patterns)
//! Layer 2: Dataflow analysis (taint tracking source→sink)
//! Layer 3: Context validation (false positive reduction)
//! Layer 4: LLM agent pipeline (semantic reasoning about code)

use crate::adapters::DetectedFinding;
use skwaq_core::analysis::DangerousApiDetector;
use skwaq_core::config::Config;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::GraphDb;
use skwaq_core::source::parse_file;
use std::path::Path;

/// Run full agentic analysis on a source file.
///
/// Layers:
/// 1. Ingest source → build code property graph
/// 2. Pattern detection → store initial findings
/// 3. Multi-cycle orchestrator (dataflow + context validation)
/// 4. LLM agent pipeline (attack-surface → vuln-hunter → critic)
pub async fn run_agentic_source_analysis(
    path: &Path,
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let db = GraphDb::in_memory()?;
    let parsed = parse_file(path)?;

    let inv_id = format!("gym-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = path.to_string_lossy().to_string();

    // --- Layer 1: Ingest source into graph ---
    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &inv_id.as_str(),
            &file_str.as_str(),
            &file_str.as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;

    let builder = GraphBuilder::new(&db);
    let counts = builder.build_from_source(std::slice::from_ref(&parsed), &inv_id)?;
    tracing::debug!(
        "Ingested {}: {} functions, {} calls, {} sources, {} sinks",
        file_str,
        counts.functions,
        counts.calls,
        counts.sources,
        counts.sinks,
    );

    // --- Layer 2: Pattern detection ---
    let detector = DangerousApiDetector::new();
    if let Ok(hits) = detector.detect_in_source(path, &parsed.language) {
        for hit in &hits {
            let finding_id = uuid::Uuid::new_v4().to_string();
            if let Err(e) = db.execute(
                "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id, \
                 status, severity, category) \
                 VALUES (?1, ?2, ?3, 'source-pattern-detector', ?4, ?5, 'new', ?6, ?7)",
                &[
                    &finding_id.as_str(),
                    &format!(
                        "Dangerous pattern: {} ({}:{})",
                        hit.function_name, hit.file, hit.line
                    )
                    .as_str(),
                    &format!(
                        "category={}, severity={}, reason={}",
                        hit.danger_category, hit.severity, hit.reason
                    )
                    .as_str(),
                    &now.as_str(),
                    &inv_id.as_str(),
                    &hit.severity.to_string().to_lowercase().as_str(),
                    &hit.danger_category.to_string().as_str(),
                ],
            ) {
                tracing::warn!("Failed to store finding for {}: {}", hit.function_name, e);
            }
        }
    }

    // --- Layer 3: Multi-cycle orchestrator (dataflow + context validation) ---
    let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
    let _cycles = orchestrator.run_quick_analysis(&inv_id)?;

    // --- Layer 4: LLM agent pipeline ---
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await;

    // Collect all non-invalidated findings
    collect_findings_from_db(&db, &inv_id)
}

/// Run the LLM agent pipeline if ANTHROPIC_API_KEY is configured.
/// Gracefully degrades to pattern-only analysis if no API key is available.
async fn run_llm_pipeline(db: &GraphDb, inv_id: &str, file_str: &str, timeout_secs: u64) {
    let config = match Config::load() {
        Ok(c) => c,
        Err(_) => return,
    };

    let llm_client = match skwaq_core::llm::create_client(&config.llm).await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("LLM not available ({}), using pattern-only analysis", e);
            return;
        }
    };

    // Use the deep pipeline with multi-agent validation panel
    // (attack-surface → vuln-hunter → exploit-analyst → defense-analyst → cwe-classifier)
    let pipeline = skwaq_core::agents::deep_pipeline();
    let budget_amount = config.analysis.default_token_budget.min(100_000);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    let target = std::path::Path::new(file_str)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_str.to_string());

    tracing::info!("Running LLM agent pipeline on {}", target);

    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        pipeline.run(&target, inv_id, db, llm_client, &mut budget),
    )
    .await
    {
        Ok(Ok(results)) => {
            let total_tokens: u64 = results.iter().map(|r| r.tokens_used).sum();
            tracing::info!(
                "LLM pipeline completed for {}: {} agents, {} tokens",
                target,
                results.len(),
                total_tokens,
            );
        }
        Ok(Err(e)) => {
            tracing::warn!("LLM pipeline failed for {}: {}", file_str, e);
        }
        Err(_) => {
            tracing::warn!(
                "LLM pipeline timed out for {} after {}s",
                file_str,
                timeout_secs
            );
        }
    }
}

/// Extract findings from the DB after all analysis layers complete.
fn collect_findings_from_db(
    db: &GraphDb,
    investigation_id: &str,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, title, severity, category FROM findings \
         WHERE investigation_id = ?1 AND status != 'invalidated'",
    )?;

    let findings = stmt
        .query_map(rusqlite::params![investigation_id], |row| {
            let id: String = row.get(0)?;
            let title: String = row.get(1)?;
            let severity: String = row.get(2).unwrap_or_default();
            let category: String = row.get(3).unwrap_or_default();

            Ok(DetectedFinding {
                id,
                category,
                severity,
                cwes: vec![],
                file: String::new(),
                function: extract_function_from_title(&title),
                line: None,
                title,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(findings)
}

fn extract_function_from_title(title: &str) -> String {
    if let Some(start) = title.find(": ") {
        let rest = &title[start + 2..];
        if let Some(end) = rest.find(' ') {
            return rest[..end].to_string();
        }
        return rest.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> std::path::PathBuf {
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop();
        dir.pop();
        dir.join("tests/fixtures")
    }

    #[test]
    fn test_sync_layers_buffer_overflow() {
        let fixture = fixtures_dir().join("buffer_overflow.c");
        if !fixture.exists() {
            return;
        }

        let db = GraphDb::in_memory().unwrap();
        let parsed = parse_file(&fixture).unwrap();
        let inv_id = "test-sync";
        let now = chrono::Utc::now().to_rfc3339();

        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
            &[&inv_id, &"test", &"test", &now.as_str(), &now.as_str()],
        )
        .unwrap();

        let builder = GraphBuilder::new(&db);
        builder
            .build_from_source(std::slice::from_ref(&parsed), inv_id)
            .unwrap();

        let detector = DangerousApiDetector::new();
        let hits = detector
            .detect_in_source(&fixture, &parsed.language)
            .unwrap();
        assert!(
            !hits.is_empty(),
            "Pattern detector should find dangerous APIs"
        );

        let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
        let cycles = orchestrator.run_quick_analysis(inv_id).unwrap();
        assert!(
            !cycles.is_empty(),
            "Orchestrator should run at least one cycle"
        );
    }

    #[test]
    fn test_sync_layers_command_injection() {
        let fixture = fixtures_dir().join("command_injection.c");
        if !fixture.exists() {
            return;
        }

        let db = GraphDb::in_memory().unwrap();
        let parsed = parse_file(&fixture).unwrap();
        let inv_id = "test-injection";
        let now = chrono::Utc::now().to_rfc3339();

        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
            &[&inv_id, &"test", &"test", &now.as_str(), &now.as_str()],
        )
        .unwrap();

        let builder = GraphBuilder::new(&db);
        builder
            .build_from_source(std::slice::from_ref(&parsed), inv_id)
            .unwrap();

        let detector = DangerousApiDetector::new();
        let hits = detector
            .detect_in_source(&fixture, &parsed.language)
            .unwrap();
        let has_injection = hits
            .iter()
            .any(|h| h.danger_category.to_string() == "injection");
        assert!(
            has_injection,
            "Should detect injection pattern in command_injection.c"
        );
    }

    #[tokio::test]
    async fn test_full_agentic_analysis() {
        let fixture = fixtures_dir().join("buffer_overflow.c");
        if !fixture.exists() {
            return;
        }

        let findings = run_agentic_source_analysis(&fixture, 30).await.unwrap();
        assert!(!findings.is_empty(), "Should produce findings");
        let has_memory = findings.iter().any(|f| f.category == "memory");
        assert!(has_memory, "Should detect memory category");
    }
}
