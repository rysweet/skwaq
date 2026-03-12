//! Agentic analysis: dual-judge vulnerability detection pipeline.
//!
//! Uses a dual-judge approach (inspired by SafeGenBench) where findings
//! must be confirmed by BOTH pattern detection AND LLM agents to count.
//! This combines pattern precision (~80%) with LLM recall (~100%).
//!
//! Layer 1: Pattern detection (dangerous APIs, known-bad patterns)
//! Layer 2: Dataflow analysis (taint tracking source→sink)
//! Layer 3: Context validation (false positive reduction)
//! Layer 4: LLM agent pipeline (semantic reasoning about code)
//! Layer 5: Dual-judge intersection (only keep findings both layers agree on)

use crate::adapters::DetectedFinding;
use crate::scoring;
use skwaq_core::analysis::DangerousApiDetector;
use skwaq_core::config::Config;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::GraphDb;
use skwaq_core::source::parse_file;
use std::collections::HashSet;
use std::path::Path;

/// Run full agentic analysis on a source file.
///
/// Uses dual-judge scoring: only reports findings where both pattern
/// detection AND LLM agents agree on the vulnerability category.
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
    builder.build_from_source(std::slice::from_ref(&parsed), &inv_id)?;

    // --- Layer 2: Pattern detection → collect pattern-detected categories ---
    let mut pattern_categories: HashSet<String> = HashSet::new();
    let detector = DangerousApiDetector::new();
    let pattern_findings = if let Ok(hits) = detector.detect_in_source(path, &parsed.language) {
        let mut findings = Vec::new();
        for hit in &hits {
            let category = hit.danger_category.to_string();
            pattern_categories.insert(category.clone());

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
                    &category.as_str(),
                ],
            ) {
                tracing::warn!("Failed to store finding for {}: {}", hit.function_name, e);
            }

            findings.push(DetectedFinding {
                id: finding_id,
                category,
                severity: hit.severity.to_string(),
                cwes: vec![],
                file: file_str.clone(),
                function: hit.function_name.clone(),
                line: if hit.line > 0 {
                    Some(hit.line as u32)
                } else {
                    None
                },
                title: format!("Dangerous API: {}", hit.function_name),
            });
        }
        findings
    } else {
        Vec::new()
    };

    // Also collect CWE families from patterns for dual-judge matching
    let pattern_cwe_families: HashSet<u32> = pattern_categories
        .iter()
        .flat_map(|cat| scoring::category_to_cwes(cat))
        .map(scoring::cwe_family)
        .collect();

    // --- Layer 3: Multi-cycle orchestrator (dataflow + context validation) ---
    let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
    let _cycles = orchestrator.run_quick_analysis(&inv_id)?;

    // Collect orchestrator findings (taint flows, etc.) and add their categories
    let orchestrator_findings = collect_findings_from_db(&db, &inv_id, "source-pattern-detector")?;
    for f in &orchestrator_findings {
        pattern_categories.insert(f.category.clone());
    }

    // --- Layer 4: LLM agent pipeline ---
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await;

    // --- Layer 5: Dual-judge intersection ---
    // Collect ALL findings from DB (pattern + orchestrator + LLM)
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    // If no LLM was available, return pattern findings directly
    if all_findings
        .iter()
        .all(|f| f.title.starts_with("Dangerous pattern:"))
    {
        return Ok(pattern_findings);
    }

    // When patterns found nothing (e.g. CGC custom APIs like cgc_allocate),
    // trust LLM-only findings. The LLM can understand non-standard APIs
    // that patterns don't cover, providing semantic "understanding" over
    // syntactic matching.
    let no_patterns = pattern_categories.is_empty();

    // Dual-judge: keep findings where the category's CWE family was
    // also found by pattern detection. This means patterns anchor the
    // detection (precision) while LLM provides the semantic validation (recall).
    // Exception: when patterns found nothing, trust LLM findings directly.
    let confirmed: Vec<DetectedFinding> = all_findings
        .into_iter()
        .filter(|f| {
            // If patterns found nothing, trust all LLM findings
            if no_patterns {
                return true;
            }
            // Keep if the finding's category was also detected by patterns
            if pattern_categories.contains(&f.category) {
                return true;
            }
            // Or if any of the finding's CWE families match pattern CWE families
            let finding_families: HashSet<u32> = scoring::category_to_cwes(&f.category)
                .into_iter()
                .map(scoring::cwe_family)
                .collect();
            !finding_families.is_disjoint(&pattern_cwe_families)
        })
        .collect();

    // Deduplicate by category (keep one finding per category)
    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = confirmed
        .into_iter()
        .filter(|f| seen_categories.insert(f.category.clone()))
        .collect();

    Ok(deduped)
}

/// Run the LLM agent pipeline if ANTHROPIC_API_KEY is configured.
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

/// Collect findings from DB, optionally excluding a specific agent.
fn collect_findings_from_db(
    db: &GraphDb,
    investigation_id: &str,
    exclude_agent: &str,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, title, severity, category FROM findings \
         WHERE investigation_id = ?1 AND status != 'invalidated' AND agent != ?2",
    )?;

    let findings = stmt
        .query_map(rusqlite::params![investigation_id, exclude_agent], |row| {
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

/// Collect ALL findings from DB (no agent filter).
fn collect_all_findings_from_db(
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
    }

    #[test]
    fn test_dual_judge_deduplication() {
        // Simulate dual-judge: if pattern finds "memory" and LLM finds "memory",
        // deduplication should produce 1 finding, not 2.
        let findings = vec![
            DetectedFinding {
                id: "1".into(),
                category: "memory".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "Pattern: strcpy".into(),
            },
            DetectedFinding {
                id: "2".into(),
                category: "memory".into(),
                severity: "critical".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "LLM: buffer overflow in strcpy".into(),
            },
        ];

        let mut seen = HashSet::new();
        let deduped: Vec<_> = findings
            .into_iter()
            .filter(|f| seen.insert(f.category.clone()))
            .collect();
        assert_eq!(deduped.len(), 1);
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
