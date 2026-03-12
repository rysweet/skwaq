//! Agentic analysis: synthesis-based vulnerability detection pipeline.
//!
//! Uses a synthesis approach where an LLM weighs ALL evidence from both
//! pattern detection and LLM agents to decide which findings are credible.
//! This replaces the old intersection filter that discarded LLM-only findings.
//!
//! Layer 1: Pattern detection (dangerous APIs, known-bad patterns)
//! Layer 2: Dataflow analysis (taint tracking source→sink)
//! Layer 3: Context validation (false positive reduction)
//! Layer 4: LLM agent pipeline (semantic reasoning about code)
//! Layer 5: Synthesis (LLM weighs all evidence to select credible findings)

use crate::adapters::DetectedFinding;
use crate::scoring;
use skwaq_core::analysis::DangerousApiDetector;
use skwaq_core::config::Config;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::GraphDb;
use skwaq_core::source::parse_file;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

/// Tracks how many cases used LLM synthesis vs. deterministic fallback.
///
/// Thread-safe counters for use across concurrent gym case execution.
/// Call [`SynthesisStats::report`] at end of a gym run to log the summary.
pub struct SynthesisStats {
    llm_synthesis_count: AtomicU32,
    fallback_count: AtomicU32,
}

impl Default for SynthesisStats {
    fn default() -> Self {
        Self {
            llm_synthesis_count: AtomicU32::new(0),
            fallback_count: AtomicU32::new(0),
        }
    }
}

impl SynthesisStats {
    pub fn new() -> Self {
        Self::default()
    }

    fn record_llm_synthesis(&self) {
        self.llm_synthesis_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_fallback(&self) {
        self.fallback_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Log end-of-run synthesis summary. Call after all cases complete.
    pub fn report(&self) {
        let llm = self.llm_synthesis_count.load(Ordering::Relaxed);
        let fallback = self.fallback_count.load(Ordering::Relaxed);
        let total = llm + fallback;
        if total == 0 {
            tracing::info!("Synthesis: no dual-source cases (nothing to synthesize)");
            return;
        }
        if fallback > 0 {
            tracing::warn!(
                "Synthesis summary: {}/{} cases used LLM synthesis, {} used deterministic fallback",
                llm,
                total,
                fallback,
            );
            eprintln!(
                "\n  WARNING: {}/{} synthesis cases fell back to deterministic merge.\n  \
                 LLM synthesis may not be working. Check warnings above.\n",
                fallback, total,
            );
        } else {
            tracing::info!(
                "Synthesis summary: {}/{} cases used LLM synthesis (all successful)",
                llm,
                total,
            );
        }
    }
}

/// Global synthesis stats for the current gym run.
static SYNTHESIS_STATS: std::sync::LazyLock<SynthesisStats> =
    std::sync::LazyLock::new(SynthesisStats::new);

/// Get the global synthesis stats. Call [`SynthesisStats::report`] at end of run.
pub fn synthesis_stats() -> &'static SynthesisStats {
    &SYNTHESIS_STATS
}

/// Run full agentic analysis on a source file.
///
/// Uses synthesis scoring: an LLM weighs evidence from both pattern
/// detection and agent findings to decide which are credible.
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
    let _pattern_cwe_families: HashSet<u32> = pattern_categories
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

    // --- Layer 5: Synthesis — weigh all evidence ---
    // Collect ALL findings from DB (pattern + orchestrator + LLM)
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    // If no LLM was available, return pattern findings directly
    if all_findings
        .iter()
        .all(|f| f.title.starts_with("Dangerous pattern:"))
    {
        return Ok(pattern_findings);
    }

    // Synthesize: use LLM to weigh all evidence and decide which findings are credible.
    // Unlike the old intersection filter, this preserves LLM-only findings that
    // demonstrate real understanding of the code.
    let synthesized =
        synthesize_findings(all_findings, &pattern_categories, &db, timeout_secs).await;

    // Deduplicate by category (keep one finding per category)
    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = synthesized
        .into_iter()
        .filter(|f| seen_categories.insert(f.category.clone()))
        .collect();

    Ok(deduped)
}

/// Run full agentic analysis on a compiled binary.
///
/// Parses the binary with goblin, populates the graph, runs pattern
/// detection on imports, then (optionally) runs the LLM agent pipeline.
pub async fn run_agentic_binary_analysis(
    path: &Path,
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::binary::native::parse_binary;

    let db = GraphDb::in_memory()?;
    let binary_info = parse_binary(path)?;

    let inv_id = format!("gym-bin-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = path.to_string_lossy().to_string();

    // Create investigation
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

    // Ingest binary into graph
    let builder = GraphBuilder::new(&db);
    builder.build_from_binary_info(&binary_info, &inv_id)?;

    // Pattern detection on imports
    let mut pattern_categories: HashSet<String> = HashSet::new();
    let detector = DangerousApiDetector::new();
    let import_hits = detector.check_imports(&binary_info.imports);

    let mut pattern_findings = Vec::new();
    for hit in &import_hits {
        let category = hit.danger_category.to_string();
        pattern_categories.insert(category.clone());

        let finding_id = uuid::Uuid::new_v4().to_string();
        let _ = db.execute(
            "INSERT INTO findings (id, title, evidence, agent, timestamp, investigation_id, \
             status, severity, category) \
             VALUES (?1, ?2, ?3, 'binary-pattern-detector', ?4, ?5, 'new', ?6, ?7)",
            &[
                &finding_id.as_str(),
                &format!("Binary import: {} ({})", hit.function_name, hit.library).as_str(),
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
        );

        pattern_findings.push(DetectedFinding {
            id: finding_id,
            category,
            severity: hit.severity.to_string(),
            cwes: vec![],
            file: file_str.clone(),
            function: hit.function_name.clone(),
            line: None,
            title: format!("Binary import: {}", hit.function_name),
        });
    }

    // Collect CWE families from patterns
    let _pattern_cwe_families: HashSet<u32> = pattern_categories
        .iter()
        .flat_map(|cat| scoring::category_to_cwes(cat))
        .map(scoring::cwe_family)
        .collect();

    // Multi-cycle orchestrator (taint analysis on graph)
    let orchestrator = skwaq_core::analysis::AnalysisOrchestrator::new(&db, 3);
    let _cycles = orchestrator.run_quick_analysis(&inv_id)?;

    let orchestrator_findings = collect_findings_from_db(&db, &inv_id, "binary-pattern-detector")?;
    for f in &orchestrator_findings {
        pattern_categories.insert(f.category.clone());
    }

    // LLM agent pipeline
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await;

    // Synthesis — weigh all evidence
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    if all_findings
        .iter()
        .all(|f| f.title.starts_with("Binary import:"))
    {
        return Ok(pattern_findings);
    }

    let synthesized =
        synthesize_findings(all_findings, &pattern_categories, &db, timeout_secs).await;

    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = synthesized
        .into_iter()
        .filter(|f| seen_categories.insert(f.category.clone()))
        .collect();

    Ok(deduped)
}

/// Run LLM-only analysis on a source file (no pattern detection).
///
/// Skips pattern detection entirely and relies solely on the LLM agent
/// pipeline. This measures what the agents actually UNDERSTAND about
/// vulnerability semantics, independent of pattern matching.
pub async fn run_llm_only_source_analysis(
    path: &Path,
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let db = GraphDb::in_memory()?;
    let parsed = parse_file(path)?;

    let inv_id = format!("gym-llm-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = path.to_string_lossy().to_string();

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

    // Skip pattern detection — go straight to LLM pipeline
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await;

    // Return all LLM findings directly (no intersection filter)
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    // Deduplicate by category
    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = all_findings
        .into_iter()
        .filter(|f| seen_categories.insert(f.category.clone()))
        .collect();

    Ok(deduped)
}

/// Run LLM-only analysis on a compiled binary (no pattern detection).
pub async fn run_llm_only_binary_analysis(
    path: &Path,
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    use skwaq_core::binary::native::parse_binary;

    let db = GraphDb::in_memory()?;
    let binary_info = parse_binary(path)?;

    let inv_id = format!("gym-llm-bin-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = path.to_string_lossy().to_string();

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
    builder.build_from_binary_info(&binary_info, &inv_id)?;

    // Skip pattern detection — go straight to LLM pipeline
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await;

    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = all_findings
        .into_iter()
        .filter(|f| seen_categories.insert(f.category.clone()))
        .collect();

    Ok(deduped)
}

/// Synthesize findings from both pattern detection and LLM agents.
///
/// Models how a human security team works:
/// - Junior analysts (patterns) flag potential issues
/// - Senior researchers (LLM agents) investigate deeply
/// - Lead reviewer (this function) makes final call, weighing all evidence
///
/// Synthesize findings from pattern detection and LLM agents.
///
/// Models how a lead security reviewer works:
/// - Receives reports from junior analysts (pattern detection) and
///   senior researchers (LLM agents)
/// - Uses judgment to CONFIRM or REJECT each finding
///
/// When an LLM is available, calls it to evaluate all findings together.
/// Falls back to deterministic merge (LLM-priority union) when unavailable.
async fn synthesize_findings(
    all_findings: Vec<DetectedFinding>,
    _pattern_categories: &HashSet<String>,
    _db: &GraphDb,
    timeout_secs: u64,
) -> Vec<DetectedFinding> {
    if all_findings.is_empty() {
        return all_findings;
    }

    // Classify findings by source
    let mut pattern_findings = Vec::new();
    let mut llm_findings = Vec::new();

    for f in &all_findings {
        if f.title.starts_with("Dangerous pattern:") || f.title.starts_with("Binary import:") {
            pattern_findings.push(f.clone());
        } else {
            llm_findings.push(f.clone());
        }
    }

    // If only one source produced findings, trust it directly
    if pattern_findings.is_empty() || llm_findings.is_empty() {
        return all_findings;
    }

    // Both sources have findings — attempt LLM synthesis
    match llm_synthesize(&pattern_findings, &llm_findings, timeout_secs).await {
        Some(synthesized) => {
            SYNTHESIS_STATS.record_llm_synthesis();
            synthesized
        }
        None => {
            SYNTHESIS_STATS.record_fallback();
            // Fallback: deterministic merge with LLM priority
            merge_findings_deterministic(all_findings)
        }
    }
}

/// Call the LLM to evaluate findings like a lead security reviewer.
///
/// Returns None if LLM is unavailable (caller should fall back).
/// Logs WARN on every failure path so problems are visible.
async fn llm_synthesize(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    timeout_secs: u64,
) -> Option<Vec<DetectedFinding>> {
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("LLM synthesis unavailable: config load failed: {}", e);
            eprintln!(
                "  WARNING: LLM synthesis unavailable (config load failed: {}), using merge fallback",
                e
            );
            return None;
        }
    };
    let client = match skwaq_core::llm::create_client(&config.llm).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("LLM synthesis unavailable: client creation failed: {}", e);
            eprintln!(
                "  WARNING: LLM synthesis unavailable (client creation failed: {}), using merge fallback",
                e
            );
            return None;
        }
    };

    // Build the synthesis prompt
    let mut prompt = String::from(
        "You are a lead security reviewer evaluating vulnerability findings from two sources:\n\
         1. PATTERN DETECTION (automated regex-based, high precision, limited understanding)\n\
         2. LLM AGENTS (AI-powered deep analysis, better understanding, may hallucinate)\n\n\
         Your job: decide which findings are REAL vulnerabilities.\n\n\
         For each finding, respond with one line:\n\
         CONFIRM <id> — strong evidence from one or both sources\n\
         REJECT <id> — insufficient evidence, likely false positive\n\n\
         Only REJECT findings where you are confident they are false positives.\n\
         When in doubt, CONFIRM.\n\n",
    );

    prompt.push_str("=== PATTERN FINDINGS ===\n");
    for f in pattern_findings {
        // Sanitize titles to prevent prompt injection from finding content
        let safe_title = sanitize_for_prompt(&f.title);
        prompt.push_str(&format!(
            "ID: {} | Category: {} | Severity: {} | {}\n",
            f.id, f.category, f.severity, safe_title
        ));
    }

    prompt.push_str("\n=== LLM AGENT FINDINGS ===\n");
    for f in llm_findings {
        let safe_title = sanitize_for_prompt(&f.title);
        prompt.push_str(&format!(
            "ID: {} | Category: {} | Severity: {} | {}\n",
            f.id, f.category, f.severity, safe_title
        ));
    }

    prompt.push_str("\nEvaluate each finding. Respond with CONFIRM or REJECT for each ID.\n");

    // Budget scales with number of findings to evaluate
    let budget_amount = config
        .analysis
        .default_token_budget
        .min(10_000 + (pattern_findings.len() + llm_findings.len()) as u64 * 500);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);
    let model = &config.llm.copilot.model;

    // Use execute_with_tools with no tools for a simple completion
    let noop_executor = |_name: String, _args: serde_json::Value| async move {
        Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({"error": "no tools"}))
    };

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        skwaq_core::llm::execute_with_tools(
            &client,
            model,
            "You are a lead security reviewer evaluating vulnerability findings.",
            &prompt,
            &[],
            noop_executor,
            &mut budget,
        ),
    )
    .await;

    let response_text = match result {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => {
            tracing::warn!("LLM synthesis call failed: {}", e);
            eprintln!(
                "  WARNING: LLM synthesis call failed ({}), using merge fallback",
                e
            );
            return None;
        }
        Err(_) => {
            tracing::warn!("LLM synthesis timed out after {}s", timeout_secs);
            eprintln!(
                "  WARNING: LLM synthesis timed out after {}s, using merge fallback",
                timeout_secs
            );
            return None;
        }
    };

    // Parse and apply synthesis decisions
    let synthesized = apply_synthesis_decisions(pattern_findings, llm_findings, &response_text);

    Some(synthesized)
}

/// Sanitize a string for safe inclusion in an LLM prompt.
/// Strips control characters and truncates to prevent prompt injection.
fn sanitize_for_prompt(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(200) // Truncate long titles
        .collect::<String>()
        .replace("===", "---") // Prevent section marker injection
}

/// Parse LLM synthesis response and apply CONFIRM/REJECT decisions.
///
/// Pure function — no I/O, fully testable.
/// Default behavior: CONFIRM all (only explicit REJECT removes findings).
fn apply_synthesis_decisions(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    response_text: &str,
) -> Vec<DetectedFinding> {
    // Parse REJECT decisions (CONFIRM is the default — unlisted = confirmed)
    let rejected_ids: HashSet<String> = response_text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim().to_uppercase();
            if trimmed.starts_with("REJECT") {
                // Extract ID: "REJECT abc-123" or "REJECT abc-123 — reason"
                trimmed
                    .split_whitespace()
                    .nth(1)
                    .map(|id| id.to_lowercase()) // Normalize case for matching
            } else {
                None
            }
        })
        .collect();

    let total = pattern_findings.len() + llm_findings.len();
    tracing::info!(
        "LLM synthesis: {} rejected out of {} total findings",
        rejected_ids.len(),
        total
    );

    // Keep all non-rejected findings, deduplicated by category
    // LLM findings first (they represent deeper analysis)
    let mut seen_categories: HashSet<String> = HashSet::new();
    let mut synthesized: Vec<DetectedFinding> = Vec::new();

    for f in llm_findings {
        if !rejected_ids.contains(&f.id.to_lowercase())
            && seen_categories.insert(f.category.clone())
        {
            synthesized.push(f.clone());
        }
    }
    for f in pattern_findings {
        if !rejected_ids.contains(&f.id.to_lowercase())
            && seen_categories.insert(f.category.clone())
        {
            synthesized.push(f.clone());
        }
    }

    synthesized
}

/// Deterministic merge fallback: LLM-priority union with deduplication.
/// Used when the LLM synthesis call is unavailable.
fn merge_findings_deterministic(all_findings: Vec<DetectedFinding>) -> Vec<DetectedFinding> {
    let mut synthesized = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    // First pass: add all LLM findings
    for f in &all_findings {
        if !f.title.starts_with("Dangerous pattern:")
            && !f.title.starts_with("Binary import:")
            && seen_ids.insert(f.id.clone())
        {
            synthesized.push(f.clone());
        }
    }

    // Second pass: add pattern findings for uncovered categories
    let llm_categories: HashSet<String> = synthesized.iter().map(|f| f.category.clone()).collect();
    for f in &all_findings {
        if (f.title.starts_with("Dangerous pattern:") || f.title.starts_with("Binary import:"))
            && !llm_categories.contains(&f.category)
            && seen_ids.insert(f.id.clone())
        {
            synthesized.push(f.clone());
        }
    }

    synthesized
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
            tracing::warn!("LLM not available ({}), using pattern-only analysis", e);
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

    #[test]
    fn test_merge_findings_pattern_only() {
        let findings = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let result = merge_findings_deterministic(findings);
        assert_eq!(result.len(), 1, "Pattern-only: should keep all");
    }

    #[test]
    fn test_merge_findings_llm_only() {
        let findings = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "LLM: buffer overflow in strcpy".into(),
        }];
        let result = merge_findings_deterministic(findings);
        assert_eq!(result.len(), 1, "LLM-only: should keep all");
    }

    #[test]
    fn test_merge_findings_overlapping_categories() {
        // Both sources find "memory" — should deduplicate to 1 finding (LLM preferred)
        let findings = vec![
            DetectedFinding {
                id: "p1".into(),
                category: "memory".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "Dangerous pattern: strcpy".into(),
            },
            DetectedFinding {
                id: "l1".into(),
                category: "memory".into(),
                severity: "critical".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "LLM: buffer overflow with taint path".into(),
            },
        ];
        let result = merge_findings_deterministic(findings);
        assert_eq!(result.len(), 1, "Overlapping: should deduplicate");
        assert!(
            result[0].title.starts_with("LLM:"),
            "LLM finding should be preferred"
        );
    }

    #[test]
    fn test_merge_findings_disjoint_categories() {
        // Pattern finds "memory", LLM finds "injection" — keep both
        let findings = vec![
            DetectedFinding {
                id: "p1".into(),
                category: "memory".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "Dangerous pattern: strcpy".into(),
            },
            DetectedFinding {
                id: "l1".into(),
                category: "injection".into(),
                severity: "critical".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "system".into(),
                line: Some(20),
                title: "LLM: command injection via user input".into(),
            },
        ];
        let result = merge_findings_deterministic(findings);
        assert_eq!(result.len(), 2, "Disjoint: should keep both");
    }

    #[tokio::test]
    async fn test_synthesize_findings_empty() {
        let db = GraphDb::in_memory().unwrap();
        let cats = HashSet::new();
        let result = synthesize_findings(vec![], &cats, &db, 30).await;
        assert!(result.is_empty());
    }

    #[test]
    fn test_apply_synthesis_confirm_all() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "f".into(),
            line: Some(1),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "injection".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "g".into(),
            line: Some(2),
            title: "LLM: command injection".into(),
        }];
        let response = "CONFIRM p1\nCONFIRM l1\n";
        let result = apply_synthesis_decisions(&pattern, &llm, response);
        assert_eq!(result.len(), 2, "Both confirmed → keep both");
    }

    #[test]
    fn test_apply_synthesis_reject_one() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "f".into(),
            line: Some(1),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "injection".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "g".into(),
            line: Some(2),
            title: "LLM: command injection".into(),
        }];
        let response = "CONFIRM l1\nREJECT p1 — insufficient evidence\n";
        let result = apply_synthesis_decisions(&pattern, &llm, response);
        assert_eq!(result.len(), 1, "One rejected → only 1 remains");
        assert_eq!(result[0].id, "l1");
    }

    #[test]
    fn test_apply_synthesis_empty_response() {
        // Malformed/empty response → keep everything (default CONFIRM)
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "f".into(),
            line: Some(1),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "injection".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "g".into(),
            line: Some(2),
            title: "LLM: something".into(),
        }];
        let response = "I'm not sure what to do with these findings.\n";
        let result = apply_synthesis_decisions(&pattern, &llm, response);
        assert_eq!(
            result.len(),
            2,
            "Malformed response → keep all (safe default)"
        );
    }

    #[test]
    fn test_apply_synthesis_case_insensitive() {
        let pattern = vec![DetectedFinding {
            id: "P1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "f".into(),
            line: Some(1),
            title: "Dangerous pattern: x".into(),
        }];
        let response = "reject p1\n"; // lowercase reject, lowercase id
        let result = apply_synthesis_decisions(&pattern, &[], response);
        assert_eq!(result.len(), 0, "Case-insensitive REJECT should work");
    }

    #[test]
    fn test_sanitize_for_prompt() {
        assert_eq!(sanitize_for_prompt("normal title"), "normal title");
        assert_eq!(
            sanitize_for_prompt("=== INJECTED SECTION ==="),
            "--- INJECTED SECTION ---"
        );
        // Control chars stripped
        let with_controls = "title\x00with\x01controls";
        assert!(!sanitize_for_prompt(with_controls).contains('\x00'));
        // Truncation
        let long = "a".repeat(500);
        assert_eq!(sanitize_for_prompt(&long).len(), 200);
    }

    #[tokio::test]
    async fn test_synthesize_findings_single_source_passthrough() {
        let db = GraphDb::in_memory().unwrap();
        let cats = HashSet::new();

        // LLM-only findings should pass through directly
        let findings = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "foo".into(),
            line: Some(1),
            title: "LLM: something dangerous".into(),
        }];
        let result = synthesize_findings(findings.clone(), &cats, &db, 30).await;
        assert_eq!(result.len(), 1, "Single-source should pass through");
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

    #[tokio::test]
    async fn test_synthesis_is_tracked() {
        // When both sources have findings, synthesize_findings should
        // attempt LLM synthesis and track the outcome (either success or fallback).
        // It must NOT silently skip tracking.
        let db = GraphDb::in_memory().unwrap();
        let cats = HashSet::new();

        let findings = vec![
            DetectedFinding {
                id: "p1".into(),
                category: "memory".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "t.c".into(),
                function: "f".into(),
                line: Some(1),
                title: "Dangerous pattern: strcpy".into(),
            },
            DetectedFinding {
                id: "l1".into(),
                category: "injection".into(),
                severity: "critical".into(),
                cwes: vec![],
                file: "t.c".into(),
                function: "g".into(),
                line: Some(2),
                title: "LLM: command injection".into(),
            },
        ];

        let stats = synthesis_stats();
        let before_llm = stats.llm_synthesis_count.load(Ordering::Relaxed);
        let before_fallback = stats.fallback_count.load(Ordering::Relaxed);

        let result = synthesize_findings(findings, &cats, &db, 30).await;
        assert!(!result.is_empty(), "Should produce findings");

        let after_llm = stats.llm_synthesis_count.load(Ordering::Relaxed);
        let after_fallback = stats.fallback_count.load(Ordering::Relaxed);

        // Either LLM synthesis succeeded or fallback was used — one counter must increase
        let total_increase = (after_llm - before_llm) + (after_fallback - before_fallback);
        assert!(
            total_increase > 0,
            "Synthesis must track its outcome: llm_delta={}, fallback_delta={} (neither changed!)",
            after_llm - before_llm,
            after_fallback - before_fallback,
        );
    }

    #[test]
    fn test_synthesis_stats_report() {
        let stats = SynthesisStats::new();
        stats.record_llm_synthesis();
        stats.record_llm_synthesis();
        stats.record_fallback();
        // Just verify it doesn't panic — the output goes to tracing/eprintln
        stats.report();
    }
}
