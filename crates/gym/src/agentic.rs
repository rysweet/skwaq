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
use anyhow::Context;
use skwaq_core::analysis::{
    extract_function_from_title, extract_line_from_title, DangerousApiDetector,
    SemanticPatternClass, SemanticPatternClassifier,
};
use skwaq_core::binary::ghidra::{load_cached_or_analyze, GhidraLoadOutcome};
use skwaq_core::config::Config;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::GraphDb;
use skwaq_core::source::parse_file;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Tracks how many cases used LLM synthesis vs. encountered errors.
///
/// Thread-safe counters for use across concurrent gym case execution.
/// Call [`SynthesisStats::report`] at end of a gym run to log the summary.
pub struct SynthesisStats {
    llm_synthesis_count: AtomicU32,
    failed_count: AtomicU32,
}

impl Default for SynthesisStats {
    fn default() -> Self {
        Self {
            llm_synthesis_count: AtomicU32::new(0),
            failed_count: AtomicU32::new(0),
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

    fn record_failure(&self) {
        self.failed_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Log end-of-run synthesis summary. Call after all cases complete.
    pub fn report(&self) {
        let llm = self.llm_synthesis_count.load(Ordering::Relaxed);
        let failed = self.failed_count.load(Ordering::Relaxed);
        let total = llm + failed;
        if total == 0 {
            tracing::info!("Synthesis: no dual-source cases (nothing to synthesize)");
            return;
        }
        if failed > 0 {
            tracing::warn!(
                "Synthesis summary: {}/{} cases used LLM synthesis, {} failed loudly",
                llm,
                total,
                failed,
            );
            eprintln!(
                "\n  WARNING: {}/{} synthesis cases failed loudly.\n  \
                 Check the logged LLM synthesis errors above.\n",
                failed, total,
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

const GHIDRA_ANALYSIS_TIMEOUT_SECS: u64 = 300;
const SYNTHESIS_REFINEMENT_MAX_BUDGET: u64 = 10_000;

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
    if let Ok(hits) = detector.detect_in_source(path, &parsed.language) {
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
        }
    }

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
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await?;

    // --- Layer 5: Synthesis — weigh all evidence ---
    // Collect ALL findings from DB (pattern + orchestrator + LLM)
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    // Synthesize: use the LLM to weigh all evidence and decide which findings are credible.
    // Unlike the old intersection filter, this preserves LLM-only findings that
    // demonstrate real understanding of the code, but it fails loudly if synthesis
    // cannot run instead of silently downgrading analysis quality.
    let synthesized =
        synthesize_findings(all_findings, &pattern_categories, &db, timeout_secs).await?;

    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = synthesized
        .into_iter()
        .filter(|f| seen_categories.insert(dedup_key(f)))
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
    enrich_binary_graph_with_ghidra(path, &builder, &inv_id).await?;

    // Pattern detection on imports
    let mut pattern_categories: HashSet<String> = HashSet::new();
    let detector = DangerousApiDetector::new();
    let import_hits = detector.check_imports(&binary_info.imports);

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
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await?;

    // Synthesis — weigh all evidence
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    let synthesized =
        synthesize_findings(all_findings, &pattern_categories, &db, timeout_secs).await?;

    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = synthesized
        .into_iter()
        .filter(|f| seen_categories.insert(dedup_key(f)))
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
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await?;

    // Return all LLM findings directly (no intersection filter)
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    // Deduplicate by category
    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = all_findings
        .into_iter()
        .filter(|f| seen_categories.insert(dedup_key(f)))
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
    enrich_binary_graph_with_ghidra(path, &builder, &inv_id).await?;

    // Skip pattern detection — go straight to LLM pipeline
    run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await?;

    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    let mut seen_categories: HashSet<String> = HashSet::new();
    let deduped: Vec<DetectedFinding> = all_findings
        .into_iter()
        .filter(|f| seen_categories.insert(dedup_key(f)))
        .collect();

    Ok(deduped)
}

async fn enrich_binary_graph_with_ghidra(
    path: &Path,
    builder: &GraphBuilder<'_>,
    investigation_id: &str,
) -> anyhow::Result<()> {
    match load_cached_or_analyze(path, GHIDRA_ANALYSIS_TIMEOUT_SECS).await {
        GhidraLoadOutcome::NotAvailable => {
            anyhow::bail!(
                "Ghidra enrichment unavailable for {}: no cached analysis found and live Ghidra is not available",
                path.display()
            );
        }
        GhidraLoadOutcome::Cached(analysis) => {
            tracing::info!(
                "Using cached Ghidra analysis for {} ({} functions)",
                path.display(),
                analysis.functions.len(),
            );
            store_ghidra_results(builder, &analysis, investigation_id);
            Ok(())
        }
        GhidraLoadOutcome::Fresh(analysis) => {
            let decompiled_count = analysis
                .functions
                .iter()
                .filter(|f| f.decompiled.is_some())
                .count();
            tracing::info!(
                "Loaded fresh Ghidra analysis for {} ({} functions, {} with decompiled source)",
                path.display(),
                analysis.functions.len(),
                decompiled_count,
            );
            store_ghidra_results(builder, &analysis, investigation_id);
            Ok(())
        }
        GhidraLoadOutcome::Failed(error) => {
            anyhow::bail!("Ghidra enrichment failed for {}: {}", path.display(), error,)
        }
    }
}

fn store_ghidra_results(
    builder: &GraphBuilder<'_>,
    analysis: &skwaq_core::binary::types::GhidraAnalysis,
    investigation_id: &str,
) {
    match builder.build_from_ghidra_analysis(analysis, investigation_id) {
        Ok(counts) => {
            tracing::info!(
                "Stored Ghidra graph enrichment for {}: {} functions updated, {} new functions, {} call edges",
                investigation_id,
                counts.functions_updated,
                counts.functions_added,
                counts.calls_added,
            );
        }
        Err(error) => {
            tracing::warn!(
                "Failed to store Ghidra analysis in benchmark graph for {}: {}",
                investigation_id,
                error,
            );
        }
    }
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
/// When both pattern and LLM findings exist, the analysis must be synthesized
/// by an LLM reviewer. Fail loudly if that synthesis cannot run.
async fn synthesize_findings(
    all_findings: Vec<DetectedFinding>,
    _pattern_categories: &HashSet<String>,
    _db: &GraphDb,
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    if all_findings.is_empty() {
        return Ok(all_findings);
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
        return Ok(all_findings);
    }

    // Both sources have findings — synthesis is mandatory.
    match llm_synthesize(&pattern_findings, &llm_findings, timeout_secs).await {
        Ok(synthesized) => {
            SYNTHESIS_STATS.record_llm_synthesis();
            Ok(synthesized)
        }
        Err(e) => {
            SYNTHESIS_STATS.record_failure();
            Err(e)
        }
    }
}

/// Call the LLM to evaluate findings like a lead security reviewer.
async fn llm_synthesize(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let config = Config::load().context("LLM synthesis requires a valid skwaq configuration")?;
    skwaq_core::llm::ensure_benchmark_copilot_ready(&config.llm)
        .await
        .context("LLM synthesis requires explicit Copilot benchmark readiness")?;
    let client = skwaq_core::llm::create_client(&config.llm)
        .await
        .context("LLM synthesis requires a working LLM client")?;

    if timeout_secs == 0 {
        anyhow::bail!("LLM synthesis requires a positive timeout budget");
    }

    // Build the synthesis prompt
    let mut prompt = String::from(
        "You are a lead security reviewer evaluating vulnerability findings from two sources:\n\
         1. PATTERN DETECTION (automated regex-based, high precision, limited understanding)\n\
         2. LLM AGENTS (AI-powered deep analysis, better understanding, may hallucinate)\n\n\
         Your job: decide which findings are REAL vulnerabilities.\n\n\
         For each finding, respond with one line:\n\
         CONFIRM <id> — strong evidence from one or both sources\n\
         REVIEW <id> — plausible finding, but the evidence is conflicting or incomplete and needs a second pass\n\
         REJECT <id> — insufficient evidence, likely false positive\n\n\
         Only REJECT findings where you are confident they are false positives.\n\
         Use REVIEW when the finding may be real but you need a stricter second-pass check.\n\
         When evidence is strong enough, prefer CONFIRM over REVIEW.\n\n",
    );

    append_findings_for_prompt(&mut prompt, "=== PATTERN FINDINGS ===\n", pattern_findings);
    append_findings_for_prompt(&mut prompt, "\n=== LLM AGENT FINDINGS ===\n", llm_findings);

    prompt.push_str("\nEvaluate each finding. Respond with CONFIRM or REJECT for each ID.\n");

    // Budget scales with number of findings to evaluate
    let budget_amount = config
        .analysis
        .default_token_budget
        .min(10_000 + (pattern_findings.len() + llm_findings.len()) as u64 * 500);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);
    let model = &config.llm.copilot.model;
    let synthesis_started = Instant::now();

    let response_text = execute_synthesis_completion(
        &client,
        model,
        "You are a lead security reviewer evaluating vulnerability findings.",
        &prompt,
        timeout_secs,
        &mut budget,
    )
    .await?;
    let first_pass = parse_synthesis_decisions(&response_text);
    let mut rejected_ids = first_pass.rejected_ids.clone();

    let review_findings = collect_review_findings(
        pattern_findings,
        llm_findings,
        &first_pass.review_ids,
        &rejected_ids,
    );

    if !review_findings.is_empty() {
        let remaining_timeout =
            remaining_refinement_timeout(timeout_secs, synthesis_started.elapsed());
        if remaining_timeout == 0 {
            tracing::warn!(
                "Skipping synthesis refinement for {} finding(s): no timeout budget remained after first pass",
                review_findings.len()
            );
        } else {
            tracing::info!(
                "Running synthesis refinement on {} uncertain finding(s) with {}s remaining",
                review_findings.len(),
                remaining_timeout
            );
            let refinement_prompt = build_refinement_prompt(&review_findings);
            let mut refinement_budget = skwaq_core::llm::TokenBudget::new(
                (budget_amount / 4).clamp(2_000, SYNTHESIS_REFINEMENT_MAX_BUDGET),
            );
            let refinement_text = match execute_synthesis_completion(
                &client,
                model,
                "You are a lead security reviewer performing a stricter second-pass review.",
                &refinement_prompt,
                remaining_timeout,
                &mut refinement_budget,
            )
            .await
            {
                Ok(text) => text,
                Err(error) => {
                    tracing::warn!(
                        "LLM synthesis refinement failed after successful initial synthesis; using initial decisions: {}",
                        error
                    );
                    return Ok(apply_rejected_synthesis_decisions(
                        pattern_findings,
                        llm_findings,
                        &rejected_ids,
                    ));
                }
            };
            let refinement = parse_synthesis_decisions(&refinement_text);
            let refined_rejections: HashSet<String> = refinement
                .rejected_ids
                .into_iter()
                .filter(|id| first_pass.review_ids.contains(id))
                .collect();
            tracing::info!(
                "Synthesis refinement rejected {} of {} reviewed finding(s)",
                refined_rejections.len(),
                review_findings.len()
            );
            rejected_ids.extend(refined_rejections);
        }
    }

    // Parse and apply synthesis decisions
    let synthesized =
        apply_rejected_synthesis_decisions(pattern_findings, llm_findings, &rejected_ids);

    Ok(synthesized)
}

fn remaining_refinement_timeout(timeout_secs: u64, elapsed: Duration) -> u64 {
    timeout_secs.saturating_sub(elapsed.as_secs())
}
fn append_findings_for_prompt(prompt: &mut String, heading: &str, findings: &[DetectedFinding]) {
    prompt.push_str(heading);
    for finding in findings {
        let safe_title = sanitize_for_prompt(&finding.title);
        let semantic = semantic_prompt_hint(finding);
        prompt.push_str(&format!(
            "ID: {} | Category: {} | Severity: {} | Semantic classes: {} | {}\n",
            finding.id, finding.category, finding.severity, semantic, safe_title
        ));
    }
}

fn build_refinement_prompt(review_findings: &[DetectedFinding]) -> String {
    let mut prompt = String::from(
        "You are performing a stricter second-pass review of findings that were previously marked REVIEW.\n\
         These findings may be real, but the first pass considered the evidence incomplete or conflicting.\n\n\
         For each finding, respond with exactly one line:\n\
         CONFIRM <id> — enough concrete evidence remains after re-checking\n\
         REJECT <id> — evidence is still incomplete, conflicting, or too speculative\n\n\
         Do not emit REVIEW on the second pass.\n\
         Prefer REJECT when the finding depends on assumptions not supported by the evidence.\n\n",
    );
    append_findings_for_prompt(&mut prompt, "=== REVIEW FINDINGS ===\n", review_findings);
    prompt.push_str(
        "\nRe-evaluate each reviewed finding. Respond with CONFIRM or REJECT for every ID.\n",
    );
    prompt
}

async fn execute_synthesis_completion(
    client: &skwaq_core::llm::Client,
    model: &str,
    system_prompt: &str,
    prompt: &str,
    timeout_secs: u64,
    budget: &mut skwaq_core::llm::TokenBudget,
) -> anyhow::Result<String> {
    let noop_executor = |_name: String, _args: serde_json::Value| async move {
        Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({"error": "no tools"}))
    };

    let result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        skwaq_core::llm::execute_with_tools(
            client,
            model,
            system_prompt,
            prompt,
            &[],
            noop_executor,
            budget,
        ),
    )
    .await;

    match result {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(e)) => anyhow::bail!("LLM synthesis call failed: {}", e),
        Err(_) => anyhow::bail!("LLM synthesis timed out after {}s", timeout_secs),
    }
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
#[derive(Debug, Default)]
struct SynthesisDecisionSummary {
    rejected_ids: HashSet<String>,
    review_ids: HashSet<String>,
}

fn parse_synthesis_decisions(response_text: &str) -> SynthesisDecisionSummary {
    let mut decisions = SynthesisDecisionSummary::default();

    for line in response_text.lines() {
        let trimmed = line.trim();
        let upper = trimmed.to_uppercase();
        let id = trimmed
            .split_whitespace()
            .nth(1)
            .map(|raw| {
                raw.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_')
            })
            .filter(|raw| !raw.is_empty())
            .map(|raw| raw.to_ascii_lowercase());

        match (upper.starts_with("REJECT"), upper.starts_with("REVIEW"), id) {
            (true, _, Some(id)) => {
                decisions.review_ids.remove(&id);
                decisions.rejected_ids.insert(id);
            }
            (false, true, Some(id)) if !decisions.rejected_ids.contains(&id) => {
                decisions.review_ids.insert(id);
            }
            _ => {}
        }
    }

    decisions
}

#[cfg(test)]
fn apply_synthesis_decisions(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    response_text: &str,
) -> Vec<DetectedFinding> {
    let decisions = parse_synthesis_decisions(response_text);
    apply_rejected_synthesis_decisions(pattern_findings, llm_findings, &decisions.rejected_ids)
}

fn apply_rejected_synthesis_decisions(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    rejected_ids: &HashSet<String>,
) -> Vec<DetectedFinding> {
    let total = pattern_findings.len() + llm_findings.len();
    tracing::info!(
        "LLM synthesis: {} rejected out of {} total findings",
        rejected_ids.len(),
        total
    );

    let mut seen_categories: HashSet<String> = HashSet::new();
    let mut synthesized: Vec<DetectedFinding> = Vec::new();

    for f in llm_findings {
        if !rejected_ids.contains(&f.id.to_lowercase()) && seen_categories.insert(dedup_key(f)) {
            synthesized.push(f.clone());
        }
    }
    for f in pattern_findings {
        if !rejected_ids.contains(&f.id.to_lowercase()) && seen_categories.insert(dedup_key(f)) {
            synthesized.push(f.clone());
        }
    }

    synthesized
}

fn collect_review_findings(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    review_ids: &HashSet<String>,
    rejected_ids: &HashSet<String>,
) -> Vec<DetectedFinding> {
    llm_findings
        .iter()
        .chain(pattern_findings.iter())
        .filter(|finding| {
            let finding_id = finding.id.to_ascii_lowercase();
            review_ids.contains(&finding_id) && !rejected_ids.contains(&finding_id)
        })
        .cloned()
        .collect()
}

/// Cached LLM client for the process. Avoids redundant Copilot token
/// negotiation when many cases run concurrently. The `Client` is `Clone`,
/// so each pipeline stage gets a cheap clone.
static LLM_CLIENT: tokio::sync::OnceCell<skwaq_core::llm::Client> =
    tokio::sync::OnceCell::const_new();

/// Open the default durable memory store for agents.
///
/// Returns `None` if memory cannot be initialized (non-fatal — agents
/// simply run without cross-run learning).
fn open_memory_store() -> Option<skwaq_core::memory::MemoryStore> {
    match skwaq_core::memory::MemoryStore::open_default() {
        Ok(store) => {
            tracing::info!("Durable agent memory enabled");
            Some(store)
        }
        Err(e) => {
            tracing::warn!("Could not open durable memory store: {e}. Running without memory.");
            None
        }
    }
}

/// Run the LLM agent pipeline and fail explicitly if the client is unavailable.
async fn run_llm_pipeline(
    db: &GraphDb,
    inv_id: &str,
    file_str: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let config = Config::load()
        .context("Failed to load skwaq configuration for hybrid benchmark analysis")?;

    // Create or reuse the cached LLM client. The first call validates
    // Copilot readiness and negotiates a token; subsequent calls reuse it.
    // This eliminates cold-start rate-limit failures when many cases start
    // concurrently.
    let llm_client = LLM_CLIENT
        .get_or_try_init(|| async {
            skwaq_core::llm::ensure_benchmark_copilot_ready(&config.llm).await?;
            skwaq_core::llm::create_client(&config.llm).await
        })
        .await
        .with_context(|| {
            format!(
                "Hybrid benchmark analysis requires a working LLM client for {}",
                file_str
            )
        })?
        .clone();

    let pipeline = skwaq_core::agents::deep_pipeline_for_target(file_str);
    let budget_amount = config.analysis.default_token_budget.min(100_000);
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    let target = std::path::Path::new(file_str)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_str.to_string());

    tracing::info!("Running LLM agent pipeline on {}", target);

    // Use durable memory if available so agents learn across benchmark runs.
    let memory = open_memory_store();

    let pipeline_result = if let Some(ref mem) = memory {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            pipeline.run_with_memory(&target, inv_id, db, llm_client, &mut budget, mem),
        )
        .await
    } else {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            pipeline.run(&target, inv_id, db, llm_client, &mut budget),
        )
        .await
    };

    match pipeline_result {
        Ok(Ok(results)) => {
            let total_tokens: u64 = results.iter().map(|r| r.tokens_used).sum();
            for result in &results {
                if let Some(parse_error) = &result.parsed_output_error {
                    tracing::warn!(
                        target = %target,
                        investigation_id = %inv_id,
                        agent = %result.agent_name,
                        schema = %result
                            .context_frame
                            .output_schema
                            .as_deref()
                            .unwrap_or("unknown"),
                        error = %parse_error,
                        "Structured agent output did not match schema during gym analysis"
                    );
                }
            }
            tracing::info!(
                "LLM pipeline completed for {}: {} agents, {} tokens",
                target,
                results.len(),
                total_tokens,
            );
            Ok(())
        }
        Ok(Err(e)) => {
            anyhow::bail!("LLM pipeline failed for {}: {}", file_str, e);
        }
        Err(_) => {
            anyhow::bail!(
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
                line: extract_line_from_title(&title),
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
                line: extract_line_from_title(&title),
                title,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(findings)
}

fn semantic_classes_for_finding(finding: &DetectedFinding) -> Vec<SemanticPatternClass> {
    SemanticPatternClassifier::new()
        .classify(&finding.category, &finding.title, &finding.function)
        .into_iter()
        .collect()
}

fn semantic_classes_for_prompt(finding: &DetectedFinding) -> Vec<SemanticPatternClass> {
    SemanticPatternClassifier::new()
        .classify(&finding.category, "", &finding.function)
        .into_iter()
        .collect()
}

fn normalize_function_key(function: &str) -> String {
    function
        .split('@')
        .next()
        .unwrap_or(function)
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .to_ascii_lowercase()
}

fn dedup_key(finding: &DetectedFinding) -> String {
    let function = normalize_function_key(&finding.function);
    let scope = if function.is_empty() {
        "global".to_string()
    } else {
        function
    };
    let location = dedup_location_key(finding);

    let classes = semantic_classes_for_finding(finding);
    if classes.is_empty() {
        return format!("category:{}:{}:{}", finding.category, scope, location);
    }

    let class_names = classes
        .into_iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>()
        .join("+");
    format!("semantic:{}:{}:{}", class_names, scope, location)
}

fn dedup_location_key(finding: &DetectedFinding) -> String {
    if let Some(line) = finding.line {
        return format!("line:{line}");
    }

    let normalized_title = finding
        .title
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if normalized_title.is_empty() || normalized_title.bytes().all(|byte| byte == b'_') {
        return format!("id:{}", finding.id);
    }
    format!("title:{normalized_title}")
}

fn semantic_prompt_hint(finding: &DetectedFinding) -> String {
    let classes = semantic_classes_for_prompt(finding);
    if classes.is_empty() {
        return "none".to_string();
    }
    classes
        .into_iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use skwaq_core::binary::types::{
        BinaryFormat, BinaryInfo, GhidraAnalysis, GhidraFunction, HardeningInfo, SymbolInfo,
    };
    use skwaq_core::config::Config;

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
            .filter(|f| seen.insert(dedup_key(f)))
            .collect();
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_semantic_dedup_preserves_distinct_memory_classes() {
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
                function: "cleanup".into(),
                line: Some(40),
                title: "LLM: use-after-free in cleanup".into(),
            },
        ];

        let mut seen = HashSet::new();
        let deduped: Vec<_> = findings
            .into_iter()
            .filter(|f| seen.insert(dedup_key(f)))
            .collect();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_semantic_dedup_preserves_same_class_on_different_lines() {
        let findings = vec![
            DetectedFinding {
                id: "1".into(),
                category: "tempfile".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "create_temp".into(),
                line: Some(10),
                title: "Pattern: mktemp".into(),
            },
            DetectedFinding {
                id: "2".into(),
                category: "tempfile".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "create_temp".into(),
                line: Some(20),
                title: "Pattern: mktemp".into(),
            },
        ];

        let mut seen = HashSet::new();
        let deduped: Vec<_> = findings
            .into_iter()
            .filter(|f| seen.insert(dedup_key(f)))
            .collect();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_semantic_prompt_hint_lists_classes() {
        let finding = DetectedFinding {
            id: "1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "LLM: stack buffer overflow in strcpy".into(),
        };

        assert_eq!(semantic_prompt_hint(&finding), "buffer_overflow");
    }

    #[test]
    fn test_semantic_prompt_hint_does_not_echo_llm_title() {
        let finding = DetectedFinding {
            id: "1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "cleanup".into(),
            line: Some(10),
            title: "LLM: use-after-free in cleanup".into(),
        };

        assert_eq!(semantic_prompt_hint(&finding), "none");
    }

    #[test]
    fn test_dedup_location_key_falls_back_to_id_for_empty_title() {
        let finding = DetectedFinding {
            id: "finding-1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "parse".into(),
            line: None,
            title: String::new(),
        };

        assert_eq!(dedup_location_key(&finding), "id:finding-1");
    }

    #[test]
    fn test_dedup_location_key_falls_back_to_id_for_symbol_only_title() {
        let finding = DetectedFinding {
            id: "finding-2".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "parse".into(),
            line: None,
            title: "!!!".into(),
        };

        assert_eq!(dedup_location_key(&finding), "id:finding-2");
    }

    #[test]
    fn test_store_ghidra_results_enriches_binary_graph() {
        let db = GraphDb::in_memory().unwrap();
        let builder = GraphBuilder::new(&db);
        let inv_id = "test-bin-ghidra";

        let info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: "x86_64".into(),
            bits: 64,
            endianness: "little".into(),
            is_stripped: false,
            entry_point: 0x401000,
            sections: vec![],
            symbols: vec![SymbolInfo {
                name: "main".into(),
                address: 0x401000,
                size: 64,
                symbol_type: "2".into(),
                binding: "Global".into(),
            }],
            imports: vec![],
            strings: vec![],
            hardening: HardeningInfo::default(),
        };
        builder.build_from_binary_info(&info, inv_id).unwrap();

        let analysis = GhidraAnalysis {
            functions: vec![
                GhidraFunction {
                    name: "main".into(),
                    address: "401000".into(),
                    size: 64,
                    decompiled: Some("int main(int argc, char **argv) { return argc; }".into()),
                    calls: vec!["401020".into()],
                    called_by: vec![],
                    parameter_count: 2,
                },
                GhidraFunction {
                    name: "helper".into(),
                    address: "401020".into(),
                    size: 32,
                    decompiled: Some("void helper(void) { return; }".into()),
                    calls: vec![],
                    called_by: vec!["401000".into()],
                    parameter_count: 0,
                },
            ],
            strings: vec![],
            imports: vec![],
        };

        store_ghidra_results(&builder, &analysis, inv_id);

        let decompiled: String = db
            .conn()
            .query_row(
                "SELECT decompiled FROM functions WHERE name = 'main' AND investigation_id = ?1",
                [inv_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(decompiled.contains("return argc;"));

        let helper_count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM functions WHERE name = 'helper' AND investigation_id = ?1",
                [inv_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(helper_count, 1);
    }

    // merge_findings_deterministic tests removed — function deleted (no fallback paths)

    #[tokio::test]
    async fn test_synthesize_findings_empty() {
        let db = GraphDb::in_memory().unwrap();
        let cats = HashSet::new();
        let result = synthesize_findings(vec![], &cats, &db, 30).await.unwrap();
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
    fn test_parse_synthesis_decisions_tracks_review_ids() {
        let response = "CONFIRM p1\nREVIEW l1 — conflicting evidence\nREJECT p2 — false positive\n";
        let decisions = parse_synthesis_decisions(response);
        assert!(decisions.review_ids.contains("l1"));
        assert!(decisions.rejected_ids.contains("p2"));
        assert!(!decisions.review_ids.contains("p2"));
    }

    #[test]
    fn test_apply_synthesis_review_keeps_finding_until_rejected() {
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "copy".into(),
            line: Some(12),
            title: "LLM: possible stack overflow".into(),
        }];
        let response = "REVIEW l1 — re-check required\n";
        let result = apply_synthesis_decisions(&[], &llm, response);
        assert_eq!(
            result.len(),
            1,
            "REVIEW alone should not drop a finding before the refinement pass"
        );
    }

    #[test]
    fn test_collect_review_findings_excludes_already_rejected_ids() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "copy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let mut review_ids = HashSet::new();
        review_ids.insert("p1".to_string());
        let mut rejected_ids = HashSet::new();
        rejected_ids.insert("p1".to_string());

        let result = collect_review_findings(&pattern, &[], &review_ids, &rejected_ids);
        assert!(
            result.is_empty(),
            "Rejected findings should not be re-reviewed"
        );
    }

    #[test]
    fn test_remaining_refinement_timeout_stays_within_budget() {
        for (timeout_secs, elapsed_secs, expected) in [
            (0_u64, 0_u64, 0_u64),
            (1, 0, 1),
            (1, 1, 0),
            (2, 1, 1),
            (30, 12, 18),
        ] {
            let remaining =
                remaining_refinement_timeout(timeout_secs, Duration::from_secs(elapsed_secs));
            assert_eq!(remaining, expected);
            assert!(remaining <= timeout_secs);
        }
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
        let result = synthesize_findings(findings.clone(), &cats, &db, 30)
            .await
            .unwrap();
        assert_eq!(result.len(), 1, "Single-source should pass through");
    }

    #[tokio::test]
    async fn test_full_agentic_analysis() {
        let fixture = fixtures_dir().join("buffer_overflow.c");
        if !fixture.exists() {
            return;
        }

        let config = Config::load().unwrap_or_default();
        if skwaq_core::llm::ensure_benchmark_copilot_ready(&config.llm)
            .await
            .is_err()
        {
            return;
        }
        if !std::env::current_dir()
            .unwrap_or_default()
            .join("agents/decompile-renamer.md")
            .exists()
        {
            return;
        }

        let findings = run_agentic_source_analysis(&fixture, 30).await.unwrap();
        assert!(!findings.is_empty(), "Should produce findings");
        let has_memory = findings.iter().any(|f| f.category == "memory");
        assert!(has_memory, "Should detect memory category");
    }

    #[tokio::test]
    async fn test_synthesis_is_tracked() {
        // When both sources have findings, synthesis must either succeed
        // or fail loudly and track that failure. It must NOT silently degrade.
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
        let before_failed = stats.failed_count.load(Ordering::Relaxed);

        let result = synthesize_findings(findings, &cats, &db, 30).await;
        if let Ok(findings) = &result {
            assert!(
                findings.len() <= 2,
                "Successful synthesis should return a bounded subset of the candidate findings"
            );
        }

        let after_llm = stats.llm_synthesis_count.load(Ordering::Relaxed);
        let after_failed = stats.failed_count.load(Ordering::Relaxed);

        // Either LLM synthesis succeeded or it failed loudly — one counter must increase.
        let total_increase = (after_llm - before_llm) + (after_failed - before_failed);
        assert!(
            total_increase > 0,
            "Synthesis must track its outcome: llm_delta={}, failed_delta={} (neither changed!)",
            after_llm - before_llm,
            after_failed - before_failed,
        );
    }

    #[test]
    fn test_synthesis_stats_report() {
        let stats = SynthesisStats::new();
        stats.record_llm_synthesis();
        stats.record_llm_synthesis();
        stats.record_failure();
        // Just verify it doesn't panic — the output goes to tracing/eprintln
        stats.report();
    }
}
