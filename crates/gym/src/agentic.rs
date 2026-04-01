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
    extract_function_from_title, extract_line_from_title, DangerousApiDetector, DangerousApiHit,
    SemanticPatternClass, SemanticPatternClassifier, Severity,
};
use skwaq_core::binary::ghidra::{load_cached_or_analyze, GhidraLoadOutcome};
use skwaq_core::config::Config;
use skwaq_core::graph::builder::GraphBuilder;
use skwaq_core::graph::GraphDb;
use skwaq_core::source::parse_file;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Tracks how dual-source cases were resolved across gym execution.
///
/// Thread-safe counters for use across concurrent gym case execution.
/// Call [`SynthesisStats::report`] at end of a gym run to log the summary.
pub struct SynthesisStats {
    pattern_confidence_early_exit_count: AtomicU32,
    semantic_confidence_fast_path_count: AtomicU32,
    expert_routed_count: AtomicU32,
    llm_synthesis_count: AtomicU32,
    consensus_early_exit_count: AtomicU32,
    fallback_count: AtomicU32,
    failed_count: AtomicU32,
}

impl Default for SynthesisStats {
    fn default() -> Self {
        Self {
            pattern_confidence_early_exit_count: AtomicU32::new(0),
            semantic_confidence_fast_path_count: AtomicU32::new(0),
            expert_routed_count: AtomicU32::new(0),
            llm_synthesis_count: AtomicU32::new(0),
            consensus_early_exit_count: AtomicU32::new(0),
            fallback_count: AtomicU32::new(0),
            failed_count: AtomicU32::new(0),
        }
    }
}

impl SynthesisStats {
    pub fn new() -> Self {
        Self::default()
    }

    fn record_pattern_confidence_early_exit(&self) {
        self.pattern_confidence_early_exit_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_semantic_confidence_fast_path(&self) {
        self.semantic_confidence_fast_path_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_expert_routed(&self) {
        self.expert_routed_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_llm_synthesis(&self) {
        self.llm_synthesis_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_consensus_early_exit(&self) {
        self.consensus_early_exit_count
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_fallback(&self) {
        self.fallback_count.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn record_failure(&self) {
        self.failed_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Log end-of-run synthesis summary. Call after all cases complete.
    pub fn report(&self) {
        let pattern_confidence = self
            .pattern_confidence_early_exit_count
            .load(Ordering::Relaxed);
        let semantic_confidence = self
            .semantic_confidence_fast_path_count
            .load(Ordering::Relaxed);
        let expert_routed = self.expert_routed_count.load(Ordering::Relaxed);
        let llm = self.llm_synthesis_count.load(Ordering::Relaxed);
        let consensus = self.consensus_early_exit_count.load(Ordering::Relaxed);
        let fallback = self.fallback_count.load(Ordering::Relaxed);
        let failed = self.failed_count.load(Ordering::Relaxed);
        let total = pattern_confidence
            + semantic_confidence
            + expert_routed
            + llm
            + consensus
            + fallback
            + failed;
        if total == 0 {
            tracing::info!("Synthesis: no dual-source cases (nothing to synthesize)");
            return;
        }
        if fallback > 0 || failed > 0 {
            tracing::warn!(
                "Synthesis summary: {}/{} pattern-confidence early-exit, {}/{} semantic-confidence fast-path, {}/{} expert-routed, {}/{} LLM synthesis, {}/{} consensus early-exit, {}/{} fallback (kept all findings), {} failed",
                pattern_confidence,
                total,
                semantic_confidence,
                total,
                expert_routed,
                total,
                llm,
                total,
                consensus,
                total,
                fallback,
                total,
                failed,
            );
            if fallback > 0 {
                eprintln!(
                    "\n  NOTE: {}/{} synthesis cases used fallback (kept all findings due to LLM errors).\n  \
                     Scoring is still valid but synthesis quality is degraded for those cases.\n",
                    fallback, total,
                );
            }
            if failed > 0 {
                eprintln!(
                    "\n  WARNING: {}/{} synthesis cases failed loudly.\n  \
                     Check the logged LLM synthesis errors above.\n",
                    failed, total,
                );
            }
        } else {
            tracing::info!(
                "Synthesis summary: {}/{} pattern-confidence early-exit, {}/{} semantic-confidence fast-path, {}/{} expert-routed, {}/{} LLM synthesis, {}/{} consensus early-exit (all successful)",
                pattern_confidence,
                total,
                semantic_confidence,
                total,
                expert_routed,
                total,
                llm,
                total,
                consensus,
                total,
            );
        }
    }
}

/// Global synthesis stats for the current gym run.
static SYNTHESIS_STATS: std::sync::LazyLock<SynthesisStats> =
    std::sync::LazyLock::new(SynthesisStats::new);

const GHIDRA_ANALYSIS_TIMEOUT_SECS: u64 = 300;
const SYNTHESIS_REFINEMENT_MAX_BUDGET: u64 = 50_000;

/// Get the global synthesis stats. Call [`SynthesisStats::report`] at end of run.
pub fn synthesis_stats() -> &'static SynthesisStats {
    &SYNTHESIS_STATS
}

/// Optional context hints to augment agentic analysis.
///
/// When analyzing cases that come with metadata (e.g. CyberGym cases with
/// vulnerability descriptions and patch diffs), these hints are injected
/// into the LLM prompt to guide deeper investigation. This is an agentic
/// pattern experiment: giving agents partial human-level context to see
/// if it improves detection precision and recall.
#[derive(Debug, Default, Clone)]
pub struct AnalysisHints {
    /// Vulnerability description (e.g. from CyberGym description.txt).
    /// Injected as a "prior intelligence" section for the failure analyst.
    pub vuln_description: Option<String>,
    /// Patch diff (e.g. from CyberGym patch.diff).
    /// Injected as "known fix" context for offense/defense analysts.
    pub patch_diff: Option<String>,
    /// Sanitizer/crash output (e.g. from CyberGym error.txt).
    /// Shows the exact crash location and error type from ASan/MSan/UBSan.
    pub error_output: Option<String>,
}

/// Run full agentic analysis on a source file.
///
/// Uses synthesis scoring: an LLM weighs evidence from both pattern
/// detection and agent findings to decide which are credible.
pub async fn run_agentic_source_analysis(
    path: &Path,
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    run_agentic_source_analysis_with_hints(path, timeout_secs, &AnalysisHints::default()).await
}

/// Run full agentic analysis with additional companion files ingested into
/// the same graph for cross-file relationship detection.
///
/// This is used for Juliet variants 51-68 where the vulnerability spans
/// multiple files (e.g., source in 51a.c, sink in 51b.c).
pub async fn run_agentic_multi_file_source_analysis(
    primary: &Path,
    companions: &[PathBuf],
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    if companions.len() <= 1 {
        // No companions — fall back to single-file analysis
        return run_agentic_source_analysis(primary, timeout_secs).await;
    }

    // Ingest all files into a shared graph, then run the agent pipeline
    // on the primary file with cross-file context available.
    let db = GraphDb::in_memory()?;
    let inv_id = format!("gym-mf-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = primary.to_string_lossy().to_string();

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

    // Ingest ALL companion files into the shared graph
    let builder = GraphBuilder::new(&db);
    let mut parsed_files = Vec::new();
    for path in companions {
        match parse_file(path) {
            Ok(parsed) => parsed_files.push(parsed),
            Err(e) => tracing::debug!("Multi-file parse skip {}: {}", path.display(), e),
        }
    }
    if parsed_files.is_empty() {
        return Ok(vec![]);
    }
    builder.build_from_source(&parsed_files, &inv_id)?;

    tracing::info!(
        "Multi-file agentic: ingested {} files into shared graph for {}",
        parsed_files.len(),
        file_str
    );

    // Run pattern detection across all files
    let detector = DangerousApiDetector::new();
    let mut all_findings = Vec::new();
    for comp_path in companions {
        let lang = comp_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("c");
        if let Ok(hits) = detector.detect_in_source(comp_path, lang) {
            for hit in hits {
                all_findings.push(DetectedFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: hit.danger_category.to_string(),
                    severity: hit.severity.to_string(),
                    cwes: vec![],
                    file: comp_path.to_string_lossy().to_string(),
                    function: hit.function_name.clone(),
                    line: Some(hit.line as u32),
                    title: format!(
                        "Dangerous pattern: {} ({}:{})",
                        hit.function_name,
                        comp_path.file_name().unwrap_or_default().to_string_lossy(),
                        hit.line
                    ),
                });
            }
        }
    }

    // Graph-based cross-file detection
    if let Ok(graph_hits) = detector.detect(&db) {
        let seen: std::collections::HashSet<String> =
            all_findings.iter().map(|f| f.function.clone()).collect();
        for hit in graph_hits {
            if !seen.contains(&hit.function_name) {
                all_findings.push(DetectedFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: hit.danger_category.to_string(),
                    severity: hit.severity.to_string(),
                    cwes: vec![],
                    file: hit.file.clone(),
                    function: hit.function_name.clone(),
                    line: Some(hit.line as u32),
                    title: format!("Cross-file: {} ({})", hit.function_name, hit.reason),
                });
            }
        }
    }

    // Run taint analysis on the shared graph
    let taint = skwaq_core::analysis::TaintAnalyzer::new(&db, 10);
    if let Ok(paths) = taint.find_unsanitized_paths() {
        for tp in &paths {
            all_findings.push(DetectedFinding {
                id: uuid::Uuid::new_v4().to_string(),
                category: "taint_flow".to_string(),
                severity: "high".to_string(),
                cwes: vec![],
                file: file_str.clone(),
                function: tp.sink.clone(),
                line: None,
                title: format!(
                    "Cross-file taint: {} → {} ({})",
                    tp.source,
                    tp.sink,
                    tp.hops.join(" → ")
                ),
            });
        }
    }

    Ok(all_findings)
}

/// Run pattern-only analysis across multiple source files with a shared graph.
///
/// Unlike per-file analysis, this ingests ALL files into a single Code Property
/// Graph before running pattern detection. This enables cross-file relationship
/// detection: a dangerous API call in one file that uses data defined in another
/// file can be traced through the shared graph.
///
/// This is an agentic pattern experiment: does shared-graph multi-file analysis
/// improve detection on real-world projects where vulnerabilities span files?
pub fn run_multi_file_pattern_analysis(paths: &[PathBuf]) -> anyhow::Result<Vec<DetectedFinding>> {
    if paths.is_empty() {
        return Ok(vec![]);
    }

    let db = GraphDb::in_memory()?;
    let inv_id = format!("gym-mf-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let target = paths
        .first()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

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

    // Ingest all files into a single shared graph
    let builder = GraphBuilder::new(&db);
    let mut parsed_files = Vec::new();
    for path in paths {
        match parse_file(path) {
            Ok(parsed) => parsed_files.push(parsed),
            Err(e) => tracing::debug!("Multi-file parse skip {}: {}", path.display(), e),
        }
    }

    if parsed_files.is_empty() {
        return Ok(vec![]);
    }

    builder.build_from_source(&parsed_files, &inv_id)?;

    // Run pattern detection across the shared graph
    let detector = DangerousApiDetector::new();
    let mut all_findings = Vec::new();

    // Per-file source pattern detection
    for path in paths {
        let lang = path.extension().and_then(|e| e.to_str()).unwrap_or("c");
        if let Ok(hits) = detector.detect_in_source(path, lang) {
            for hit in hits {
                all_findings.push(DetectedFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: hit.danger_category.to_string(),
                    severity: hit.severity.to_string(),
                    cwes: vec![],
                    file: path.to_string_lossy().to_string(),
                    function: hit.function_name.clone(),
                    line: Some(hit.line as u32),
                    title: format!(
                        "Dangerous pattern: {} ({}:{})",
                        hit.function_name,
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        hit.line
                    ),
                });
            }
        }
    }

    // Graph-based cross-file detection
    if let Ok(graph_hits) = detector.detect(&db) {
        let seen: std::collections::HashSet<String> =
            all_findings.iter().map(|f| f.function.clone()).collect();
        for hit in graph_hits {
            let base = hit
                .function_name
                .split('@')
                .next()
                .unwrap_or(&hit.function_name)
                .to_string();
            if !seen.contains(&base) {
                all_findings.push(DetectedFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: hit.danger_category.to_string(),
                    severity: hit.severity.to_string(),
                    cwes: vec![],
                    file: target.clone(),
                    function: base,
                    line: None,
                    title: format!("Cross-file graph: {}", hit.function_name),
                });
            }
        }
    }

    tracing::debug!(
        "Multi-file analysis: {} files, {} findings",
        paths.len(),
        all_findings.len()
    );

    Ok(all_findings)
}

/// Run full agentic analysis with optional context hints.
///
/// When hints are provided (vulnerability description, patch diff), the LLM
/// agents receive augmented context that can improve detection accuracy.
/// This is the primary entry point for CyberGym and other metadata-rich
/// benchmark suites.
pub async fn run_agentic_source_analysis_with_hints(
    path: &Path,
    timeout_secs: u64,
    hints: &AnalysisHints,
) -> anyhow::Result<Vec<DetectedFinding>> {
    let db = GraphDb::in_memory()?;
    let parsed = parse_file(path)?;

    let inv_id = format!("gym-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = chrono::Utc::now().to_rfc3339();
    let file_str = path.to_string_lossy().to_string();

    // If we have context hints, store them as investigation metadata
    // so LLM agents can reference them during analysis.
    if hints.vuln_description.is_some()
        || hints.patch_diff.is_some()
        || hints.error_output.is_some()
    {
        let mut hint_text = String::new();
        if let Some(desc) = &hints.vuln_description {
            hint_text.push_str("PRIOR INTELLIGENCE (vulnerability description):\n");
            let capped = if desc.len() > 2000 {
                &desc[..2000]
            } else {
                desc
            };
            hint_text.push_str(capped);
            hint_text.push_str("\n\n");
        }
        if let Some(error) = &hints.error_output {
            hint_text.push_str("CRASH EVIDENCE (sanitizer output — shows exact crash location):\n");
            let capped = if error.len() > 3000 {
                &error[..3000]
            } else {
                error
            };
            hint_text.push_str(capped);
            hint_text.push_str("\n\n");
        }
        if let Some(diff) = &hints.patch_diff {
            hint_text.push_str("KNOWN FIX (patch diff — indicates what the developers changed):\n");
            let capped = if diff.len() > 4000 {
                &diff[..4000]
            } else {
                diff
            };
            hint_text.push_str(capped);
            hint_text.push('\n');
        }
        tracing::debug!(
            "Analysis hints injected for {}: {} chars",
            file_str,
            hint_text.len()
        );
    }

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
    let mut pattern_hits = Vec::new();
    if let Ok(hits) = detector.detect_in_source(path, &parsed.language) {
        pattern_hits = hits;
        for hit in &pattern_hits {
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

    // --- Layer 3b: Explicit taint analysis via graph traversal ---
    // Trace source→sink paths through the Code Property Graph using
    // recursive CTEs. These paths represent actual data flow chains
    // that regex patterns can never capture.
    let taint_analyzer = skwaq_core::analysis::taint::TaintAnalyzer::new(&db, 8);
    let taint_paths = taint_analyzer.find_unsanitized_paths().unwrap_or_default();
    if !taint_paths.is_empty() {
        tracing::info!(
            "Taint analysis found {} unsanitized source→sink paths for {}",
            taint_paths.len(),
            file_str
        );
        // Store taint findings in the graph so LLM agents can see them
        for path in &taint_paths {
            let finding_id = uuid::Uuid::new_v4().to_string();
            let _ = db.execute(
                "INSERT INTO findings (id, title, evidence, agent, timestamp, \
                 investigation_id, status, severity, category) \
                 VALUES (?1, ?2, ?3, 'taint-analyzer', ?4, ?5, 'new', 'high', 'taint')",
                &[
                    &finding_id.as_str(),
                    &format!("Taint flow: {} → {}", path.source, path.sink).as_str(),
                    &format!("Unsanitized data flow path: {}", path.hops.join(" → ")).as_str(),
                    &now.as_str(),
                    &inv_id.as_str(),
                ],
            );
        }
    }

    // Also run stack-buffer-write chain detection on the source
    if let Ok(ref content) = std::fs::read_to_string(path) {
        let chains = skwaq_core::analysis::taint::detect_stack_buffer_write_chains(content);
        for chain in &chains {
            let finding_id = uuid::Uuid::new_v4().to_string();
            let _ = db.execute(
                "INSERT INTO findings (id, title, evidence, agent, timestamp, \
                 investigation_id, status, severity, category) \
                 VALUES (?1, ?2, ?3, 'taint-analyzer', ?4, ?5, 'new', 'high', 'memory')",
                &[
                    &finding_id.as_str(),
                    &format!(
                        "Stack buffer write chain: {} ({} bytes) → {}",
                        chain.buffer_var, chain.buffer_size, chain.write_api
                    )
                    .as_str(),
                    &format!(
                        "Buffer '{}' (size {}) at line {} is written by {} at line {} without bounds check",
                        chain.buffer_var,
                        chain.buffer_size,
                        chain.decl_line,
                        chain.write_api,
                        chain.write_line
                    )
                    .as_str(),
                    &now.as_str(),
                    &inv_id.as_str(),
                ],
            );
        }
        if !chains.is_empty() {
            tracing::info!(
                "Stack buffer chain detection found {} chains for {}",
                chains.len(),
                file_str
            );
        }
    }

    // Collect ALL orchestrator + taint findings and add their categories
    let orchestrator_findings = collect_findings_from_db(&db, &inv_id, "source-pattern-detector")?;
    let taint_findings = collect_findings_from_db(&db, &inv_id, "taint-analyzer")?;
    for f in orchestrator_findings.iter().chain(taint_findings.iter()) {
        pattern_categories.insert(f.category.clone());
    }

    let all_graph_findings: Vec<_> = orchestrator_findings
        .iter()
        .chain(taint_findings.iter())
        .cloned()
        .collect();
    let skip_llm_pipeline =
        should_skip_llm_pipeline_for_pattern_confidence(&pattern_hits, &all_graph_findings);

    // --- Layer 4: LLM agent pipeline ---
    if skip_llm_pipeline {
        SYNTHESIS_STATS.record_pattern_confidence_early_exit();
        tracing::info!(
            "Pattern-confidence early-exit: {} source pattern hit(s) covered {} supporting graph finding(s); skipping LLM pipeline for {}",
            pattern_hits.len(),
            orchestrator_findings.len(),
            file_str,
        );
    } else {
        run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await?;
    }

    // --- Layer 5: Synthesis — weigh all evidence ---
    // Collect ALL findings from DB (pattern + orchestrator + LLM)
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    // Synthesize: use the LLM to weigh all evidence and decide which findings are credible.
    // Unlike the old intersection filter, this preserves LLM-only findings that
    // demonstrate real understanding of the code, but it fails loudly if synthesis
    // cannot run instead of silently downgrading analysis quality.
    let synthesized = if skip_llm_pipeline {
        all_findings
    } else {
        synthesize_findings(all_findings, &pattern_categories, &db, timeout_secs).await?
    };

    let deduped = dedup_findings_by_best_severity(synthesized);

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

    let skip_llm_pipeline =
        should_skip_llm_pipeline_for_pattern_confidence(&import_hits, &orchestrator_findings);

    // LLM agent pipeline
    if skip_llm_pipeline {
        SYNTHESIS_STATS.record_pattern_confidence_early_exit();
        tracing::info!(
            "Pattern-confidence early-exit: {} binary pattern hit(s) covered {} supporting graph finding(s); skipping LLM pipeline for {}",
            import_hits.len(),
            orchestrator_findings.len(),
            file_str,
        );
    } else {
        run_llm_pipeline(&db, &inv_id, &file_str, timeout_secs).await?;
    }

    // Synthesis — weigh all evidence
    let all_findings = collect_all_findings_from_db(&db, &inv_id)?;

    let synthesized = if skip_llm_pipeline {
        all_findings
    } else {
        synthesize_findings(all_findings, &pattern_categories, &db, timeout_secs).await?
    };

    let deduped = dedup_findings_by_best_severity(synthesized);

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

    let deduped = dedup_findings_by_best_severity(all_findings);

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

    let deduped = dedup_findings_by_best_severity(all_findings);

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

fn should_skip_llm_pipeline_for_pattern_confidence(
    pattern_hits: &[DangerousApiHit],
    supporting_findings: &[DetectedFinding],
) -> bool {
    if pattern_hits.is_empty() || supporting_findings.is_empty() {
        return false;
    }

    if pattern_hits
        .iter()
        .any(|hit| !matches!(hit.severity, Severity::Critical | Severity::High))
    {
        return false;
    }

    let pattern_findings: Vec<DetectedFinding> = pattern_hits
        .iter()
        .map(|hit| DetectedFinding {
            id: format!(
                "pattern-confidence:{}:{}:{}",
                hit.danger_category, hit.function_name, hit.line
            ),
            category: hit.danger_category.to_string(),
            severity: hit.severity.to_string().to_ascii_lowercase(),
            cwes: vec![],
            file: hit.file.clone(),
            function: hit.function_name.clone(),
            line: Some(hit.line as u32),
            title: format!(
                "Dangerous pattern: {} ({}:{})",
                hit.function_name, hit.file, hit.line
            ),
        })
        .collect();

    findings_have_consensus(&pattern_findings, supporting_findings)
        && findings_have_consensus(supporting_findings, &pattern_findings)
}

/// Check whether pattern and LLM findings have consensus.
///
/// Consensus means both sources identified vulnerabilities in the same
/// functions (by normalized name) AND the same semantic pattern classes.
/// When they agree, there is no ambiguity for an LLM reviewer to resolve
/// — we can skip the expensive synthesis call entirely.
///
/// Returns `true` when every LLM finding's function+category+semantic-class
/// fingerprint is also covered by at least one pattern finding.
fn findings_have_consensus(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
) -> bool {
    // Build semantic fingerprints: (normalized_function, raw_category, semantic_class) tuples.
    // Keeping the raw category prevents unrelated findings that share a dangerous API
    // signature from being treated as consensus.
    let fingerprint = |findings: &[DetectedFinding]| -> HashSet<(String, String, String)> {
        let mut set = HashSet::new();
        for f in findings {
            let func = normalize_function_key(&f.function);
            let category = f.category.to_ascii_lowercase();
            let classes = semantic_classes_for_finding(f);
            if classes.is_empty() {
                set.insert((func, category.clone(), category));
            } else {
                for class in classes {
                    set.insert((func.clone(), category.clone(), class.as_str().to_string()));
                }
            }
        }
        set
    };

    let pattern_fp = fingerprint(pattern_findings);
    let llm_fp = fingerprint(llm_findings);

    if pattern_fp.is_empty() || llm_fp.is_empty() {
        return false;
    }

    // Consensus: every LLM fingerprint is covered by patterns.
    // We intentionally do NOT require patterns ⊆ LLM — pattern detectors
    // are high-precision and may flag things the LLM missed, which is fine.
    llm_fp.iter().all(|fp| pattern_fp.contains(fp))
}

/// Domain expertise areas for specialized synthesis prompts.
///
/// When all dual-source findings fall into a single semantic cluster,
/// the synthesis prompt is tailored with domain-specific guidance that
/// helps the LLM reviewer make more precise CONFIRM/REJECT decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpertDomain {
    MemorySafety,
    CodeExecution,
    WebDataFlow,
    FilesystemSafety,
    ArithmeticSafety,
    Crypto,
    ResourceManagement,
}

impl ExpertDomain {
    /// Map a semantic confidence cluster name to an expert domain.
    fn from_cluster(cluster: &str) -> Option<Self> {
        match cluster {
            // The semantic classifier returns fine-grained cluster names
            // (e.g. "memory_bounds") while expert routing needs coarser
            // domain groupings. Map all sub-clusters to their parent domain.
            "memory_safety"
            | "memory_bounds"
            | "memory_lifecycle"
            | "memory_allocation"
            | "initialization_safety"
            | "unsafe_api" => Some(Self::MemorySafety),
            "code_execution" | "format_string" => Some(Self::CodeExecution),
            "web_data_flow" => Some(Self::WebDataFlow),
            "filesystem_safety" => Some(Self::FilesystemSafety),
            "arithmetic_safety" => Some(Self::ArithmeticSafety),
            "crypto" => Some(Self::Crypto),
            "resource_management" => Some(Self::ResourceManagement),
            _ => None,
        }
    }

    /// Domain-specific system prompt for the synthesis reviewer.
    fn system_prompt(&self) -> &'static str {
        match self {
            Self::MemorySafety => {
                "You are a memory-safety expert reviewing vulnerability findings. \
                 You have deep knowledge of buffer overflows, use-after-free, null pointer \
                 dereferences, and heap corruption. Evaluate each finding based on whether \
                 the code path can actually reach the vulnerable operation with attacker-controlled \
                 data sizes or dangling pointers."
            }
            Self::CodeExecution => {
                "You are a code-execution security expert reviewing vulnerability findings. \
                 You specialize in command injection, deserialization attacks, and code evaluation \
                 vulnerabilities. Evaluate whether user-controlled input can actually reach the \
                 dangerous sink without adequate sanitization or type constraints."
            }
            Self::WebDataFlow => {
                "You are a web-security expert reviewing vulnerability findings. \
                 You specialize in cross-site scripting (XSS), prototype pollution, and \
                 data-flow attacks in web applications. Evaluate whether the taint path from \
                 user input to output is real and whether encoding or sanitization is missing."
            }
            Self::FilesystemSafety => {
                "You are a filesystem-security expert reviewing vulnerability findings. \
                 You specialize in path traversal, insecure temporary files, and race conditions \
                 (TOCTOU). Evaluate whether the file operations use attacker-controlled paths \
                 without canonicalization or whether race windows are exploitable."
            }
            Self::ArithmeticSafety => {
                "You are a numeric-safety expert reviewing vulnerability findings. \
                 You specialize in integer overflows, underflows, divide-by-zero conditions, \
                 and unchecked loop bounds from untrusted input. \
                 Evaluate whether arithmetic operations or loop iteration counts on \
                 attacker-influenced values can actually overflow, divide by zero, or \
                 drive unsafe looping in the given context."
            }
            Self::Crypto => {
                "You are a cryptography expert reviewing vulnerability findings. \
                 You specialize in weak algorithms, hardcoded credentials, insufficient key \
                 lengths, and missing integrity checks. Evaluate whether the cryptographic \
                 weakness is real and exploitable in the deployment context."
            }
            Self::ResourceManagement => {
                "You are a resource-management expert reviewing vulnerability findings. \
                 You specialize in resource leaks, file descriptor exhaustion, unclosed handles, \
                 and improper cleanup in error paths. Evaluate whether allocated resources \
                 (memory, handles, connections) are released on all code paths including \
                 error and exception paths."
            }
        }
    }

    /// Domain-specific preamble injected into the synthesis prompt body.
    fn prompt_preamble(&self) -> &'static str {
        match self {
            Self::MemorySafety => {
                "All findings below relate to MEMORY SAFETY vulnerabilities.\n\
                 Focus on: buffer bounds, allocation lifetimes, pointer validity, and \
                 whether attacker-controlled sizes reach vulnerable operations.\n\
                 CONFIRM findings where a concrete overflow, UAF, or null-deref path exists.\n\
                 REJECT findings where bounds checks, safe wrappers, or allocator guards prevent exploitation.\n\n"
            }
            Self::CodeExecution => {
                "All findings below relate to CODE EXECUTION vulnerabilities.\n\
                 Focus on: injection sinks, deserialization gadgets, eval-like constructs, and \
                 whether unsanitized input reaches dangerous APIs.\n\
                 CONFIRM findings where attacker input flows to execution sinks without filtering.\n\
                 REJECT findings where input is validated, typed, or sandboxed before reaching the sink.\n\n"
            }
            Self::WebDataFlow => {
                "All findings below relate to WEB DATA-FLOW vulnerabilities.\n\
                 Focus on: output encoding, DOM manipulation, prototype chains, and \
                 whether user input reaches browser-rendered output unescaped.\n\
                 CONFIRM findings where taint flows from input to output without encoding.\n\
                 REJECT findings where framework auto-escaping or CSP prevents exploitation.\n\n"
            }
            Self::FilesystemSafety => {
                "All findings below relate to FILESYSTEM SAFETY vulnerabilities.\n\
                 Focus on: path canonicalization, temporary file predictability, symlink attacks, \
                 and TOCTOU race windows.\n\
                 CONFIRM findings where attacker-controlled paths bypass validation or races are exploitable.\n\
                 REJECT findings where paths are resolved, permissions restrict access, or atomicity is ensured.\n\n"
            }
            Self::ArithmeticSafety => {
                "All findings below relate to ARITHMETIC SAFETY vulnerabilities.\n\
                 Focus on: integer width, signedness, overflow wrapping behavior, \
                 divisor validation, and loop bound validation.\n\
                 CONFIRM findings where attacker-influenced arithmetic can wrap, divide by zero, \
                 or control loop iteration counts without effective bounds checks.\n\
                 REJECT findings where range checks, saturating arithmetic, type constraints, \
                 or explicit iteration limits prevent overflow or unsafe looping.\n\n"
            }
            Self::Crypto => {
                "All findings below relate to CRYPTOGRAPHIC vulnerabilities.\n\
                 Focus on: algorithm strength, key management, randomness sources, and \
                 integrity verification.\n\
                 CONFIRM findings where weak algorithms, hardcoded keys, or missing MAC checks are used.\n\
                 REJECT findings where the cryptographic choice is appropriate for the threat model.\n\n"
            }
            Self::ResourceManagement => {
                "All findings below relate to RESOURCE MANAGEMENT vulnerabilities.\n\
                 Focus on: resource allocation/deallocation symmetry, error-path cleanup, \
                 handle lifetime tracking, and leak-on-exception scenarios.\n\
                 CONFIRM findings where resources are allocated but not freed on all exit paths.\n\
                 REJECT findings where RAII, try-finally, defer, or other cleanup mechanisms ensure release.\n\n"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SynthesisRoute {
    ConsensusEarlyExit,
    SemanticConfidenceFastPath,
    /// All findings share a single semantic cluster — use domain-expert prompt.
    ExpertRouted(ExpertDomain),
    FullSynthesis,
}

fn semantic_confidence_clusters(finding: &DetectedFinding) -> HashSet<&'static str> {
    semantic_classes_for_finding(finding)
        .into_iter()
        .map(|class| class.confidence_cluster())
        .collect()
}

fn has_semantic_specificity(finding: &DetectedFinding) -> bool {
    !semantic_classes_for_finding(finding).is_empty()
}

fn same_function_and_category(pattern: &DetectedFinding, llm: &DetectedFinding) -> bool {
    normalize_function_key(&pattern.function) == normalize_function_key(&llm.function)
        && !has_semantic_specificity(pattern)
        && !has_semantic_specificity(llm)
        && pattern.category.eq_ignore_ascii_case(&llm.category)
}

fn same_function_and_semantic_cluster(pattern: &DetectedFinding, llm: &DetectedFinding) -> bool {
    if normalize_function_key(&pattern.function) != normalize_function_key(&llm.function) {
        return false;
    }

    let pattern_clusters = semantic_confidence_clusters(pattern);
    let llm_clusters = semantic_confidence_clusters(llm);

    !pattern_clusters.is_empty()
        && !llm_clusters.is_empty()
        && pattern_clusters
            .iter()
            .any(|cluster| llm_clusters.contains(cluster))
}

fn cwe_families_for_finding(finding: &DetectedFinding) -> HashSet<u32> {
    scoring::inferred_finding_cwes(finding)
        .into_iter()
        .map(scoring::cwe_family)
        .collect()
}

/// Two findings overlap when they share at least one CWE family root.
///
/// This catches cases like pattern="memory" (CWE-119 family) and
/// LLM="integer_overflow" (CWE-190 family) where both map to distinct
/// families — those do NOT overlap, preserving accuracy.  But
/// pattern="memory" and LLM="memory" sharing CWE-119 DO overlap.
fn same_cwe_family_overlap(a: &DetectedFinding, b: &DetectedFinding) -> bool {
    let a_families = cwe_families_for_finding(a);
    let b_families = cwe_families_for_finding(b);
    !a_families.is_empty()
        && !b_families.is_empty()
        && a_families.iter().any(|f| b_families.contains(f))
}

fn findings_have_semantic_confidence(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
) -> bool {
    if pattern_findings.is_empty() || llm_findings.is_empty() {
        return false;
    }

    let is_related = |pattern: &DetectedFinding, llm: &DetectedFinding| -> bool {
        same_function_and_category(pattern, llm)
            || same_function_and_semantic_cluster(pattern, llm)
            || same_cwe_family_overlap(pattern, llm)
    };

    pattern_findings
        .iter()
        .all(|pattern| llm_findings.iter().any(|llm| is_related(pattern, llm)))
        && llm_findings.iter().all(|llm| {
            pattern_findings
                .iter()
                .any(|pattern| is_related(pattern, llm))
        })
}

/// Determine the dominant semantic cluster when ALL findings share exactly one.
///
/// Returns `Some(ExpertDomain)` when every pattern and LLM finding maps to the
/// same single cluster. Returns `None` if findings span multiple clusters or
/// any finding has no cluster.
fn dominant_expert_domain(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
) -> Option<ExpertDomain> {
    let mut clusters: HashSet<&'static str> = HashSet::new();

    for finding in pattern_findings.iter().chain(llm_findings.iter()) {
        let finding_clusters = semantic_confidence_clusters(finding);
        if finding_clusters.is_empty() {
            return None; // Unclassifiable finding — cannot route to expert
        }
        clusters.extend(finding_clusters);
    }

    // "unsafe_api" is a meta-cluster that overlaps with specific domains
    // (e.g., strcpy is both buffer_overflow/memory_bounds and unsafe_api).
    // Remove it when a more specific cluster is present.
    if clusters.len() > 1 {
        clusters.remove("unsafe_api");
    }

    if clusters.len() == 1 {
        clusters
            .into_iter()
            .next()
            .and_then(ExpertDomain::from_cluster)
    } else {
        None
    }
}

fn select_synthesis_route(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
) -> SynthesisRoute {
    if findings_have_consensus(pattern_findings, llm_findings) {
        return SynthesisRoute::ConsensusEarlyExit;
    }
    if let Some(domain) = dominant_expert_domain(pattern_findings, llm_findings) {
        return SynthesisRoute::ExpertRouted(domain);
    }
    if findings_have_semantic_confidence(pattern_findings, llm_findings) {
        return SynthesisRoute::SemanticConfidenceFastPath;
    }
    SynthesisRoute::FullSynthesis
}

/// Synthesize findings from both pattern detection and LLM agents.
///
/// Models how a human security team works:
/// - Junior analysts (patterns) flag potential issues
/// - Senior researchers (LLM agents) investigate deeply
/// - Lead reviewer (this function) makes final call, weighing all evidence
///
/// When both sources agree (consensus), findings pass through without an
/// LLM synthesis call. Only disagreement cases pay the synthesis cost.
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
        if f.title.starts_with("Dangerous pattern:")
            || f.title.starts_with("Binary import:")
            || f.title.starts_with("Cross-file graph:")
        {
            pattern_findings.push(f.clone());
        } else {
            llm_findings.push(f.clone());
        }
    }

    // When only patterns found something, trust them (patterns are high-precision).
    // When only LLM agents found something, those findings MUST still go through
    // synthesis — LLM-only findings are lower precision and need validation.
    // The old behavior of trusting LLM-only findings directly was a precision leak.
    if llm_findings.is_empty() {
        // Pattern-only: high precision, trust directly
        return Ok(all_findings);
    }
    if pattern_findings.is_empty() {
        // LLM-only: run synthesis with empty pattern set to validate
        tracing::info!(
            "LLM-only findings ({} total): running synthesis validation",
            llm_findings.len(),
        );
    }

    let synthesis_result = match select_synthesis_route(&pattern_findings, &llm_findings) {
        SynthesisRoute::ConsensusEarlyExit => {
            SYNTHESIS_STATS.record_consensus_early_exit();
            tracing::info!(
                "Consensus early-exit: {} pattern + {} LLM findings agree, skipping LLM synthesis",
                pattern_findings.len(),
                llm_findings.len(),
            );
            return Ok(all_findings);
        }
        SynthesisRoute::SemanticConfidenceFastPath => {
            SYNTHESIS_STATS.record_semantic_confidence_fast_path();
            tracing::info!(
                "Semantic-confidence fast-path: {} pattern + {} LLM findings share same-function alignment",
                pattern_findings.len(),
                llm_findings.len(),
            );
            llm_synthesize_with_limits(&pattern_findings, &llm_findings, timeout_secs, None).await
        }
        SynthesisRoute::ExpertRouted(domain) => {
            SYNTHESIS_STATS.record_expert_routed();
            tracing::info!(
                "Expert-routed synthesis ({:?}): {} pattern + {} LLM findings in same domain",
                domain,
                pattern_findings.len(),
                llm_findings.len(),
            );
            llm_synthesize_expert(&pattern_findings, &llm_findings, timeout_secs, domain).await
        }
        SynthesisRoute::FullSynthesis => {
            llm_synthesize(&pattern_findings, &llm_findings, timeout_secs).await
        }
    };

    match synthesis_result {
        Ok(synthesized) => {
            SYNTHESIS_STATS.record_llm_synthesis();
            Ok(synthesized)
        }
        Err(e) => {
            // Synthesis failed. Per the no-fallback design principle, we do NOT
            // silently return all findings. Instead, return ONLY the pattern
            // findings (high precision) and drop the unvalidated LLM findings.
            // This preserves precision at the cost of recall when the LLM is
            // unavailable, which is the correct trade-off.
            SYNTHESIS_STATS.record_fallback();
            tracing::warn!(
                "LLM synthesis failed — keeping {} pattern findings, dropping {} unvalidated LLM findings: {}",
                pattern_findings.len(),
                llm_findings.len(),
                e,
            );
            Ok(pattern_findings)
        }
    }
}

/// Call the LLM to evaluate findings like a lead security reviewer.
async fn llm_synthesize(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    timeout_secs: u64,
) -> anyhow::Result<Vec<DetectedFinding>> {
    llm_synthesize_with_limits(pattern_findings, llm_findings, timeout_secs, None).await
}

/// Call the LLM with a domain-expert synthesis prompt.
///
/// Uses the same synthesis pipeline as [`llm_synthesize_with_limits`] but
/// swaps the generic system prompt and preamble for domain-specific ones.
/// The expert prompt gives the LLM reviewer focused guidance on what
/// constitutes a real vs. false-positive finding in the given domain.
async fn llm_synthesize_expert(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    timeout_secs: u64,
    domain: ExpertDomain,
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

    // Build domain-expert synthesis prompt
    let mut prompt = String::from(
        "You are evaluating vulnerability findings from two sources:\n\
         1. PATTERN DETECTION (automated regex-based, high precision, limited understanding)\n\
         2. LLM AGENTS (AI-powered deep analysis, better understanding, may hallucinate)\n\n\
         Your job: decide which findings are REAL vulnerabilities.\n\n",
    );
    prompt.push_str(domain.prompt_preamble());
    prompt.push_str(
        "For each finding, respond with one line:\n\
         CONFIRM <id> — strong evidence from one or both sources\n\
         REJECT <id> — insufficient evidence, likely false positive\n\n",
    );

    append_findings_for_prompt(&mut prompt, "=== PATTERN FINDINGS ===\n", pattern_findings);
    append_findings_for_prompt(&mut prompt, "\n=== LLM AGENT FINDINGS ===\n", llm_findings);
    prompt.push_str("\nEvaluate each finding. Respond with CONFIRM or REJECT for each ID.\n");

    let budget_amount = config.analysis.default_token_budget;
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);
    let model = &config.llm.copilot.model;

    let response_text = execute_synthesis_completion(
        &client,
        model,
        domain.system_prompt(),
        &prompt,
        timeout_secs,
        &mut budget,
    )
    .await?;
    let decisions = parse_synthesis_decisions(&response_text);

    // Expert-routed synthesis skips REVIEW refinement — the domain-specific
    // prompt is precise enough that findings are either CONFIRM or REJECT.
    let synthesized =
        apply_rejected_synthesis_decisions(pattern_findings, llm_findings, &decisions.rejected_ids);

    Ok(synthesized)
}

async fn llm_synthesize_with_limits(
    pattern_findings: &[DetectedFinding],
    llm_findings: &[DetectedFinding],
    timeout_secs: u64,
    max_budget_override: Option<u64>,
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
         Your job: decide which findings are REAL vulnerabilities vs false positives.\n\
         Your default stance is SKEPTICAL. Most automated findings are noise.\n\n\
         For each finding, respond with one line:\n\
         CONFIRM <id> — concrete evidence that the vulnerability is real and exploitable\n\
         REVIEW <id> — plausible but evidence is incomplete; needs stricter second pass\n\
         REJECT <id> — insufficient evidence, pattern matched safe code, or LLM hallucination\n\n\
         REJECT a finding when:\n\
         - The detected API is used safely (e.g. printf with a literal format string)\n\
         - The finding is speculative without evidence of data flow to a dangerous sink\n\
         - The LLM agent described a generic vulnerability class without pointing to specific code\n\
         - Safe wrappers (strncpy, snprintf) are used correctly with proper bounds\n\n\
         CONFIRM only when:\n\
         - There is a clear path from untrusted input to a dangerous operation\n\
         - The code lacks bounds checking, validation, or sanitization on that path\n\
         - Both sources agree, or one source provides strong concrete evidence\n\n\
         When in doubt, REJECT. False positives are worse than false negatives.\n\n",
    );

    append_findings_for_prompt(&mut prompt, "=== PATTERN FINDINGS ===\n", pattern_findings);
    append_findings_for_prompt(&mut prompt, "\n=== LLM AGENT FINDINGS ===\n", llm_findings);

    prompt.push_str("\nEvaluate each finding. Respond with CONFIRM or REJECT for each ID.\n");

    // Use full budget or override if specified
    let budget_amount = max_budget_override.unwrap_or(config.analysis.default_token_budget);
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

    dedup_findings_by_best_severity(
        llm_findings
            .iter()
            .chain(pattern_findings.iter())
            .filter(|finding| !rejected_ids.contains(&finding.id.to_ascii_lowercase()))
            .cloned(),
    )
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

/// Cached reasoning client for source-only pipelines.
static REASONING_CLIENT: tokio::sync::OnceCell<skwaq_core::llm::Client> =
    tokio::sync::OnceCell::const_new();

/// Cached full pipeline clients for pipelines that require decompilation.
static FULL_PIPELINE_CLIENTS: tokio::sync::OnceCell<skwaq_core::agents::PipelineClients> =
    tokio::sync::OnceCell::const_new();

/// Open the default durable memory store for agents.
///
/// Shared durable memory store — opened once, reused across all parallel
/// gym cases. LadybugDB supports multiple connections from the same Database
/// handle within one process; it's concurrent *file opens* that crash.
static MEMORY_STORE: std::sync::OnceLock<Option<skwaq_core::memory::MemoryStore>> =
    std::sync::OnceLock::new();

/// Returns `None` if memory cannot be initialized (non-fatal — agents
/// simply run without cross-run learning).
fn open_memory_store() -> Option<skwaq_core::memory::MemoryStore> {
    MEMORY_STORE
        .get_or_init(|| match skwaq_core::memory::MemoryStore::open_default() {
            Ok(store) => {
                tracing::info!("Durable agent memory enabled (shared across gym cases)");
                Some(store)
            }
            Err(e) => {
                tracing::warn!("Could not open durable memory store: {e}. Running without memory.");
                None
            }
        })
        .clone()
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
    let pipeline = pipeline_for_target(file_str);

    // Create or reuse cached LLM clients. Source-only pipelines cache the
    // reasoning lane independently so they do not force decompilation auth;
    // binary/decompile pipelines still cache the full pair together.
    let pipeline_clients = cached_pipeline_clients(&config, &pipeline, file_str).await?;
    let budget_amount = config.analysis.default_token_budget;
    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    let target = std::path::Path::new(file_str)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_str.to_string());

    // KG pre-injection: query knowledge packs for relevant context and store
    // as investigation metadata so agents can access it via lookup_knowledge.
    inject_knowledge_context(db, inv_id, file_str);

    tracing::info!("Running LLM agent pipeline on {}", target);

    // Use durable memory if available so agents learn across benchmark runs.
    let memory = open_memory_store();

    // Use debate for source deep pipeline (exploit-analyst vs defense-analyst)
    let use_debate = should_use_debate(file_str);
    let debate = skwaq_core::agents::deep_pipeline_debate();
    // Debate runs after the vuln-hunter stage (index 2 in source deep pipeline)
    let debate_after_stage = 3;

    let pipeline_result = if use_debate {
        // Deep source pipeline with exploit/defense debate
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            pipeline.run_with_debate(
                &target,
                inv_id,
                db,
                pipeline_clients.clone(),
                &mut budget,
                &debate,
                debate_after_stage,
            ),
        )
        .await
    } else if let Some(ref mem) = memory {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            pipeline.run_with_memory(
                &target,
                inv_id,
                db,
                pipeline_clients.clone(),
                &mut budget,
                mem,
            ),
        )
        .await
    } else {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            pipeline.run(&target, inv_id, db, pipeline_clients.clone(), &mut budget),
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

/// Pre-inject knowledge pack context into the investigation so agents
/// can access it via lookup_knowledge without needing to call it explicitly.
fn inject_knowledge_context(db: &GraphDb, _inv_id: &str, file_str: &str) {
    let lang = std::path::Path::new(file_str)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("c");

    // Query relevant knowledge packs based on language
    let queries = match lang {
        "java" => vec!["methodology", "cwe-families", "cwe-79", "cwe-89"],
        "py" | "python" => vec!["methodology", "cwe-families", "cwe-78", "cwe-502"],
        "js" | "ts" => vec!["methodology", "cwe-families", "cwe-79", "cwe-1321"],
        _ => vec!["methodology", "cwe-families", "cwe-119", "cwe-134"],
    };

    for query in queries {
        if let Ok(results) = skwaq_core::knowledge::search_knowledge(Some(db), query) {
            if !results.is_empty() {
                tracing::debug!(
                    "KG pre-injection: {} returned {} results for {}",
                    query,
                    results.len(),
                    file_str
                );
            }
        }
    }
}

fn pipeline_for_target(file_str: &str) -> skwaq_core::agents::AnalysisPipeline {
    if skwaq_core::source::is_source_file(Path::new(file_str)) {
        // Use deep source pipeline with debate stages for maximum detection
        skwaq_core::agents::source_deep_pipeline_for_target(file_str)
    } else {
        skwaq_core::agents::deep_pipeline_for_target(file_str)
    }
}

/// Check if the source pipeline should use the debate pattern.
/// Returns true for source files (deep source pipeline includes debate stages).
fn should_use_debate(file_str: &str) -> bool {
    skwaq_core::source::is_source_file(Path::new(file_str))
}

async fn cached_pipeline_clients(
    config: &Config,
    pipeline: &skwaq_core::agents::AnalysisPipeline,
    file_str: &str,
) -> anyhow::Result<skwaq_core::agents::PipelineClients> {
    if pipeline.requires_decompilation_client() {
        return FULL_PIPELINE_CLIENTS
            .get_or_try_init(|| async {
                skwaq_core::llm::ensure_benchmark_copilot_ready_for_pipeline(
                    &config.llm,
                    pipeline.requires_reasoning_client(),
                    pipeline.requires_decompilation_client(),
                )
                .await?;
                let (reasoning_client, decompilation_client) = skwaq_core::llm::create_pipeline_clients(
                    &config.llm,
                    pipeline.requires_reasoning_client(),
                    pipeline.requires_decompilation_client(),
                )
                .await?;
                Ok::<skwaq_core::agents::PipelineClients, anyhow::Error>(
                    skwaq_core::agents::PipelineClients::from_optional(
                        reasoning_client,
                        decompilation_client,
                    ),
                )
            })
            .await
            .with_context(|| {
                format!(
                    "Hybrid benchmark analysis requires working reasoning/decompilation clients for {}",
                    file_str
                )
            })
            .cloned();
    }

    if let Some(full_clients) = FULL_PIPELINE_CLIENTS.get() {
        return Ok(skwaq_core::agents::PipelineClients::from_optional(
            full_clients.reasoning.clone(),
            None,
        ));
    }

    let reasoning_client = REASONING_CLIENT
        .get_or_try_init(|| async {
            skwaq_core::llm::ensure_benchmark_copilot_ready_for_pipeline(&config.llm, true, false)
                .await?;
            let (reasoning_client, _) =
                skwaq_core::llm::create_pipeline_clients(&config.llm, true, false).await?;
            reasoning_client.ok_or_else(|| {
                anyhow::anyhow!(
                    "Hybrid benchmark analysis requested a reasoning lane, but no reasoning client was created"
                )
            })
        })
        .await
        .with_context(|| {
            format!(
                "Hybrid benchmark analysis requires a working reasoning client for {}",
                file_str
            )
        })?
        .clone();

    Ok(skwaq_core::agents::PipelineClients::from_optional(
        Some(reasoning_client),
        None,
    ))
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

fn dedup_findings_by_best_severity(
    findings: impl IntoIterator<Item = DetectedFinding>,
) -> Vec<DetectedFinding> {
    let mut kept: Vec<DetectedFinding> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();

    for finding in findings {
        let key = dedup_key(&finding);
        match positions.get(&key).copied() {
            Some(index) => {
                if severity_rank(&finding.severity) < severity_rank(&kept[index].severity) {
                    kept[index] = finding;
                }
            }
            None => {
                positions.insert(key, kept.len());
                kept.push(finding);
            }
        }
    }

    kept
}

fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
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

        let deduped = dedup_findings_by_best_severity(findings);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].id, "2");
    }

    #[test]
    fn test_pipeline_for_target_uses_reasoning_only_for_source_files() {
        let pipeline = pipeline_for_target("tests/fixtures/buffer_overflow.c");
        assert!(pipeline.requires_reasoning_client());
        assert!(!pipeline.requires_decompilation_client());
    }

    #[test]
    fn test_pipeline_for_target_uses_decompilation_for_binaries() {
        let pipeline = pipeline_for_target("tests/fixtures/binaries/buffer_overflow_O0");
        assert!(pipeline.requires_reasoning_client());
        assert!(pipeline.requires_decompilation_client());
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

        let deduped = dedup_findings_by_best_severity(findings);
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

        let deduped = dedup_findings_by_best_severity(findings);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_preserves_first_finding_on_severity_tie() {
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
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "LLM: buffer overflow in strcpy".into(),
            },
        ];

        let deduped = dedup_findings_by_best_severity(findings);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].id, "1");
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

        assert_eq!(
            semantic_prompt_hint(&finding),
            "buffer_overflow, unsafe_api_usage"
        );
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
    fn test_semantic_prompt_hint_uses_use_after_free_category() {
        let finding = DetectedFinding {
            id: "1".into(),
            category: "use_after_free".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "free".into(),
            line: Some(10),
            title: "Dangerous API: free".into(),
        };

        assert_eq!(semantic_prompt_hint(&finding), "use_after_free");
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
    fn test_apply_synthesis_prefers_higher_severity_for_same_key() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "LLM: buffer overflow in strcpy".into(),
        }];
        let response = "CONFIRM p1\nCONFIRM l1\n";
        let result = apply_synthesis_decisions(&pattern, &llm, response);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "p1");
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

        // Pattern-only findings should pass through directly (high precision)
        let findings = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(1),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let result = synthesize_findings(findings.clone(), &cats, &db, 30)
            .await
            .unwrap();
        assert_eq!(
            result.len(),
            1,
            "Pattern-only findings should pass through directly"
        );
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
        // When both sources have findings, synthesis must track its outcome
        // via one of: llm_synthesis, consensus_early_exit, or failed counter.
        let db = GraphDb::in_memory().unwrap();
        let cats = HashSet::new();

        // Deliberately use DIFFERENT categories/functions so there is NO consensus
        // and the code falls through to full LLM synthesis.
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
        let before_consensus = stats.consensus_early_exit_count.load(Ordering::Relaxed);
        let before_fallback = stats.fallback_count.load(Ordering::Relaxed);
        let before_failed = stats.failed_count.load(Ordering::Relaxed);

        let result = synthesize_findings(findings, &cats, &db, 30).await;
        // With graceful fallback, synthesis always returns Ok — either via
        // LLM synthesis, consensus, or fallback (keeping all findings).
        let findings = result.expect("synthesize_findings should not fail with graceful fallback");
        assert!(
            findings.len() <= 2,
            "Synthesis should return a bounded subset of the candidate findings"
        );

        let after_llm = stats.llm_synthesis_count.load(Ordering::Relaxed);
        let after_consensus = stats.consensus_early_exit_count.load(Ordering::Relaxed);
        let after_fallback = stats.fallback_count.load(Ordering::Relaxed);
        let after_failed = stats.failed_count.load(Ordering::Relaxed);

        // One of the four counters must increase.
        let total_increase = (after_llm - before_llm)
            + (after_consensus - before_consensus)
            + (after_fallback - before_fallback)
            + (after_failed - before_failed);
        assert!(
            total_increase > 0,
            "Synthesis must track its outcome: llm_delta={}, consensus_delta={}, fallback_delta={}, failed_delta={} (none changed!)",
            after_llm - before_llm,
            after_consensus - before_consensus,
            after_fallback - before_fallback,
            after_failed - before_failed,
        );
    }

    #[test]
    fn test_synthesis_stats_report() {
        let stats = SynthesisStats::new();
        stats.record_pattern_confidence_early_exit();
        stats.record_semantic_confidence_fast_path();
        stats.record_llm_synthesis();
        stats.record_llm_synthesis();
        stats.record_consensus_early_exit();
        stats.record_fallback();
        stats.record_failure();
        // Just verify it doesn't panic — the output goes to tracing/eprintln
        stats.report();
    }

    #[test]
    fn test_consensus_same_function_same_class() {
        // Both sources find buffer overflow in strcpy → consensus
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "LLM: buffer overflow in strcpy".into(),
        }];
        assert!(
            findings_have_consensus(&pattern, &llm),
            "Same function + same semantic class should be consensus"
        );
    }

    #[test]
    fn test_no_consensus_different_functions() {
        // Pattern finds strcpy, LLM finds injection in exec → no consensus
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "injection".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "exec".into(),
            line: Some(20),
            title: "LLM: command injection in exec".into(),
        }];
        assert!(
            !findings_have_consensus(&pattern, &llm),
            "Different functions and categories should NOT be consensus"
        );
    }

    #[test]
    fn test_no_consensus_same_function_different_class() {
        // Both target the same generic function but with different vulnerability classes
        // that don't share a semantic classification (no well-known API name).
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "race-condition".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "process_request".into(),
            line: Some(10),
            title: "Dangerous pattern: process_request".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "auth-bypass".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "process_request".into(),
            line: Some(10),
            title: "LLM: auth bypass in process_request".into(),
        }];
        assert!(
            !findings_have_consensus(&pattern, &llm),
            "Same function but different classes should NOT be consensus"
        );
    }

    #[test]
    fn test_no_consensus_empty_findings() {
        let pattern: Vec<DetectedFinding> = vec![];
        let llm: Vec<DetectedFinding> = vec![];
        assert!(
            !findings_have_consensus(&pattern, &llm),
            "Empty findings should NOT be consensus"
        );
    }

    #[tokio::test]
    async fn test_consensus_early_exit_returns_all_findings() {
        // When consensus is detected, ALL original findings should be returned
        // (no LLM filtering).
        let db = GraphDb::in_memory().unwrap();
        let cats = HashSet::new();

        let findings = vec![
            DetectedFinding {
                id: "p1".into(),
                category: "memory".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "t.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "Dangerous pattern: strcpy".into(),
            },
            DetectedFinding {
                id: "l1".into(),
                category: "memory".into(),
                severity: "critical".into(),
                cwes: vec![],
                file: "t.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "LLM: buffer overflow in strcpy".into(),
            },
        ];

        let stats = synthesis_stats();
        let before = stats.consensus_early_exit_count.load(Ordering::Relaxed);

        let result = synthesize_findings(findings, &cats, &db, 30).await.unwrap();

        let after = stats.consensus_early_exit_count.load(Ordering::Relaxed);

        // These two findings have the same function and semantic class (memory/strcpy)
        // so consensus should fire.
        assert!(
            after > before,
            "Consensus counter should increase for agreeing findings"
        );
        assert_eq!(
            result.len(),
            2,
            "Consensus early-exit should return all original findings"
        );
    }

    fn dangerous_hit(function_name: &str, category: &str, severity: Severity) -> DangerousApiHit {
        DangerousApiHit {
            function_name: function_name.into(),
            library: "test".into(),
            reason: "test hit".into(),
            danger_category: match category {
                "memory" => skwaq_core::analysis::DangerCategory::Memory,
                "injection" => skwaq_core::analysis::DangerCategory::Injection,
                "format_string" => skwaq_core::analysis::DangerCategory::FormatString,
                "crypto" => skwaq_core::analysis::DangerCategory::Crypto,
                "resource_leak" => skwaq_core::analysis::DangerCategory::ResourceLeak,
                "resource_exhaustion" => skwaq_core::analysis::DangerCategory::ResourceExhaustion,
                "use_after_free" => skwaq_core::analysis::DangerCategory::UseAfterFree,
                "invalid_free" => skwaq_core::analysis::DangerCategory::InvalidFree,
                "access_control" => skwaq_core::analysis::DangerCategory::AccessControl,
                "information_exposure" => skwaq_core::analysis::DangerCategory::InformationExposure,
                "error_handling" => skwaq_core::analysis::DangerCategory::ErrorHandling,
                "type_confusion" => skwaq_core::analysis::DangerCategory::TypeConfusion,
                other => panic!("unsupported test category: {other}"),
            },
            severity,
            file: "test.c".into(),
            line: 10,
        }
    }

    #[test]
    fn test_pattern_confidence_requires_support_for_critical_hits() {
        let pattern_hits = vec![dangerous_hit("strcpy", "memory", Severity::Critical)];

        assert!(!should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &[],
        ));
    }

    #[test]
    fn test_pattern_confidence_requires_support_for_high_only_hits() {
        let pattern_hits = vec![dangerous_hit("sprintf", "format_string", Severity::High)];

        assert!(!should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &[],
        ));
    }

    #[test]
    fn test_pattern_confidence_allows_multiple_high_hits_with_aligned_support() {
        let pattern_hits = vec![
            dangerous_hit("render", "format_string", Severity::High),
            dangerous_hit("render", "format_string", Severity::High),
        ];
        let supporting = vec![DetectedFinding {
            id: "o1".into(),
            category: "format_string".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "render".into(),
            line: Some(42),
            title: "Orchestrator: format string risk".into(),
        }];

        assert!(should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &supporting,
        ));
    }

    #[test]
    fn test_pattern_confidence_allows_critical_hits_with_aligned_support() {
        let pattern_hits = vec![dangerous_hit("strcpy", "memory", Severity::Critical)];
        let supporting = vec![DetectedFinding {
            id: "o1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(42),
            title: "Orchestrator: buffer overflow risk".into(),
        }];

        assert!(should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &supporting,
        ));
    }

    #[test]
    fn test_pattern_confidence_rejects_supporting_mismatch() {
        let pattern_hits = vec![dangerous_hit("strcpy", "memory", Severity::Critical)];
        let supporting = vec![DetectedFinding {
            id: "o1".into(),
            category: "injection".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "exec".into(),
            line: Some(42),
            title: "Orchestrator: command injection risk".into(),
        }];

        assert!(!should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &supporting,
        ));
    }

    #[test]
    fn test_pattern_confidence_rejects_medium_hits() {
        let pattern_hits = vec![dangerous_hit("memcpy", "memory", Severity::Medium)];

        assert!(!should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &[],
        ));
    }

    #[test]
    fn test_pattern_confidence_requires_all_patterns_to_be_corroborated() {
        let pattern_hits = vec![
            dangerous_hit("strcpy", "memory", Severity::Critical),
            dangerous_hit("printf", "format_string", Severity::High),
        ];
        let supporting = vec![DetectedFinding {
            id: "o1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(42),
            title: "Orchestrator: buffer overflow risk".into(),
        }];

        assert!(!should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &supporting,
        ));
    }

    #[test]
    fn test_pattern_confidence_rejects_extra_uncorroborated_local_findings() {
        let pattern_hits = vec![dangerous_hit("strcpy", "memory", Severity::Critical)];
        let supporting = vec![
            DetectedFinding {
                id: "o1".into(),
                category: "memory".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(42),
                title: "Orchestrator: buffer overflow risk".into(),
            },
            DetectedFinding {
                id: "o2".into(),
                category: "injection".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "system".into(),
                line: Some(7),
                title: "Orchestrator: shell injection risk".into(),
            },
        ];

        assert!(!should_skip_llm_pipeline_for_pattern_confidence(
            &pattern_hits,
            &supporting,
        ));
    }

    #[test]
    fn test_consensus_takes_precedence_over_semantic_confidence() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy".into(),
            line: Some(10),
            title: "Dangerous pattern: copy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy".into(),
            line: Some(11),
            title: "LLM: memory corruption in copy".into(),
        }];

        assert!(findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::ConsensusEarlyExit
        );
    }

    #[test]
    fn test_semantic_confidence_rejects_different_memory_subclusters_same_function() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy_wrapper".into(),
            line: Some(10),
            title: "Dangerous pattern: buffer overflow in copy wrapper".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy_wrapper".into(),
            line: Some(11),
            title: "LLM: use-after-free in copy wrapper".into(),
        }];

        assert!(!same_function_and_category(&pattern[0], &llm[0]));
        assert!(!same_function_and_semantic_cluster(&pattern[0], &llm[0]));
        assert!(!same_cwe_family_overlap(&pattern[0], &llm[0]));
        assert!(!findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::FullSynthesis
        );
    }

    #[test]
    fn test_semantic_confidence_matches_same_arithmetic_cluster_same_function() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "integer_overflow".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "scale".into(),
            line: Some(10),
            title: "Dangerous pattern: integer overflow in scale".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "divide_by_zero".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "scale".into(),
            line: Some(11),
            title: "LLM: division by zero in scale".into(),
        }];

        assert!(findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::ExpertRouted(ExpertDomain::ArithmeticSafety)
        );
    }

    #[test]
    fn test_semantic_confidence_rejects_same_function_memory_category_when_semantics_differ() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "handler".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "handler".into(),
            line: Some(11),
            title: "LLM: null pointer dereference after unchecked malloc".into(),
        }];

        assert!(!same_function_and_category(&pattern[0], &llm[0]));
        assert!(!findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::FullSynthesis
        );
    }

    #[test]
    fn test_semantic_confidence_matches_same_cwe_family_different_functions() {
        // Both "memory" → same CWE-119 family, even with different functions.
        // This qualifies for cheap synthesis (fast path), not full synthesis.
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy".into(),
            line: Some(10),
            title: "Dangerous pattern: copy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "parse".into(),
            line: Some(11),
            title: "LLM: memory corruption in parse".into(),
        }];

        assert!(findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::SemanticConfidenceFastPath
        );
    }

    #[test]
    fn test_semantic_confidence_rejects_different_memory_families_across_functions() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "alloc".into(),
            line: Some(11),
            title: "LLM: null pointer dereference after unchecked malloc".into(),
        }];

        assert!(!same_cwe_family_overlap(&pattern[0], &llm[0]));
        assert!(!findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::FullSynthesis
        );
    }

    #[test]
    fn test_semantic_confidence_rejects_different_cwe_families() {
        // "memory" (CWE-119 family) vs "injection" (CWE-74 family) — no overlap.
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy".into(),
            line: Some(10),
            title: "Dangerous pattern: copy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "injection".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "exec".into(),
            line: Some(20),
            title: "LLM: command injection in exec".into(),
        }];

        assert!(!findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::FullSynthesis
        );
    }

    #[test]
    fn test_semantic_confidence_rejects_unknown_categories() {
        // Categories not in category_to_cwes produce empty CWE sets → no overlap.
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "custom-category".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "handler".into(),
            line: Some(10),
            title: "Dangerous pattern: handler".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "other-unknown".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "dispatch".into(),
            line: Some(20),
            title: "LLM: suspicious dispatch".into(),
        }];

        assert!(!findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::FullSynthesis
        );
    }

    #[test]
    fn test_cwe_family_overlap_same_category() {
        let a = DetectedFinding {
            id: "a".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "f".into(),
            line: Some(1),
            title: "x".into(),
        };
        let b = DetectedFinding {
            id: "b".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "g".into(),
            line: Some(2),
            title: "y".into(),
        };
        assert!(same_cwe_family_overlap(&a, &b));
    }

    #[test]
    fn test_cwe_family_overlap_different_families() {
        let a = DetectedFinding {
            id: "a".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "f".into(),
            line: Some(1),
            title: "x".into(),
        };
        let b = DetectedFinding {
            id: "b".into(),
            category: "crypto".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "t.c".into(),
            function: "g".into(),
            line: Some(2),
            title: "y".into(),
        };
        assert!(!same_cwe_family_overlap(&a, &b));
    }

    #[test]
    fn test_semantic_confidence_partial_coverage_rejects() {
        // Pattern has 2 findings, LLM only covers 1 family → not all covered.
        let pattern = vec![
            DetectedFinding {
                id: "p1".into(),
                category: "memory".into(),
                severity: "critical".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "strcpy".into(),
                line: Some(10),
                title: "Dangerous pattern: strcpy".into(),
            },
            DetectedFinding {
                id: "p2".into(),
                category: "crypto".into(),
                severity: "high".into(),
                cwes: vec![],
                file: "test.c".into(),
                function: "md5_init".into(),
                line: Some(20),
                title: "Dangerous pattern: md5_init".into(),
            },
        ];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "copy".into(),
            line: Some(11),
            title: "LLM: buffer overflow".into(),
        }];

        // p2 (crypto) has no LLM match → not fully covered
        assert!(!findings_have_semantic_confidence(&pattern, &llm));
    }

    #[test]
    fn test_synthesis_stats_fallback_counter() {
        let stats = SynthesisStats::new();
        assert_eq!(stats.fallback_count.load(Ordering::Relaxed), 0);
        stats.record_fallback();
        stats.record_fallback();
        assert_eq!(stats.fallback_count.load(Ordering::Relaxed), 2);
        stats.report();
    }

    #[test]
    fn test_expert_domain_from_cluster() {
        // Coarse cluster names (legacy)
        assert_eq!(
            ExpertDomain::from_cluster("memory_safety"),
            Some(ExpertDomain::MemorySafety)
        );
        assert_eq!(
            ExpertDomain::from_cluster("code_execution"),
            Some(ExpertDomain::CodeExecution)
        );
        assert_eq!(
            ExpertDomain::from_cluster("crypto"),
            Some(ExpertDomain::Crypto)
        );
        assert_eq!(ExpertDomain::from_cluster("unknown_cluster"), None);

        // Fine-grained memory sub-clusters all route to MemorySafety
        assert_eq!(
            ExpertDomain::from_cluster("memory_bounds"),
            Some(ExpertDomain::MemorySafety)
        );
        assert_eq!(
            ExpertDomain::from_cluster("memory_lifecycle"),
            Some(ExpertDomain::MemorySafety)
        );
        assert_eq!(
            ExpertDomain::from_cluster("memory_allocation"),
            Some(ExpertDomain::MemorySafety)
        );

        // Memory-adjacent clusters route to MemorySafety
        assert_eq!(
            ExpertDomain::from_cluster("initialization_safety"),
            Some(ExpertDomain::MemorySafety)
        );
        assert_eq!(
            ExpertDomain::from_cluster("unsafe_api"),
            Some(ExpertDomain::MemorySafety)
        );

        // Format string exploits route to CodeExecution
        assert_eq!(
            ExpertDomain::from_cluster("format_string"),
            Some(ExpertDomain::CodeExecution)
        );

        // Resource management has its own domain
        assert_eq!(
            ExpertDomain::from_cluster("resource_management"),
            Some(ExpertDomain::ResourceManagement)
        );
    }

    #[test]
    fn test_dominant_expert_domain_single_cluster() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "integer_overflow".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "scale".into(),
            line: Some(10),
            title: "Dangerous pattern: integer overflow in scale".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "divide_by_zero".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "normalize".into(),
            line: Some(20),
            title: "LLM: division by zero in normalize".into(),
        }];

        assert_eq!(
            dominant_expert_domain(&pattern, &llm),
            Some(ExpertDomain::ArithmeticSafety)
        );
    }

    #[test]
    fn test_memory_findings_route_to_expert_domain() {
        // Previously, memory findings used sub-clusters (memory_bounds,
        // memory_lifecycle) that did not match ExpertDomain::from_cluster,
        // making expert routing dead for all memory classes.
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy buffer overflow".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "memcpy".into(),
            line: Some(20),
            title: "LLM: heap buffer overflow in memcpy".into(),
        }];

        assert_eq!(
            dominant_expert_domain(&pattern, &llm),
            Some(ExpertDomain::MemorySafety)
        );
    }

    #[test]
    fn test_resource_leak_routes_to_expert_domain() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "resource_leak".into(),
            severity: "medium".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "open_file".into(),
            line: Some(10),
            title: "Dangerous pattern: file handle leak".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "resource_leak".into(),
            severity: "medium".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "connect".into(),
            line: Some(20),
            title: "LLM: socket handle not closed on error".into(),
        }];

        assert_eq!(
            dominant_expert_domain(&pattern, &llm),
            Some(ExpertDomain::ResourceManagement)
        );
    }

    #[test]
    fn test_format_string_routes_to_code_execution() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "format_string".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "printf".into(),
            line: Some(10),
            title: "Dangerous pattern: format string in printf".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "format_string".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "sprintf".into(),
            line: Some(20),
            title: "LLM: user-controlled format string".into(),
        }];

        assert_eq!(
            dominant_expert_domain(&pattern, &llm),
            Some(ExpertDomain::CodeExecution)
        );
    }

    #[test]
    fn test_dominant_expert_domain_mixed_clusters_returns_none() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "crypto".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "md5".into(),
            line: Some(20),
            title: "LLM: weak hash algorithm".into(),
        }];

        assert_eq!(dominant_expert_domain(&pattern, &llm), None);
    }

    #[test]
    fn test_dominant_expert_domain_unclassifiable_returns_none() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "totally_unknown".into(),
            severity: "low".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "foo".into(),
            line: Some(1),
            title: "Dangerous pattern: foo".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "totally_unknown".into(),
            severity: "low".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "bar".into(),
            line: Some(2),
            title: "LLM: something".into(),
        }];

        assert_eq!(dominant_expert_domain(&pattern, &llm), None);
    }

    #[test]
    fn test_expert_routing_wins_over_semantic_confidence_for_single_domain() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "injection".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.py".into(),
            function: "system".into(),
            line: Some(10),
            title: "Dangerous pattern: system".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "injection".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.py".into(),
            function: "run_command".into(),
            line: Some(30),
            title: "LLM: command injection in run_command".into(),
        }];

        assert!(!findings_have_consensus(&pattern, &llm));
        assert!(findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::ExpertRouted(ExpertDomain::CodeExecution)
        );
    }

    #[test]
    fn test_expert_domain_prompt_preamble_not_empty() {
        let domains = [
            ExpertDomain::MemorySafety,
            ExpertDomain::CodeExecution,
            ExpertDomain::WebDataFlow,
            ExpertDomain::FilesystemSafety,
            ExpertDomain::ArithmeticSafety,
            ExpertDomain::Crypto,
            ExpertDomain::ResourceManagement,
        ];
        for domain in &domains {
            assert!(
                !domain.system_prompt().is_empty(),
                "{:?} has empty system prompt",
                domain
            );
            assert!(
                !domain.prompt_preamble().is_empty(),
                "{:?} has empty preamble",
                domain
            );
        }
    }

    #[test]
    fn test_consensus_beats_expert_routing() {
        // Consensus (exact fingerprint match) is the highest-priority route
        // and beats expert routing even when a single domain exists.
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "memory".into(),
            severity: "critical".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "memory".into(),
            severity: "high".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "strcpy".into(),
            line: Some(10),
            title: "Dangerous pattern: strcpy".into(),
        }];

        assert!(findings_have_consensus(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::ConsensusEarlyExit
        );
    }

    #[test]
    fn test_unknown_findings_fall_through_to_full_synthesis() {
        let pattern = vec![DetectedFinding {
            id: "p1".into(),
            category: "totally_unknown".into(),
            severity: "medium".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "open_file".into(),
            line: Some(10),
            title: "Dangerous pattern: open_file".into(),
        }];
        let llm = vec![DetectedFinding {
            id: "l1".into(),
            category: "different_unknown".into(),
            severity: "medium".into(),
            cwes: vec![],
            file: "test.c".into(),
            function: "create_socket".into(),
            line: Some(20),
            title: "LLM: suspicious create_socket behavior".into(),
        }];

        assert!(!findings_have_consensus(&pattern, &llm));
        assert!(!findings_have_semantic_confidence(&pattern, &llm));
        assert_eq!(
            select_synthesis_route(&pattern, &llm),
            SynthesisRoute::FullSynthesis
        );
    }

    #[test]
    fn test_multi_file_pattern_analysis_empty() {
        let result = run_multi_file_pattern_analysis(&[]);
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_multi_file_pattern_analysis_with_fixtures() {
        let fixtures = fixtures_dir();
        let vuln_c = fixtures.join("tests/fixtures/vulnerable.c");
        if !vuln_c.exists() {
            return; // Skip if fixtures not available
        }
        let files = vec![vuln_c];
        let findings = run_multi_file_pattern_analysis(&files).unwrap();
        assert!(
            !findings.is_empty(),
            "Multi-file analysis should find patterns in vulnerable.c"
        );
    }

    #[test]
    fn test_should_use_debate_for_source_files() {
        assert!(should_use_debate("test.c"), ".c files should use debate");
        assert!(should_use_debate("app.py"), ".py files should use debate");
        assert!(
            should_use_debate("Main.java"),
            ".java files should use debate"
        );
        assert!(should_use_debate("index.js"), ".js files should use debate");
    }

    #[test]
    fn test_should_not_use_debate_for_binaries() {
        assert!(
            !should_use_debate("firmware.bin"),
            ".bin files should not use debate"
        );
        assert!(
            !should_use_debate("program.elf"),
            ".elf files should not use debate"
        );
    }

    #[test]
    fn test_pipeline_for_target_source_uses_deep() {
        let pipeline = pipeline_for_target("test.c");
        // Deep source pipeline has 5 stages (attack-surface, taint-tracer,
        // vuln-hunter, verdict-synthesizer, cwe-classifier)
        assert_eq!(
            pipeline.stages.len(),
            5,
            "Source files should use 5-stage deep pipeline"
        );
        assert_eq!(pipeline.stages[4].agent_name, "cwe-classifier");
    }

    #[test]
    fn test_pipeline_for_target_binary_uses_deep() {
        let pipeline = pipeline_for_target("firmware.bin");
        // Binary deep pipeline has different stage count (decompile-renamer, etc.)
        assert!(
            pipeline.stages.len() >= 4,
            "Binary files should use deep pipeline with at least 4 stages"
        );
    }
}
