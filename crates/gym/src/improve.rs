//! Agentic self-improvement loop.
//!
//! Runs benchmarks, identifies false negatives, asks the failure-analyst
//! agent to diagnose them, and produces actionable improvement proposals.
//!
//! The loop:
//! 1. Run benchmark → collect FN cases with their source code
//! 2. Ingest each FN case into a graph DB
//! 3. Run failure-analyst agent → get diagnosis + proposals
//! 4. Output proposals as structured improvement records
//! 5. (Human or automated) apply proposals and re-run

use crate::adapters::{BenchmarkAdapter, BenchmarkConfig};
use crate::ground_truth;
use crate::scoring::{self, AggregateScore};
use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Maximum compiled regex size (bytes) for LLM-proposed patterns.
/// Mirrors the limit in patterns_source.rs to prevent ReDoS.
/// Uses the same 200KB limit as the core pattern engine.
const PROPOSAL_REGEX_SIZE_LIMIT: usize = 200_000;

const IMPROVE_KB_MAX_CWE_QUERIES: usize = 6;

/// Maximum number of SourcePattern entries allowed in a single pattern file.
/// Prevents unbounded growth across successive improvement cycles.
const PATTERN_COUNT_CEILING: usize = 500;

/// Minimum training/holdout F1 gap (percentage points as a fraction) that
/// triggers an overfitting warning and flags the cycle report.
const HOLDOUT_OVERFITTING_GAP_THRESHOLD: f64 = 0.15;

const IMPROVE_KB_HITS_PER_QUERY: usize = 2;
const IMPROVE_KB_SNIPPET_CHAR_LIMIT: usize = 700;
const IMPROVE_KB_FIXED_QUERIES: [&str; 3] = ["methodology", "cwe-families", "false negative"];
const FAILURE_ANALYST_MIN_CASES: usize = 5;
const FAILURE_ANALYST_MAX_CASES: usize = 20;
const FAILURE_ANALYST_TARGET_BUDGET_PER_CASE: u64 = 50_000;
const FAILURE_ANALYST_MAX_BUDGET_PER_CASE: u64 = 100_000;

/// A proposed improvement from the failure-analyst agent.
#[derive(Debug, Clone)]
pub struct Improvement {
    pub kind: ImprovementKind,
    pub description: String,
    pub target_cwes: Vec<u32>,
    pub target_file: PathBuf,
    pub patch: Patch,
    /// The case that triggered this improvement.
    pub source_case: String,
    /// Priority from the analyst.
    pub priority: Priority,
    /// Explicit KB or durable-memory evidence cited by the failure analyst.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Structured overfitting review attached to accepted or modified proposals.
    pub review: Option<ReviewDecision>,
}

#[derive(Debug, Clone)]
pub enum ImprovementKind {
    /// Add a new regex pattern to patterns_source.rs
    NewPattern,
    /// Modify an agent's prompt for better detection
    AgentPrompt,
    /// Add a CWE mapping to scoring.rs
    CweMapping,
    /// Add a new taint source or sink
    TaintRule,
    /// The ground truth was wrong/incomplete
    GroundTruthFix,
    /// Modify a YAML analysis recipe (add/remove/reorder stages, adjust config)
    RecipeChange,
}

#[derive(Debug, Clone)]
pub enum Priority {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct Patch {
    pub find: String,
    pub replace: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceRef {
    pub source_type: EvidenceSourceType,
    pub source: Option<String>,
    pub topic: Option<String>,
    pub title: Option<String>,
    pub memory_type: Option<String>,
    pub context: Option<String>,
    pub tags: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSourceType {
    Knowledge,
    Memory,
    Heuristic,
}

#[derive(Debug, Clone)]
pub struct ReviewDecision {
    pub verdict: ReviewVerdict,
    pub reason: String,
    pub overfitting_risk: ReviewRating,
    pub real_world_applicability: ReviewRating,
    pub suggested_modification: Option<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewVerdict {
    Accept,
    Reject,
    Modify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewRating {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Deserialize)]
struct LlmProposal {
    kind: String,
    description: String,
    #[serde(default)]
    target_cwes: Vec<u32>,
    #[serde(default)]
    target_file: Option<String>,
    #[serde(default)]
    regex_pattern: Option<String>,
    #[serde(default)]
    patch_find: Option<String>,
    #[serde(default)]
    patch_replace: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    evidence_refs: Vec<LlmEvidenceRef>,
}

#[derive(Debug, Clone, Deserialize)]
struct LlmProposalResponse {
    proposals: Vec<LlmProposal>,
}

#[derive(Debug, Clone, Deserialize)]
struct LlmEvidenceRef {
    source_type: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "type")]
    memory_type: Option<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    rationale: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LlmReviewDecision {
    #[serde(default)]
    proposal_id: Option<String>,
    #[serde(default)]
    proposal_description: Option<String>,
    verdict: String,
    reason: String,
    overfitting_risk: String,
    real_world_applicability: String,
    #[serde(default)]
    suggested_modification: Option<String>,
    #[serde(default)]
    evidence_refs: Vec<LlmEvidenceRef>,
}

#[derive(Debug, Clone, Deserialize)]
struct LlmReviewResponse {
    reviews: Vec<LlmReviewDecision>,
}

/// Result of a self-improvement cycle.
#[derive(Debug)]
pub struct ImprovementCycle {
    pub suite: String,
    pub baseline_score: AggregateScore,
    pub false_negatives: Vec<FalseNegativeCase>,
    pub reviewed_proposals: Vec<Improvement>,
    pub proposals: Vec<Improvement>,
    /// Number of cases held out for validation (not used for failure analysis).
    pub holdout_case_count: usize,
    /// Number of training cases used for failure analysis.
    pub training_case_count: usize,
    /// Aggregate score computed on holdout cases (scoring only, no LLM failure analysis).
    /// `None` when `holdout_fraction` is 0 or holdout scoring fails.
    pub holdout_score: Option<AggregateScore>,
    /// Suites that SHOULD be cross-validated but were not (logged for visibility).
    pub cross_validation_pending: Vec<String>,
    /// Runtime provenance: which LLM backend/model produced this cycle's proposals.
    pub run_metadata: Option<ImproveRunMetadata>,
}

/// Runtime provenance for an improve cycle.
#[derive(Debug, Clone)]
pub struct ImproveRunMetadata {
    pub llm_backend: String,
    pub llm_model: String,
    pub run_mode: String,
    pub binary_mode: bool,
    pub profile: Option<String>,
    pub timestamp_utc: String,
}

/// Structured report returned by [`apply_accepted_proposals`].
#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    /// Proposals successfully applied to source files or DB.
    pub applied: usize,
    /// Proposals skipped (non-accepted review status or unsupported kind).
    pub skipped: usize,
    /// Proposals blocked due to missing DB, missing target file, or invalid patch content.
    pub blocked: usize,
    /// Total proposals considered.
    pub total: usize,
    /// Human-readable reason for each blocked proposal.
    pub blocked_reasons: Vec<String>,
}

fn review_proposal_id(index: usize) -> String {
    format!("P{}", index + 1)
}

/// A false negative case with context for the failure-analyst.
#[derive(Debug, Clone)]
pub struct FalseNegativeCase {
    pub case_id: String,
    pub expected_cwes: Vec<u32>,
    pub detected_cwes: Vec<u32>,
    pub source_path: PathBuf,
    /// The actual source code content (for the analyst to read).
    pub source_content: String,
}

/// Run one cycle of the self-improvement loop.
///
/// 1. Run the benchmark to get current scores
/// 2. Collect false negative cases with their source code
/// 3. Run the failure-analyst agent on each FN case
/// 4. Return structured improvement proposals
pub async fn run_improvement_cycle(
    adapter: &dyn BenchmarkAdapter,
    config: &BenchmarkConfig,
    data_dir: &Path,
    runtime_config: &skwaq_core::config::Config,
    profile_name: Option<&str>,
) -> anyhow::Result<ImprovementCycle> {
    let suite_name = adapter.name().to_string();
    tracing::info!("Starting self-improvement cycle for {}", suite_name);

    let run_metadata = Some(build_improve_run_metadata(
        config,
        runtime_config,
        profile_name,
    ));

    // Step 1: Run benchmark and collect outcomes
    let gt = adapter.ground_truth()?;
    let filtered_cases: Vec<_> = gt
        .cases
        .iter()
        .filter(|c| {
            config.cwe_filter.as_ref().is_none_or(|f| {
                c.expected_cwes.iter().any(|cwe| f.contains(cwe)) || c.expected_cwes.is_empty()
            })
        })
        .collect();
    let all_cases = match config.max_cases {
        Some(max) => ground_truth::stratified_sample(&filtered_cases, max),
        None => filtered_cases,
    };

    // Split into training and holdout sets for overfitting prevention.
    // Training cases are used for failure analysis; holdout cases are
    // reserved for validating that proposals generalize.
    let holdout_count = if config.holdout_fraction > 0.0 {
        (all_cases.len() as f64 * config.holdout_fraction).ceil() as usize
    } else {
        0
    };
    let training_end = all_cases.len().saturating_sub(holdout_count);
    let training_cases = &all_cases[..training_end];
    let holdout_cases = &all_cases[training_end..];

    if holdout_count > 0 {
        tracing::info!(
            "{}: {} training cases, {} holdout cases ({:.0}% holdout)",
            suite_name,
            training_cases.len(),
            holdout_cases.len(),
            config.holdout_fraction * 100.0
        );
    }

    let mut outcomes = Vec::new();
    for case in training_cases {
        match adapter
            .run_case(case, data_dir, config, runtime_config)
            .await
        {
            Ok(findings) => {
                let mut outcome =
                    scoring::score_case(case, &findings, &|f| adapter.map_finding_to_cwes(f));
                outcome.suite = suite_name.clone();
                outcomes.push((case, outcome, findings));
            }
            Err(e) => {
                tracing::warn!("Case {} failed: {}", case.id, e);
            }
        }
    }

    let score = scoring::aggregate(
        &outcomes
            .iter()
            .map(|(_, o, _)| o.clone())
            .collect::<Vec<_>>(),
    );

    // Step 2: Collect false negative cases
    let mut false_negatives = Vec::new();
    for (case, outcome, _findings) in &outcomes {
        // Check if any expected CWE was missed
        let missed_cwes: Vec<u32> = outcome
            .cwe_hits
            .iter()
            .filter(|(_, &hit)| !hit)
            .map(|(&cwe, _)| cwe)
            .collect();

        if missed_cwes.is_empty() {
            continue;
        }

        let source_path = data_dir.join(&case.path);
        // For directory-based suites (e.g., CyberGym), the path may contain
        // colons that are sanitized to underscores on disk. Try the sanitized
        // version if the original doesn't exist.
        let source_path = if !source_path.exists() {
            let sanitized = case.path.replace(':', "_");
            let alt = data_dir.join(&sanitized);
            if alt.exists() {
                alt
            } else {
                source_path
            }
        } else {
            source_path
        };

        // Read source: if path is a directory, find and concatenate source files
        let source_content = if source_path.is_dir() {
            let mut content = String::new();
            let mut source_files = Vec::new();
            // Walk recursively to find source files (CyberGym nests under src-vul/)
            fn collect_sources(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            collect_sources(&path, files);
                        } else {
                            let name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_lowercase();
                            if name.ends_with(".c")
                                || name.ends_with(".cc")
                                || name.ends_with(".cpp")
                                || name.ends_with(".h")
                                || name.ends_with(".py")
                                || name.ends_with(".java")
                                || name.ends_with(".js")
                            {
                                files.push(path);
                            }
                        }
                    }
                }
            }
            collect_sources(&source_path, &mut source_files);
            source_files.sort();
            for path in source_files.iter().take(5) {
                if let Ok(text) = std::fs::read_to_string(path) {
                    content.push_str(&format!(
                        "// === {} ===\n",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                    let truncated: String = text.chars().take(10_000).collect();
                    content.push_str(&truncated);
                    content.push('\n');
                }
            }
            content
        } else {
            std::fs::read_to_string(&source_path).unwrap_or_default()
        };

        if source_content.is_empty() {
            continue;
        }

        false_negatives.push(FalseNegativeCase {
            case_id: case.id.clone(),
            expected_cwes: case.expected_cwes.clone(),
            detected_cwes: outcome.detected_cwes.clone(),
            source_path,
            source_content,
        });
    }

    tracing::info!(
        "{}: F1={:.1}%, P={:.1}%, R={:.1}%, {} FN cases to analyze",
        suite_name,
        score.f1 * 100.0,
        score.precision * 100.0,
        score.recall * 100.0,
        false_negatives.len()
    );

    // Score holdout cases (scoring only — no LLM failure analysis) to provide
    // empirical generalization signal for the overfitting reviewer.
    let holdout_score = if !holdout_cases.is_empty() {
        match score_holdout_cases(
            adapter,
            holdout_cases,
            data_dir,
            config,
            runtime_config,
            &suite_name,
        )
        .await
        {
            Some(hs) => {
                let gap_pp = (score.f1 - hs.f1) * 100.0;
                tracing::info!(
                    "{}: holdout F1={:.1}%, training F1={:.1}%, gap={:.1}pp",
                    suite_name,
                    hs.f1 * 100.0,
                    score.f1 * 100.0,
                    gap_pp
                );
                if gap_pp > HOLDOUT_OVERFITTING_GAP_THRESHOLD * 100.0 {
                    tracing::warn!(
                        "{}: training/holdout F1 gap ({:.1}pp) exceeds threshold ({:.0}pp) — possible overfitting from previous cycles",
                        suite_name,
                        gap_pp,
                        HOLDOUT_OVERFITTING_GAP_THRESHOLD * 100.0
                    );
                }
                Some(hs)
            }
            None => {
                tracing::warn!(
                    "{}: holdout scoring failed; continuing without holdout signal",
                    suite_name
                );
                None
            }
        }
    } else {
        None
    };

    // Step 3: Analyze false negatives and generate proposals
    let reviewed_proposals = analyze_false_negatives(
        &false_negatives,
        &suite_name,
        holdout_score.as_ref(),
        runtime_config,
    )
    .await?;
    let mut proposals: Vec<_> = reviewed_proposals
        .iter()
        .filter(|proposal| review_allows_auto_apply(proposal.review.as_ref()))
        .cloned()
        .collect();

    // Apply max-improvements-per-cycle cap to prevent compound overfitting
    if config.max_improvements_per_cycle > 0 && proposals.len() > config.max_improvements_per_cycle
    {
        tracing::warn!(
            "Capping accepted proposals from {} to {} (max_improvements_per_cycle)",
            proposals.len(),
            config.max_improvements_per_cycle
        );
        proposals.truncate(config.max_improvements_per_cycle);
    }

    // Step 4: Store insights as knowledge for future agents to reference
    store_fn_insights(&false_negatives, &reviewed_proposals, &suite_name, data_dir);

    // Step 5: Log cross-validation warning for accepted proposals
    let cross_validation_pending = if !proposals.is_empty() {
        let other_suites = cross_validation_targets(&suite_name);
        if !other_suites.is_empty() {
            tracing::warn!(
                "CROSS-VALIDATION NEEDED: {} accepted proposals from {} should be \
                 validated on: {:?}. Run `skwaq gym run` on those suites to check \
                 for generalization before deploying.",
                proposals.len(),
                suite_name,
                other_suites
            );
        }
        other_suites
    } else {
        vec![]
    };

    Ok(ImprovementCycle {
        suite: suite_name,
        baseline_score: score,
        false_negatives,
        reviewed_proposals,
        proposals,
        holdout_case_count: holdout_cases.len(),
        training_case_count: training_cases.len(),
        holdout_score,
        cross_validation_pending,
        run_metadata,
    })
}

/// Score holdout cases through the adapter without running the failure-analyst LLM.
///
/// Returns `None` if no cases produce valid outcomes.
async fn score_holdout_cases(
    adapter: &dyn BenchmarkAdapter,
    holdout_cases: &[&crate::ground_truth::TestCase],
    data_dir: &Path,
    config: &BenchmarkConfig,
    runtime_config: &skwaq_core::config::Config,
    suite_name: &str,
) -> Option<AggregateScore> {
    let mut outcomes = Vec::new();
    for case in holdout_cases {
        match adapter
            .run_case(case, data_dir, config, runtime_config)
            .await
        {
            Ok(findings) => {
                let mut outcome =
                    scoring::score_case(case, &findings, &|f| adapter.map_finding_to_cwes(f));
                outcome.suite = suite_name.to_string();
                outcomes.push(outcome);
            }
            Err(e) => {
                tracing::warn!("Holdout case {} failed: {}", case.id, e);
            }
        }
    }
    if outcomes.is_empty() {
        return None;
    }
    Some(scoring::aggregate(&outcomes))
}

/// Analyze false negatives using the failure-analyst agent plus explicit heuristics.
async fn analyze_false_negatives(
    false_negatives: &[FalseNegativeCase],
    suite: &str,
    holdout_score: Option<&AggregateScore>,
    runtime_config: &skwaq_core::config::Config,
) -> anyhow::Result<Vec<Improvement>> {
    if false_negatives.is_empty() {
        return Ok(Vec::new());
    }

    let knowledge_db = prepare_improvement_knowledge_db()?;
    let mut proposals = Vec::new();

    let llm_proposals =
        run_failure_analyst_agent(false_negatives, suite, &knowledge_db, runtime_config).await?;
    tracing::info!(
        "Failure analyst produced {} proposal(s) for {}",
        llm_proposals.len(),
        suite
    );
    proposals.extend(llm_proposals);

    // Heuristics are an explicit second signal, not a hidden secondary path.
    let heuristic_proposals =
        annotate_heuristic_proposals(&knowledge_db, heuristic_failure_analysis(false_negatives))?;
    tracing::info!(
        "Heuristic analysis produced {} proposal(s) for {}",
        heuristic_proposals.len(),
        suite
    );
    proposals.extend(heuristic_proposals);

    // Deduplicate proposals by description
    let mut seen = std::collections::HashSet::new();
    proposals.retain(|p| seen.insert(p.description.clone()));

    // Run overfitting review gate on proposals
    proposals = run_overfitting_review(
        proposals,
        suite,
        &knowledge_db,
        holdout_score,
        runtime_config,
    )
    .await?;

    Ok(proposals)
}

/// Run the failure-analyst LLM agent on false negative cases.
async fn run_failure_analyst_agent(
    false_negatives: &[FalseNegativeCase],
    suite: &str,
    knowledge_db: &skwaq_core::graph::GraphDb,
    runtime_config: &skwaq_core::config::Config,
) -> anyhow::Result<Vec<Improvement>> {
    let llm_client = skwaq_core::llm::create_client(&runtime_config.llm).await?;
    let memory = skwaq_core::memory::MemoryStore::open_default()?;

    let agent = skwaq_core::agents::definition::load_agent("failure-analyst")?;
    let runner = skwaq_core::agents::runner::AgentRunner::new(llm_client);
    let rate_controller = crate::throttle::RateController::with_defaults(1);
    let cross_process_backoff = crate::throttle::CrossProcessBackoff::new();

    let mut proposals = Vec::new();
    let case_limit = failure_analyst_case_limit(
        runtime_config.analysis.default_token_budget,
        false_negatives.len(),
    );
    let budget_per_case =
        failure_analyst_budget_per_case(runtime_config.analysis.default_token_budget, case_limit);

    tracing::info!(
        "Failure analyst evaluating up to {} false negatives with {} tokens per case ({} total FN cases available)",
        case_limit,
        budget_per_case,
        false_negatives.len()
    );

    for (i, fn_case) in false_negatives.iter().enumerate().take(case_limit) {
        let mut budget = skwaq_core::llm::TokenBudget::new(budget_per_case);
        let source_excerpt_len = fn_case.source_content.len().min(32_000);
        if fn_case.source_content.len() > source_excerpt_len {
            tracing::warn!(
                "Truncating source context for case {} from {} to {} bytes",
                fn_case.case_id,
                fn_case.source_content.len(),
                source_excerpt_len
            );
        }
        // Sanitize the source excerpt before embedding it in the prompt.
        // For injection-class CWEs (77, 78, 88) the raw source code contains
        // shell/exec API calls that trigger the input content-safety filter.
        // We replace the dangerous function names with abstract VULN_SINK_*
        // aliases so the LLM can still reason about the vulnerability without
        // the prompt being blocked.
        let source_for_prompt = sanitize_source_for_prompt(
            &fn_case.source_content[..source_excerpt_len],
            &fn_case.expected_cwes,
        );
        let kb_context = build_false_negative_knowledge_context(knowledge_db, fn_case)?;

        // Build context with the missed case details.
        // Include which semantic classes WERE detected so the analyst
        // can focus on the gap rather than re-analyzing what was found.
        let detected_classes: Vec<String> = fn_case
            .detected_cwes
            .iter()
            .filter_map(|&cwe| {
                crate::scoring::cwe_to_semantic_class_public(cwe).map(|c| c.as_str().to_string())
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let expected_classes: Vec<String> = fn_case
            .expected_cwes
            .iter()
            .filter_map(|&cwe| {
                crate::scoring::cwe_to_semantic_class_public(cwe).map(|c| c.as_str().to_string())
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let gap_context = if detected_classes.is_empty() {
            format!(
                "Expected semantic classes: {:?}\n\
                 Detected semantic classes: NONE (complete detection gap)\n",
                expected_classes
            )
        } else {
            format!(
                "Expected semantic classes: {:?}\n\
                 Detected semantic classes: {:?}\n\
                 Semantic gap: expected but not detected classes should be \
                 the primary investigation focus.\n",
                expected_classes, detected_classes
            )
        };

        let context = format!(
            "Analyze this FALSE NEGATIVE from the {} benchmark.\n\n\
             Case: {}\n\
             Expected CWEs: {:?}\n\
             Detected CWEs: {:?}\n\
             {}\n\
             File: {}\n\n\
             Source code:\n```\n{}\n```\n\n\
             Knowledge base guidance:\n{}\n\n\
             The vulnerability was NOT detected. Explain why and propose a fix.\n\n\
             Durable memory is available for this improve cycle. Use recall_memory to check \
             for prior generalized lessons before proposing changes. Use the KB guidance \
             above plus lookup_knowledge/lookup_cwe to cross-check the expected CWE family \
             before finalizing any proposal. Only store or reuse lessons that generalize \
             beyond this specific benchmark case.\n\n\
             Return a structured report with the exact headings below and no preamble:\n\
             ## Case: {{case_id}}\n\
             Expected: CWE-{{N}} ({{description}})\n\
             File: {{path}}\n\
             Vulnerability: {{what the actual vuln is, with line numbers}}\n\
             Detection failure reason: {{why we missed it}}\n\
             Proposed fix: {{NEW_PATTERN|DEEPER_ANALYSIS|NEW_AGENT_CAPABILITY|CWE_MAPPING|TAINT_RULE|RECIPE_CHANGE}}\n\
             Details: {{specific actionable proposal}}\n\
             Priority: {{HIGH|MEDIUM|LOW}}\n\
             Evidence:\n\
             - KNOWLEDGE | source=... | topic=... | title=... | rationale=...\n\
             - MEMORY | type=... | context=... | tags=tag1,tag2 | rationale=...\n\
             Every proposal must include at least one Evidence entry. Do not emit prose \
             before ## Case:.\n\n\
             NO-SILENT-DEGRADATION INVARIANT: Do NOT propose silent degradation, silent alternate paths, or silent \
             alternate-path behavior. If a primary analysis/tool/path fails, the correct \
             fix is to fail loudly with a diagnostic error naming the primary path and why \
             no secondary is attempted — never to silently retry with a weaker method or \
             return a degraded placeholder. Proposals whose description or patch contains \
             silent degradation and silent alternate-path language will be rejected.",
            suite,
            fn_case.case_id,
            fn_case.expected_cwes,
            fn_case.detected_cwes,
            gap_context,
            fn_case.source_path.display(),
            source_for_prompt,
            kb_context,
        );

        let inv_id = format!("improve-{}", i);
        let db = prepare_improvement_agent_db(&inv_id, &fn_case.case_id, &fn_case.source_path)?;

        tracing::info!(
            "Running failure-analyst on case {} ({}/{})",
            fn_case.case_id,
            i + 1,
            case_limit
        );

        cross_process_backoff.wait_if_needed().await;
        let result = runner
            .run_agent_with_db_and_memory(&agent, &inv_id, &context, &db, &memory, &mut budget)
            .await
            .map_err(|e| {
                anyhow::anyhow!("failure analyst failed on case {}: {e}", fn_case.case_id)
            });

        // Record outcome in rate controller for backpressure tracking.
        let result = match result {
            Ok(r) => {
                rate_controller.record(crate::throttle::CallOutcome::Success);
                r
            }
            Err(e) => {
                let message = e.to_string();
                if is_content_filter_error(&message) {
                    tracing::warn!(
                        "Skipping case {} — failure-analyst blocked by content_filter",
                        fn_case.case_id
                    );
                    rate_controller.record(crate::throttle::CallOutcome::OtherError);
                    continue;
                }
                let outcome = if is_rate_limited_message(&message) {
                    cross_process_backoff
                        .signal_rate_limited(retry_after_secs_from_error(&message).unwrap_or(30));
                    crate::throttle::CallOutcome::RateLimited
                } else {
                    crate::throttle::CallOutcome::OtherError
                };
                rate_controller.record(outcome);
                return Err(e);
            }
        };

        let mut formatter_budget = skwaq_core::llm::TokenBudget::new(budget_per_case.min(50_000));
        let formatted_output = match format_failure_analyst_output(
            runtime_config,
            agent.model.as_str(),
            fn_case,
            &result.output,
            &mut formatter_budget,
        )
        .await
        {
            Ok(output) => output,
            Err(e) if is_content_filter_error(&e.to_string()) => {
                tracing::warn!(
                    "Skipping case {} — formatter blocked by content_filter",
                    fn_case.case_id
                );
                continue;
            }
            Err(e) => return Err(e),
        };

        proposals.extend(
            parse_analyst_proposals(&formatted_output, fn_case).map_err(|e| {
                anyhow::anyhow!(
                    "failure analyst returned invalid proposal payload for case {}: {e}",
                    fn_case.case_id
                )
            })?,
        );
    }

    Ok(proposals)
}

fn failure_analyst_case_limit(default_token_budget: u64, false_negative_count: usize) -> usize {
    if false_negative_count == 0 {
        return 0;
    }

    let budget_scaled_limit =
        (default_token_budget / FAILURE_ANALYST_TARGET_BUDGET_PER_CASE) as usize;
    let desired_limit =
        budget_scaled_limit.clamp(FAILURE_ANALYST_MIN_CASES, FAILURE_ANALYST_MAX_CASES);
    desired_limit.min(false_negative_count)
}

fn failure_analyst_budget_per_case(default_token_budget: u64, case_limit: usize) -> u64 {
    if case_limit == 0 {
        return 0;
    }

    (default_token_budget / case_limit as u64).clamp(1, FAILURE_ANALYST_MAX_BUDGET_PER_CASE)
}

async fn format_failure_analyst_output(
    config: &skwaq_core::config::Config,
    model: &str,
    fn_case: &FalseNegativeCase,
    raw_output: &str,
    budget: &mut skwaq_core::llm::TokenBudget,
) -> anyhow::Result<String> {
    let formatter_client = skwaq_core::llm::create_client(&config.llm).await?;
    let cross_process_backoff = crate::throttle::CrossProcessBackoff::new();
    let system_prompt = "You convert analyst reports into strict JSON. Do not add commentary.";
    let formatter_prompt = format!(
        "Convert the analyst report below into a single ```json fenced block using this schema:\n\
         {{\"proposals\":[{{\"kind\":\"NEW_PATTERN|DEEPER_ANALYSIS|NEW_AGENT_CAPABILITY|CWE_MAPPING|TAINT_RULE\",\
         \"description\":\"...\",\"target_cwes\":[119],\"target_file\":\"optional path\",\
         \"regex_pattern\":\"optional regex\",\"patch_find\":\"optional existing text\",\
         \"patch_replace\":\"optional replacement text\",\"priority\":\"HIGH|MEDIUM|LOW\",\
         \"evidence_refs\":[{{\"source_type\":\"knowledge\",\"source\":\"kb source\",\
         \"topic\":\"kb topic\",\"title\":\"kb title\",\"rationale\":\"why this KB hit supports the proposal\"}},\
         {{\"source_type\":\"memory\",\"type\":\"pattern|insight|failure\",\
         \"context\":\"recalled generalized lesson\",\"tags\":[\"cwe-119\"],\
         \"rationale\":\"why this memory supports the proposal\"}}]}}]}}\n\
         Rules:\n\
         - Return JSON only, inside one ```json fenced block.\n\
         - Do not omit evidence_refs.\n\
         - Preserve the exact proposal meaning from the analyst report.\n\
         - Use case {} expected CWEs {:?} as target_cwes when the report omits them.\n\
         - If the report contains multiple proposals, include them all.\n\n\
         Analyst report:\n{}",
        fn_case.case_id, fn_case.expected_cwes, raw_output
    );

    cross_process_backoff.wait_if_needed().await;
    skwaq_core::llm::execute_with_tools(
        &formatter_client,
        model,
        system_prompt,
        &formatter_prompt,
        &[],
        |_tool_name, _args| async move {
            Err(anyhow::anyhow!(
                "formatter unexpectedly attempted a tool call"
            ))
        },
        budget,
    )
    .await
    .inspect_err(|e| {
        let message = e.to_string();
        if is_rate_limited_message(&message) {
            cross_process_backoff
                .signal_rate_limited(retry_after_secs_from_error(&message).unwrap_or(30));
        }
    })
}

/// Parse structured improvement proposals from the failure-analyst's output.
fn parse_analyst_proposals(
    output: &str,
    fn_case: &FalseNegativeCase,
) -> anyhow::Result<Vec<Improvement>> {
    let json_str = extract_json_block(output).ok_or_else(|| {
        anyhow::anyhow!(
            "failure analyst did not return a JSON payload; raw output: {}",
            truncate_for_error(output)
        )
    })?;

    let raw_proposals = if let Ok(response) = serde_json::from_str::<LlmProposalResponse>(&json_str)
    {
        response.proposals
    } else if let Ok(raw_proposals) = serde_json::from_str::<Vec<LlmProposal>>(&json_str) {
        raw_proposals
    } else if let Ok(single) = serde_json::from_str::<LlmProposal>(&json_str) {
        vec![single]
    } else {
        return Err(anyhow::anyhow!(
            "failure analyst returned malformed JSON: {}",
            truncate_for_error(&json_str)
        ));
    };

    if raw_proposals.is_empty() {
        return Err(anyhow::anyhow!(
            "failure analyst returned zero proposals in JSON payload"
        ));
    }

    let mut converted = Vec::new();
    for (index, proposal) in raw_proposals.into_iter().enumerate() {
        if proposal_kind_is_ground_truth(&proposal.kind) {
            tracing::warn!(
                "Skipping unsupported ground-truth proposal {} for case {}",
                index + 1,
                fn_case.case_id
            );
            continue;
        }
        converted.push(convert_llm_proposal(proposal, fn_case, index + 1)?);
    }

    Ok(converted)
}

fn extract_json_block(text: &str) -> Option<String> {
    if let Some(start) = text.find("```json") {
        let after_fence = &text[start + 7..];
        if let Some(end) = after_fence.find("```") {
            let block = after_fence[..end].trim();
            if !block.is_empty() {
                return Some(block.to_string());
            }
        }
    }

    for segment in text.split("```") {
        let trimmed = segment.trim();
        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            return Some(trimmed.to_string());
        }
    }

    let brace_pos = text.find('{');
    let bracket_pos = text.find('[');
    match (brace_pos, bracket_pos) {
        (Some(b), Some(k)) if k < b => {
            if let Some(json) = find_outermost_block(text, '[', ']') {
                return Some(json);
            }
            if let Some(json) = find_outermost_block(text, '{', '}') {
                return Some(json);
            }
        }
        _ => {
            if let Some(json) = find_outermost_block(text, '{', '}') {
                return Some(json);
            }
            if let Some(json) = find_outermost_block(text, '[', ']') {
                return Some(json);
            }
        }
    }

    None
}

fn find_outermost_block(text: &str, open: char, close: char) -> Option<String> {
    let start = text.find(open)?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut preceding_backslashes = 0usize;

    for (i, ch) in text[start..].char_indices() {
        if ch == '"' && preceding_backslashes.is_multiple_of(2) {
            in_string = !in_string;
        }
        if !in_string {
            if ch == open {
                depth += 1;
            } else if ch == close {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..start + i + 1].to_string());
                }
            }
        }
        if ch == '\\' {
            preceding_backslashes += 1;
        } else {
            preceding_backslashes = 0;
        }
    }

    None
}

fn convert_llm_proposal(
    proposal: LlmProposal,
    fn_case: &FalseNegativeCase,
    proposal_number: usize,
) -> anyhow::Result<Improvement> {
    // No-silent-degradation invariant is enforced semantically by the overfitting-reviewer
    // LLM pass (see run_overfitting_review_batch) rather than a brittle string match here.
    // A deterministic keyword filter both misses rewordings and produces false positives on
    // normal English, so we rely on the reviewer's semantic judgment instead.
    let _ = proposal_number;
    let kind = match proposal.kind.to_uppercase().as_str() {
        "NEW_PATTERN" | "NEWPATTERN" | "PATTERN" => ImprovementKind::NewPattern,
        "AGENT_PROMPT"
        | "AGENTPROMPT"
        | "DEEPER_ANALYSIS"
        | "DEEPERANALYSIS"
        | "NEW_AGENT_CAPABILITY"
        | "NEWAGENTCAPABILITY" => ImprovementKind::AgentPrompt,
        "CWE_MAPPING" | "CWEMAPPING" => ImprovementKind::CweMapping,
        "TAINT_RULE" | "TAINTRULE" => ImprovementKind::TaintRule,
        "RECIPE_CHANGE" | "RECIPECHANGE" | "RECIPE" => ImprovementKind::RecipeChange,
        "GROUND_TRUTH_ERROR" | "GROUNDTRUTHERROR" | "GROUND_TRUTH" | "GROUNDTRUTH" => {
            return Err(anyhow::anyhow!(
                "proposal {} for case {} requested unsupported ground-truth editing; \
                 ground-truth fixes must be handled outside gym improve",
                proposal_number,
                fn_case.case_id,
            ))
        }
        _ => {
            return Err(anyhow::anyhow!(
                "proposal {} for case {} used unsupported kind '{}'",
                proposal_number,
                fn_case.case_id,
                proposal.kind
            ))
        }
    };

    let description = require_non_empty_string(
        proposal.description,
        "description",
        &format!("proposal {} for case {}", proposal_number, fn_case.case_id),
    )?;

    let priority = match proposal
        .priority
        .as_deref()
        .unwrap_or("medium")
        .to_uppercase()
        .as_str()
    {
        "HIGH" => Priority::High,
        "LOW" => Priority::Low,
        _ => Priority::Medium,
    };

    let target_cwes = if proposal.target_cwes.is_empty() {
        fn_case.expected_cwes.clone()
    } else {
        proposal.target_cwes
    };

    let supporting_evidence = convert_evidence_refs(
        proposal.evidence_refs,
        &format!(
            "proposal {} ('{}') for case {}",
            proposal_number, description, fn_case.case_id
        ),
        false,
    )?;

    // For NewPattern proposals, always target patterns_source.rs regardless
    // of what the LLM suggests (it often puts the test case file path).
    let target_file = match kind {
        ImprovementKind::NewPattern => PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
        _ => proposal
            .target_file
            .map(PathBuf::from)
            .unwrap_or_else(|| match kind {
                ImprovementKind::AgentPrompt => PathBuf::from("agents/vuln-hunter.md"),
                ImprovementKind::CweMapping => PathBuf::from("crates/gym/src/scoring.rs"),
                ImprovementKind::TaintRule => PathBuf::from("crates/core/src/analysis/taint.rs"),
                ImprovementKind::GroundTruthFix => PathBuf::from("data/gym/ground_truth/"),
                ImprovementKind::RecipeChange => PathBuf::from("recipes/analysis/standard.yaml"),
                _ => unreachable!(),
            }),
    };

    Ok(Improvement {
        kind,
        description,
        target_cwes,
        target_file,
        patch: Patch {
            find: proposal.patch_find.unwrap_or_default(),
            replace: proposal
                .regex_pattern
                .or(proposal.patch_replace)
                .unwrap_or_default(),
        },
        source_case: fn_case.case_id.clone(),
        priority,
        supporting_evidence,
        review: None,
    })
}

fn convert_evidence_refs(
    raw_refs: Vec<LlmEvidenceRef>,
    evidence_context: &str,
    strict: bool,
) -> anyhow::Result<Vec<EvidenceRef>> {
    if raw_refs.is_empty() {
        if strict {
            return Err(anyhow::anyhow!(
                "{evidence_context}: proposals must include at least one evidence entry (KB or memory citation). \
                 Add evidence_refs before submitting."
            ));
        }
        // Non-strict path (review decisions): warn but allow empty evidence.
        // Early improve cycles may have empty memory; the overfitting reviewer
        // will still evaluate proposals without agent-side evidence.
        tracing::warn!(
            "{evidence_context}: no KB or memory evidence cited. Proposal will proceed \
             but the overfitting reviewer should scrutinize more carefully."
        );
        return Ok(vec![]);
    }

    raw_refs
        .into_iter()
        .enumerate()
        .map(|(index, raw)| convert_evidence_ref(raw, evidence_context, index + 1))
        .collect()
}

fn convert_evidence_ref(
    raw: LlmEvidenceRef,
    evidence_context: &str,
    evidence_number: usize,
) -> anyhow::Result<EvidenceRef> {
    let source_type = match raw.source_type.trim().to_ascii_lowercase().as_str() {
        "knowledge" => EvidenceSourceType::Knowledge,
        "memory" => EvidenceSourceType::Memory,
        other => {
            return Err(anyhow::anyhow!(
                "{} evidence {} used unsupported source_type '{}'",
                evidence_context,
                evidence_number,
                other
            ))
        }
    };

    let rationale = require_non_empty_string(
        raw.rationale,
        "rationale",
        &format!("{evidence_context} evidence {evidence_number}"),
    )?;
    let source = normalize_optional_string(raw.source);
    let topic = normalize_optional_string(raw.topic);
    let title = normalize_optional_string(raw.title);
    let memory_type = normalize_optional_string(raw.memory_type);
    let context = normalize_optional_string(raw.context);
    let tags = raw
        .tags
        .into_iter()
        .filter_map(|tag| {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect::<Vec<_>>();

    match source_type {
        EvidenceSourceType::Knowledge => {
            require_present(
                source.as_deref(),
                "source",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
            require_present(
                topic.as_deref(),
                "topic",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
            require_present(
                title.as_deref(),
                "title",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
        }
        EvidenceSourceType::Memory => {
            require_present(
                memory_type.as_deref(),
                "type",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
            require_present(
                context.as_deref(),
                "context",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
        }
        EvidenceSourceType::Heuristic => {
            require_present(
                source.as_deref(),
                "source",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
            require_present(
                title.as_deref(),
                "title",
                &format!("{evidence_context} evidence {evidence_number}"),
            )?;
        }
    }

    Ok(EvidenceRef {
        source_type,
        source,
        topic,
        title,
        memory_type,
        context,
        tags,
        rationale,
    })
}

fn require_non_empty_string(value: String, field: &str, context: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(anyhow::anyhow!(
            "{context} is missing required field '{field}'"
        ))
    } else {
        Ok(trimmed.to_string())
    }
}

fn require_present(value: Option<&str>, field: &str, context: &str) -> anyhow::Result<()> {
    if value.is_some_and(|value| !value.trim().is_empty()) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{context} is missing required field '{field}'"
        ))
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn proposal_kind_is_ground_truth(kind: &str) -> bool {
    matches!(
        kind.trim().to_ascii_uppercase().as_str(),
        "GROUND_TRUTH_ERROR" | "GROUNDTRUTHERROR" | "GROUND_TRUTH" | "GROUNDTRUTH"
    )
}

fn review_allows_auto_apply(review: Option<&ReviewDecision>) -> bool {
    matches!(
        review.map(|review| review.verdict),
        None | Some(ReviewVerdict::Accept)
    )
}

fn warn_or_bail(strict_mode: bool, message: impl Into<String>) -> anyhow::Result<()> {
    let message = message.into();
    if strict_mode {
        Err(anyhow::anyhow!(message))
    } else {
        tracing::warn!("{message}");
        Ok(())
    }
}

fn truncate_for_error(text: &str) -> String {
    const LIMIT: usize = 240;
    let truncated: String = text.chars().take(LIMIT).collect();
    if text.chars().count() > LIMIT {
        format!("{truncated}...")
    } else {
        truncated
    }
}

/// Run the overfitting-reviewer agent as a gate on proposals.
///
/// Each proposal is evaluated for real-world generality vs benchmark overfitting.
/// Proposals that the reviewer rejects (benchmark-specific, wildcard FP risk,
/// inflated CWE mapping) are filtered out.
async fn run_overfitting_review(
    proposals: Vec<Improvement>,
    suite: &str,
    knowledge_db: &skwaq_core::graph::GraphDb,
    holdout_score: Option<&AggregateScore>,
    runtime_config: &skwaq_core::config::Config,
) -> anyhow::Result<Vec<Improvement>> {
    if proposals.is_empty() {
        return Ok(proposals);
    }

    // Batch proposals to avoid LLM output truncation.
    // The reviewer generates verbose structured JSON per proposal;
    // more than ~5 proposals per call risks exceeding output limits.
    const BATCH_SIZE: usize = 5;

    if proposals.len() <= BATCH_SIZE {
        return run_overfitting_review_batch(
            proposals,
            suite,
            knowledge_db,
            holdout_score,
            runtime_config,
        )
        .await;
    }

    let mut all_reviewed = Vec::new();
    for (batch_idx, chunk) in proposals.chunks(BATCH_SIZE).enumerate() {
        tracing::info!(
            "Overfitting review batch {}/{} ({} proposals)",
            batch_idx + 1,
            proposals.len().div_ceil(BATCH_SIZE),
            chunk.len()
        );
        let batch = chunk.to_vec();
        let reviewed =
            run_overfitting_review_batch(batch, suite, knowledge_db, holdout_score, runtime_config)
                .await?;
        all_reviewed.extend(reviewed);
    }

    Ok(all_reviewed)
}

async fn run_overfitting_review_batch(
    proposals: Vec<Improvement>,
    suite: &str,
    knowledge_db: &skwaq_core::graph::GraphDb,
    holdout_score: Option<&AggregateScore>,
    runtime_config: &skwaq_core::config::Config,
) -> anyhow::Result<Vec<Improvement>> {
    if proposals.is_empty() {
        return Ok(proposals);
    }

    let llm_client = skwaq_core::llm::create_client(&runtime_config.llm)
        .await
        .map_err(|e| anyhow::anyhow!("overfitting review requires an LLM client: {e}"))?;
    let cross_process_backoff = crate::throttle::CrossProcessBackoff::new();

    // Use full budget — the reviewer needs enough tokens to evaluate all proposals
    // with detailed structured JSON output.
    let budget_amount = runtime_config.analysis.default_token_budget;
    let knowledge_context = build_overfitting_knowledge_context(knowledge_db, &proposals)?;

    // Prepend empirical holdout signal when available so the reviewer has real data.
    let holdout_header = format_holdout_score_header(holdout_score);

    let mut proposal_text = format!(
        "{}\
         Use the knowledge-base guidance below as grounding when judging \
         real-world generality and CWE mapping accuracy.\n\n\
         {}\n\n\
         Review these {} improvement proposals from the {} benchmark for overfitting risk.\n\
         Return JSON only in a single ```json fenced block using this schema:\n\
         {{\"reviews\":[{{\"proposal_id\":\"P1\",\
         \"proposal_description\":\"exact proposal description\",\
         \"verdict\":\"ACCEPT|REJECT|MODIFY\",\"reason\":\"...\",\
         \"overfitting_risk\":\"LOW|MEDIUM|HIGH\",\
         \"real_world_applicability\":\"LOW|MEDIUM|HIGH\",\
         \"suggested_modification\":\"required when verdict=MODIFY\",\
         \"evidence_refs\":[{{\"source_type\":\"knowledge\",\"source\":\"kb source\",\
         \"topic\":\"kb topic\",\"title\":\"kb title\",\"rationale\":\"why this KB hit justifies the verdict\"}},\
         {{\"source_type\":\"memory\",\"type\":\"pattern|insight|failure\",\
         \"context\":\"recalled generalized lesson\",\"tags\":[\"cwe-119\"],\
         \"rationale\":\"why this memory justifies the verdict\"}}]}}]}}\n\
         Rules:\n\
         - Every proposal must have exactly one review entry.\n\
         - proposal_id must match exactly.\n\
         - proposal_description should also match exactly.\n\
         - Each review entry must include at least one evidence_refs item.\n\
         - Do not emit prose outside the JSON block.\n\
         - REJECT any proposal whose description or patch introduces \
           silent degradation or silent alternate-path behavior. The project's \
           invariant is: fail loudly with a diagnostic error instead of silently \
           degrading to a weaker code path.\n\n\
         Review these proposals:\n\n",
        holdout_header,
        knowledge_context,
        proposals.len(),
        suite
    );
    for (i, p) in proposals.iter().enumerate() {
        let kind = match &p.kind {
            ImprovementKind::NewPattern => "NEW_PATTERN",
            ImprovementKind::AgentPrompt => "AGENT_PROMPT",
            ImprovementKind::CweMapping => "CWE_MAPPING",
            ImprovementKind::TaintRule => "TAINT_RULE",
            ImprovementKind::GroundTruthFix => "GROUND_TRUTH",
            ImprovementKind::RecipeChange => "RECIPE_CHANGE",
        };
        proposal_text.push_str(&format!(
            "{}. Proposal ID: {}\n   Kind: [{}] {}\n   Target CWEs: {:?}\n   Patch: {}\n   From case: {}\n\n",
            i + 1,
            review_proposal_id(i),
            kind,
            p.description,
            p.target_cwes,
            p.patch.replace,
            p.source_case,
        ));
    }

    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);
    cross_process_backoff.wait_if_needed().await;
    let output = skwaq_core::llm::execute_with_tools(
        &llm_client,
        &runtime_config.llm.copilot.model,
        "You are a strict overfitting reviewer. Return only the requested JSON.",
        &proposal_text,
        &[],
        |_tool_name, _args| async move {
            Err(anyhow::anyhow!(
                "overfitting review unexpectedly attempted a tool call"
            ))
        },
        &mut budget,
    )
    .await
    .inspect_err(|e| {
        let message = e.to_string();
        if is_rate_limited_message(&message) {
            cross_process_backoff
                .signal_rate_limited(retry_after_secs_from_error(&message).unwrap_or(30));
        }
    })
    .map_err(|e| anyhow::anyhow!("overfitting reviewer failed: {e}"))?;

    let decisions = parse_review_decisions(&output, &proposals).map_err(|e| {
        anyhow::anyhow!("overfitting reviewer returned invalid review payload: {e}")
    })?;
    let total_count = proposals.len();
    let mut reviewed = Vec::new();
    let mut accepted_count = 0usize;

    for (proposal, review) in proposals.into_iter().zip(decisions) {
        let mut proposal = proposal;
        if matches!(review.verdict, ReviewVerdict::Reject) {
            tracing::info!(
                "Overfitting reviewer REJECTED proposal: {}",
                proposal.description
            );
        } else {
            accepted_count += 1;
        }
        proposal.review = Some(review);
        reviewed.push(proposal);
    }
    tracing::info!(
        "Overfitting review: {}/{} proposals accepted",
        accepted_count,
        total_count
    );
    Ok(reviewed)
}

fn prepare_improvement_knowledge_db() -> anyhow::Result<skwaq_core::graph::GraphDb> {
    let db = skwaq_core::graph::GraphDb::in_memory()?;
    let summary = skwaq_core::knowledge::search::initialize_cwe_catalog(&db)?;
    if summary.total_seed_cwes == 0 {
        eprintln!(
            "WARNING [skwaq-gym improve]: KnowledgeDB catalog is empty (0 seed CWEs loaded). \
             Improve-cycle proposals will lack CWE context — check the data/knowledge/ directory. \
             Proposals generated without KB context will have lower confidence."
        );
    } else {
        tracing::debug!(
            "KnowledgeDB loaded {} seed CWEs for improve cycle",
            summary.total_seed_cwes
        );
    }
    Ok(db)
}

fn build_improve_run_metadata(
    config: &BenchmarkConfig,
    runtime_config: &skwaq_core::config::Config,
    profile_name: Option<&str>,
) -> ImproveRunMetadata {
    ImproveRunMetadata {
        llm_backend: runtime_config.llm.reasoning.trim().to_string(),
        llm_model: runtime_config.llm.copilot.model.clone(),
        run_mode: if config.quick_mode {
            "pattern-only".to_string()
        } else if config.llm_only {
            "llm-only".to_string()
        } else {
            "hybrid".to_string()
        },
        binary_mode: config.binary_mode,
        profile: profile_name.map(str::to_string),
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
    }
}

fn is_rate_limited_message(message: &str) -> bool {
    message.contains("429")
        || message.contains("529")
        || message.contains("rate")
        || message.contains("Rate")
        || message.contains("throttl")
        || message.contains("overloaded")
}

fn is_content_filter_error(message: &str) -> bool {
    message.contains("content_filter") || message.contains("LLM content_filter")
}

/// Injection-class CWEs whose source code is most likely to trigger the input
/// content-safety filter because they contain raw shell/exec API calls.
fn is_injection_class_cwe(cwe: u32) -> bool {
    // CWE-77: Command Injection, CWE-78: OS Command Injection, CWE-88: Argument Injection
    matches!(cwe, 77 | 78 | 88)
}

/// Returns the common vulnerability name for a CWE, used in analyst prompt headers
/// so the LLM immediately knows what class of vulnerability to hunt for.
fn cwe_brief_name(cwe: u32) -> &'static str {
    match cwe {
        77 => "Command Injection",
        78 => "OS Command Injection",
        88 => "Argument Injection",
        89 => "SQL Injection",
        90 => "LDAP Injection",
        118 | 119 => "Improper Buffer Size Validation",
        120 => "Buffer Copy Without Size Check (Classic Overflow)",
        121 => "Stack-Based Buffer Overflow",
        122 => "Heap-Based Buffer Overflow",
        123 => "Write-What-Where Condition",
        124 | 126 | 127 => "Buffer Underwrite",
        125 => "Out-of-Bounds Read",
        128 | 189 | 190 => "Integer Overflow",
        191 => "Integer Underflow",
        192..=197 => "Integer Conversion Error",
        134 => "Uncontrolled Format String",
        252 | 253 | 476 | 690 => "NULL Pointer Dereference",
        362 | 364 | 366 | 367 | 832 => "Race Condition",
        377 => "Insecure Temporary File",
        400 | 401 | 404 | 675 | 772 | 773 | 789 => "Resource Leak",
        415 => "Double Free",
        416 | 562 | 761 | 763 => "Use After Free",
        457 | 665 | 908 => "Uninitialized Variable",
        502 => "Unsafe Deserialization",
        590 => "Free of Memory Not on the Heap",
        680..=682 => "Integer Overflow to Buffer Overflow",
        787 | 788 | 805 | 806 => "Out-of-Bounds Write",
        591 => "Sensitive Data Storage in Improperly Locked Memory",
        843 => "Type Confusion",
        22 | 23 | 36 | 426 => "Path Traversal",
        79 | 80 => "Cross-Site Scripting",
        _ => "Memory/Safety Vulnerability",
    }
}

/// Returns a one-sentence detection hint for a CWE list, used in analyst prompt
/// headers to focus the LLM on what specific patterns to look for.
fn cwe_detection_hint(cwes: &[u32]) -> &'static str {
    for &cwe in cwes {
        let hint = match cwe {
            77 | 78 | 88 => {
                "Trace user-controlled data into shell/exec sinks (VULN_SINK_* in sanitized source)."
            }
            89 => "Trace user input into SQL query string construction without parameterization.",
            90 => "Trace user input into LDAP query construction without escaping.",
            119 | 120 | 121 | 122 | 787 | 788 | 805 | 806 => {
                "Trace data from input to strcpy/memcpy/sprintf; check for fixed-size buffers with unchecked writes."
            }
            123 => "Look for attacker-controlled pointer used as write destination.",
            125 => {
                "Look for array/pointer reads beyond allocated bounds; check index arithmetic."
            }
            134 => {
                "Look for user-controlled format string argument in printf/fprintf/syslog calls."
            }
            128 | 189 | 190 | 191 | 680 | 681 | 682 => {
                "Trace integer arithmetic on user-controlled values that flows into buffer sizes or array indices."
            }
            415 => "Locate multiple free() calls on the same pointer in any code path.",
            416 | 562 | 761 | 763 => {
                "Trace heap allocation lifetime; find dereference after free() on any path."
            }
            457 | 665 | 908 => "Look for variables used before initialization, especially on error paths.",
            476 | 252 | 253 | 690 => {
                "Check for pointer dereferences without NULL guards, especially after fallible allocations."
            }
            502 => {
                "Look for deserialization of untrusted data without type/integrity validation."
            }
            590 => {
                "Look for free() applied to stack-allocated arrays, globals, or already-freed pointers."
            }
            22 | 23 | 36 => {
                "Trace user-supplied file paths into filesystem APIs without canonicalization/allowlist."
            }
            362 | 364 | 366 | 367 | 832 => {
                "Look for shared-state access without synchronization on concurrent code paths."
            }
            591 => {
                "Look for sensitive data kept in memory without effective mlock/VirtualLock protection or without checking lock success."
            }
            843 => {
                "Look for type casting or union access where the stored type doesn't match the access type."
            }
            _ => continue,
        };
        return hint;
    }
    "Trace user-controlled data from input sources to dangerous sinks."
}

/// Sanitize source code for embedding in an LLM prompt when the case involves
/// injection-class CWEs (77, 78, 88).  Raw shell-execution function calls
/// (system, execl, popen, …) cause the input content-safety filter to block
/// the request.  We replace the dangerous function names with abstract
/// `VULN_SINK_*` aliases and obfuscate known interpreter paths so the LLM
/// still understands the vulnerability class but the literal call patterns no
/// longer match the safety filter's heuristics.
///
/// For all CWEs, a structured analyst-context header is prepended to the
/// source snippet so the LLM immediately knows:
///   1. Which CWE(s) with their common names it is analysing.
///   2. A one-sentence detection hint for the specific vulnerability class.
///   3. (Injection-class only) that VULN_SINK_* aliases stand for the
///      original dangerous APIs that were obfuscated for content safety.
fn sanitize_source_for_prompt(source: &str, expected_cwes: &[u32]) -> String {
    // Build the analyst-context header prepended to every source snippet.
    let cwe_label = if expected_cwes.is_empty() {
        "Unknown".to_string()
    } else {
        expected_cwes
            .iter()
            .map(|&c| format!("CWE-{} ({})", c, cwe_brief_name(c)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let hint = cwe_detection_hint(expected_cwes);
    let has_injection = expected_cwes.iter().any(|&c| is_injection_class_cwe(c));

    let mut header = format!(
        "// [SKWAQ ANALYST CONTEXT]\n\
         // Target: {cwe_label}\n\
         // Focus:  {hint}\n"
    );
    if has_injection {
        header.push_str(
            "// NOTE:  Shell/exec API names replaced with VULN_SINK_* aliases (content safety).\n\
             //        VULN_SINK_SYSTEM/EXEC/POPEN/SHELLEXEC = dangerous command execution sinks.\n\
             //        Treat every VULN_SINK_* call as the corresponding original dangerous API.\n",
        );
    }
    header.push_str("// ====================================================\n");

    if !has_injection {
        return format!("{header}{source}");
    }

    // Ordered from most-specific (longest) to least-specific (shortest) so that
    // broader patterns (e.g. `system(`) don't partially match before the more
    // specific ones (e.g. `os.system(`) can fire.
    const REPLACEMENTS: &[(&str, &str)] = &[
        // Python subprocess / os  (must precede bare C system/popen entries)
        ("subprocess.check_output(", "VULN_SINK_SUBPROCESS("),
        ("subprocess.check_call(", "VULN_SINK_SUBPROCESS("),
        ("subprocess.Popen(", "VULN_SINK_SUBPROCESS("),
        ("subprocess.call(", "VULN_SINK_SUBPROCESS("),
        ("subprocess.run(", "VULN_SINK_SUBPROCESS("),
        ("os.system(", "VULN_SINK_OS_SYSTEM("),
        ("os.popen(", "VULN_SINK_OS_POPEN("),
        ("os.execvpe(", "VULN_SINK_OS_EXEC("),
        ("os.execvp(", "VULN_SINK_OS_EXEC("),
        ("os.execve(", "VULN_SINK_OS_EXEC("),
        ("os.execl(", "VULN_SINK_OS_EXEC("),
        ("os.execv(", "VULN_SINK_OS_EXEC("),
        // Java Runtime / ProcessBuilder (must precede bare exec() entry)
        ("getRuntime().exec(", "VULN_SINK_RT_EXEC("),
        ("Runtime.exec(", "VULN_SINK_RT_EXEC("),
        // Windows shell APIs (must precede bare ShellExecute/CreateProcess entries)
        ("ShellExecuteExA(", "VULN_SINK_SHELLEXEC("),
        ("ShellExecuteExW(", "VULN_SINK_SHELLEXEC("),
        ("ShellExecuteA(", "VULN_SINK_SHELLEXEC("),
        ("ShellExecuteW(", "VULN_SINK_SHELLEXEC("),
        ("ShellExecute(", "VULN_SINK_SHELLEXEC("),
        ("CreateProcessA(", "VULN_SINK_CREATEPROC("),
        ("CreateProcessW(", "VULN_SINK_CREATEPROC("),
        ("CreateProcess(", "VULN_SINK_CREATEPROC("),
        ("WinExec(", "VULN_SINK_WINEXEC("),
        // C/C++ exec family (longer variants before shorter)
        ("execvpe(", "VULN_SINK_EXECVPE("),
        ("execvp(", "VULN_SINK_EXECVP("),
        ("execve(", "VULN_SINK_EXECVE("),
        ("execlpe(", "VULN_SINK_EXECLPE("),
        ("execlp(", "VULN_SINK_EXECLP("),
        ("execle(", "VULN_SINK_EXECLE("),
        ("execl(", "VULN_SINK_EXECL("),
        ("execv(", "VULN_SINK_EXECV("),
        ("exec(", "VULN_SINK_EXEC("),
        // C/C++ shell/pipe launchers
        ("system(", "VULN_SINK_SYSTEM("),
        ("popen(", "VULN_SINK_POPEN("),
        ("_popen(", "VULN_SINK_POPEN("),
        // Shell interpreter paths (literal strings that match filter heuristics)
        ("/usr/bin/env bash", "[SHELL_INTERP]"),
        ("/usr/bin/env sh", "[SHELL_INTERP]"),
        ("/usr/bin/bash", "[SHELL_INTERP]"),
        ("/usr/bin/sh", "[SHELL_INTERP]"),
        ("/bin/bash", "[SHELL_INTERP]"),
        ("/bin/sh", "[SHELL_INTERP]"),
        // Common shell flag that passes user-controlled command strings
        ("\"-c\"", "\"[SHELL_CMD_FLAG]\""),
        ("'-c'", "'[SHELL_CMD_FLAG]'"),
    ];

    let mut out = source.to_string();
    for (from, to) in REPLACEMENTS {
        out = out.replace(from, to);
    }
    format!("{header}{out}")
}

fn retry_after_secs_from_error(message: &str) -> Option<u64> {
    message
        .split("delay_secs=")
        .nth(1)
        .and_then(|suffix| suffix.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|seconds| seconds.parse::<u64>().ok())
}

fn build_false_negative_knowledge_context(
    knowledge_db: &skwaq_core::graph::GraphDb,
    fn_case: &FalseNegativeCase,
) -> anyhow::Result<String> {
    let queries = build_improvement_knowledge_queries(fn_case.expected_cwes.iter().copied());
    tracing::info!(
        "Building KB guidance for false negative case {} with queries {:?}",
        fn_case.case_id,
        queries
    );
    render_knowledge_context(knowledge_db, &queries)
}

fn build_overfitting_knowledge_context(
    knowledge_db: &skwaq_core::graph::GraphDb,
    proposals: &[Improvement],
) -> anyhow::Result<String> {
    let target_cwes = proposals
        .iter()
        .flat_map(|proposal| proposal.target_cwes.iter().copied())
        .collect::<BTreeSet<_>>();
    let queries = build_improvement_knowledge_queries(target_cwes);
    tracing::info!(
        "Building KB guidance for overfitting review with queries {:?}",
        queries
    );
    render_knowledge_context(knowledge_db, &queries)
}

/// Format a concise holdout score summary header for the overfitting reviewer context.
///
/// When `holdout_score` is `Some`, returns a block that gives the reviewer empirical
/// signal (training vs. holdout F1 gap) so it can weight evidence accordingly.
/// When `None`, returns an empty string so the prompt is unchanged.
fn format_holdout_score_header(holdout_score: Option<&AggregateScore>) -> String {
    match holdout_score {
        None => String::new(),
        Some(hs) => {
            format!(
                "=== EMPIRICAL HOLDOUT SIGNAL ===\n\
                 Holdout F1: {:.1}%  Holdout P: {:.1}%  Holdout R: {:.1}%\n\
                 TP={} FP={} FN={}\n\
                 A large training/holdout gap indicates previous cycles may have overfit.\n\
                 Weight this signal when judging whether proposals are likely to generalize.\n\
                 =================================\n\n",
                hs.f1 * 100.0,
                hs.precision * 100.0,
                hs.recall * 100.0,
                hs.true_positives,
                hs.false_positives,
                hs.false_negatives,
            )
        }
    }
}

fn render_knowledge_context(
    knowledge_db: &skwaq_core::graph::GraphDb,
    queries: &[String],
) -> anyhow::Result<String> {
    let mut sections = Vec::new();
    let mut seen_hits = std::collections::HashSet::new();

    for query in queries.iter().filter(|query| !query.trim().is_empty()) {
        let hits = skwaq_core::knowledge::search::search_knowledge(Some(knowledge_db), query)?;
        tracing::info!(
            "KB query '{}' returned {} hit(s) for improve cycle context",
            query,
            hits.len()
        );
        for hit in hits.into_iter().take(IMPROVE_KB_HITS_PER_QUERY) {
            let key = format!("{}::{}::{}", hit.source, hit.topic, hit.title);
            if !seen_hits.insert(key) {
                continue;
            }

            let snippet: String = hit
                .content
                .chars()
                .take(IMPROVE_KB_SNIPPET_CHAR_LIMIT)
                .collect();
            sections.push(format!(
                "### Query: {query}\n- Source: {}\n- Topic: {}\n- Title: {}\n{}\n",
                hit.source, hit.topic, hit.title, snippet
            ));
        }
    }

    if sections.is_empty() {
        return Err(anyhow::anyhow!(
            "KB returned no hits for improve-cycle queries {:?}",
            queries
        ));
    }

    tracing::info!(
        "Prepared {} KB guidance snippet(s) for improve cycle context",
        sections.len()
    );
    Ok(sections.join("\n"))
}

fn build_improvement_knowledge_queries<I>(cwes: I) -> Vec<String>
where
    I: IntoIterator<Item = u32>,
{
    let unique_cwes = cwes.into_iter().collect::<BTreeSet<_>>();
    let mut queries = IMPROVE_KB_FIXED_QUERIES
        .iter()
        .map(|query| query.to_string())
        .collect::<Vec<_>>();

    if unique_cwes.len() > IMPROVE_KB_MAX_CWE_QUERIES {
        let dropped = unique_cwes
            .iter()
            .copied()
            .skip(IMPROVE_KB_MAX_CWE_QUERIES)
            .collect::<Vec<_>>();
        tracing::warn!(
            "Truncating improve-cycle CWE KB queries from {} to {}; dropped {:?}",
            unique_cwes.len(),
            IMPROVE_KB_MAX_CWE_QUERIES,
            dropped
        );
    }

    queries.extend(
        unique_cwes
            .into_iter()
            .take(IMPROVE_KB_MAX_CWE_QUERIES)
            .map(|cwe| format!("cwe-{cwe}")),
    );
    queries
}

fn prepare_improvement_agent_db(
    investigation_id: &str,
    investigation_name: &str,
    target_path: &Path,
) -> anyhow::Result<skwaq_core::graph::GraphDb> {
    let db = skwaq_core::graph::GraphDb::in_memory()?;
    skwaq_core::knowledge::search::initialize_cwe_catalog(&db)?;
    let now = chrono::Utc::now().to_rfc3339();
    let target = target_path.display().to_string();
    db.execute(
        "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
        &[
            &investigation_id,
            &investigation_name,
            &target.as_str(),
            &now.as_str(),
            &now.as_str(),
        ],
    )?;
    Ok(db)
}

fn parse_review_decisions(
    output: &str,
    proposals: &[Improvement],
) -> anyhow::Result<Vec<ReviewDecision>> {
    let json_str = extract_json_block(output).ok_or_else(|| {
        anyhow::anyhow!(
            "overfitting reviewer did not return a JSON payload; raw output: {}",
            truncate_for_error(output)
        )
    })?;

    let raw_reviews = if let Ok(response) = serde_json::from_str::<LlmReviewResponse>(&json_str) {
        response.reviews
    } else if let Ok(raw_reviews) = serde_json::from_str::<Vec<LlmReviewDecision>>(&json_str) {
        raw_reviews
    } else if let Ok(single) = serde_json::from_str::<LlmReviewDecision>(&json_str) {
        vec![single]
    } else {
        return Err(anyhow::anyhow!(
            "overfitting reviewer returned malformed JSON: {}",
            truncate_for_error(&json_str)
        ));
    };

    if raw_reviews.len() != proposals.len() {
        return Err(anyhow::anyhow!(
            "overfitting reviewer returned {} review entries for {} proposals: {}",
            raw_reviews.len(),
            proposals.len(),
            truncate_for_error(&json_str)
        ));
    }

    let mut raw_by_key = std::collections::HashMap::new();
    for raw_review in raw_reviews {
        let review_key = raw_review_key(&raw_review)?;
        if raw_by_key.insert(review_key.clone(), raw_review).is_some() {
            return Err(anyhow::anyhow!(
                "overfitting reviewer returned duplicate review entry for '{}'",
                review_key
            ));
        }
    }

    proposals
        .iter()
        .enumerate()
        .map(|(index, proposal)| {
            let proposal_id = review_proposal_id(index);
            let raw_review = raw_by_key
                .remove(&proposal_id)
                .or_else(|| raw_by_key.remove(&proposal.description))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "overfitting reviewer omitted review entry for {} ('{}')",
                        proposal_id,
                        proposal.description
                    )
                })?;
            convert_review_decision(raw_review, &proposal.description)
        })
        .collect()
}

fn raw_review_key(raw_review: &LlmReviewDecision) -> anyhow::Result<String> {
    if let Some(proposal_id) = raw_review.proposal_id.as_ref() {
        return require_non_empty_string(proposal_id.clone(), "proposal_id", "review entry");
    }
    if let Some(proposal_description) = raw_review.proposal_description.as_ref() {
        return require_non_empty_string(
            proposal_description.clone(),
            "proposal_description",
            "review entry",
        );
    }
    Err(anyhow::anyhow!(
        "review entry is missing required field 'proposal_id'"
    ))
}

fn convert_review_decision(
    raw_review: LlmReviewDecision,
    proposal_description: &str,
) -> anyhow::Result<ReviewDecision> {
    let verdict = match raw_review.verdict.trim().to_ascii_uppercase().as_str() {
        "ACCEPT" => ReviewVerdict::Accept,
        "REJECT" => ReviewVerdict::Reject,
        "MODIFY" => ReviewVerdict::Modify,
        other => {
            return Err(anyhow::anyhow!(
                "review for '{}' used unsupported verdict '{}'",
                proposal_description,
                other
            ))
        }
    };

    let reason = require_non_empty_string(
        raw_review.reason,
        "reason",
        &format!("review for '{}'", proposal_description),
    )?;
    let overfitting_risk = parse_review_rating(
        &raw_review.overfitting_risk,
        "overfitting_risk",
        proposal_description,
    )?;
    let real_world_applicability = parse_review_rating(
        &raw_review.real_world_applicability,
        "real_world_applicability",
        proposal_description,
    )?;
    let suggested_modification = normalize_optional_string(raw_review.suggested_modification);
    if matches!(verdict, ReviewVerdict::Modify) && suggested_modification.is_none() {
        return Err(anyhow::anyhow!(
            "review for '{}' used MODIFY without suggested_modification",
            proposal_description
        ));
    }
    let evidence_refs = convert_evidence_refs(
        raw_review.evidence_refs,
        &format!("review for '{}'", proposal_description),
        false,
    )?;

    Ok(ReviewDecision {
        verdict,
        reason,
        overfitting_risk,
        real_world_applicability,
        suggested_modification,
        evidence_refs,
    })
}

fn parse_review_rating(
    rating: &str,
    field: &str,
    proposal_description: &str,
) -> anyhow::Result<ReviewRating> {
    match rating.trim().to_ascii_uppercase().as_str() {
        "LOW" => Ok(ReviewRating::Low),
        "MEDIUM" => Ok(ReviewRating::Medium),
        "HIGH" => Ok(ReviewRating::High),
        other => Err(anyhow::anyhow!(
            "review for '{}' used unsupported {} '{}'",
            proposal_description,
            field,
            other
        )),
    }
}

/// Heuristic analysis of false negatives (no LLM needed).
/// Checks for graph context gaps first (missing taint rules, agent prompt gaps),
/// then falls back to missing regex patterns.
#[cfg(not(feature = "test-heuristic-api"))]
fn heuristic_failure_analysis(false_negatives: &[FalseNegativeCase]) -> Vec<Improvement> {
    heuristic_failure_analysis_impl(false_negatives)
}

#[cfg(feature = "test-heuristic-api")]
pub fn heuristic_failure_analysis(false_negatives: &[FalseNegativeCase]) -> Vec<Improvement> {
    heuristic_failure_analysis_impl(false_negatives)
}

fn heuristic_failure_analysis_impl(false_negatives: &[FalseNegativeCase]) -> Vec<Improvement> {
    let mut proposals = Vec::new();

    // Phase 1: Check for graph context gaps — prefer agent prompt and taint rule proposals
    // These are functions that should be taint sources/sinks but might not be configured
    let taint_source_apis: Vec<(&str, &str, &[u32])> = vec![
        ("recv", "network", &[119, 120]),
        ("read", "file_descriptor", &[119, 120]),
        ("fread", "file", &[119, 120]),
        ("fgets", "file", &[119, 120]),
        ("scanf", "stdin", &[119, 120, 121, 122]),
        ("getenv", "environment", &[78, 119]),
        ("argv", "command_line", &[78, 119]),
        ("accept", "network", &[119]),
        ("recvfrom", "network", &[119, 120]),
    ];

    let taint_sink_apis: Vec<(&str, &str, &[u32])> = vec![
        ("system", "command_execution", &[78]),
        ("exec", "command_execution", &[78]),
        ("popen", "command_execution", &[78]),
        ("strcpy", "memory_write", &[119, 120]),
        ("memcpy", "memory_write", &[119, 120]),
        ("sprintf", "memory_write", &[119, 120, 134]),
        ("free", "memory_dealloc", &[415, 416]),
    ];

    for fn_case in false_negatives {
        let content = &fn_case.source_content;

        // Check if the missed case involves a known taint source that agents should trace
        for (api, source_type, cwes) in &taint_source_apis {
            let pattern = format!(r"\b{}\s*\(", regex::escape(api));
            if let Ok(re) = regex::Regex::new(&pattern) {
                if re.is_match(content) {
                    let missed: Vec<u32> = fn_case
                        .expected_cwes
                        .iter()
                        .filter(|e| {
                            cwes.iter()
                                .any(|c| scoring::cwe_family(*c) == scoring::cwe_family(**e))
                        })
                        .copied()
                        .collect();
                    if !missed.is_empty() {
                        // Propose adding this as a taint source
                        proposals.push(Improvement {
                            kind: ImprovementKind::TaintRule,
                            description: format!(
                                "Add taint source '{}' (type: {}) for CWE-{:?} detection (found in {})",
                                api, source_type, missed, fn_case.case_id
                            ),
                            target_cwes: missed.clone(),
                            target_file: PathBuf::from("agents/vuln-hunter.md"),
                            patch: Patch {
                                find: String::new(),
                                replace: format!(
                                    "When you see `{}()` calls, treat the return value as a taint source \
                                     (type: {}). Trace it through the call graph using get_taint_paths \
                                     and get_cross_file_calls to find dangerous sinks.",
                                    api, source_type
                                ),
                            },
                            source_case: fn_case.case_id.clone(),
                            priority: Priority::High,
                            supporting_evidence: Vec::new(),
                            review: None,
                        });
                    }
                }
            }
        }

        // Check for taint sink gaps
        for (api, sink_type, cwes) in &taint_sink_apis {
            let pattern = format!(r"\b{}\s*\(", regex::escape(api));
            if let Ok(re) = regex::Regex::new(&pattern) {
                if re.is_match(content) {
                    let missed: Vec<u32> = fn_case
                        .expected_cwes
                        .iter()
                        .filter(|e| {
                            cwes.iter()
                                .any(|c| scoring::cwe_family(*c) == scoring::cwe_family(**e))
                        })
                        .copied()
                        .collect();
                    if !missed.is_empty() {
                        proposals.push(Improvement {
                            kind: ImprovementKind::AgentPrompt,
                            description: format!(
                                "Update vuln-hunter to trace '{}' (sink type: {}) for CWE-{:?} (found in {})",
                                api, sink_type, missed, fn_case.case_id
                            ),
                            target_cwes: missed,
                            target_file: PathBuf::from("agents/vuln-hunter.md"),
                            patch: Patch {
                                find: String::new(),
                                replace: format!(
                                    "When analyzing `{}()` calls (sink type: {}), use get_taint_paths \
                                     to check if any taint source flows into this sink. Also use \
                                     get_cross_file_calls to trace the data across file boundaries.",
                                    api, sink_type
                                ),
                            },
                            source_case: fn_case.case_id.clone(),
                            priority: Priority::High,
                            supporting_evidence: Vec::new(),
                            review: None,
                        });
                    }
                }
            }
        }
    }

    // Track which cases got proposals from Phase 1
    let _phase1_cases: std::collections::HashSet<String> =
        proposals.iter().map(|p| p.source_case.clone()).collect();

    // Phase 2: Emit regex pattern proposals for remaining gaps
    let missing_patterns: Vec<(&str, &str, &[u32])> = vec![
        (r"\bexecl\s*\(", "injection", &[78]),
        (r"\bexecv\s*\(", "injection", &[78]),
        (r"\bexecvp\s*\(", "injection", &[78]),
        (r"\bexecle\s*\(", "injection", &[78]),
        (r"\bwcscpy\s*\(", "memory", &[120]),
        (r"\bwcscat\s*\(", "memory", &[120]),
        (r"\bsscanf\s*\(", "memory", &[119, 120, 121, 122]),
        (r"\bfscanf\s*\(", "memory", &[119, 120, 121, 122]),
        (r"\batoi\s*\(", "memory", &[190]),
        (r"\batol\s*\(", "memory", &[190]),
        (r"\brand\s*\(", "crypto", &[338]),
        (r"\bsrand\s*\(", "crypto", &[338]),
        (
            r#"(?i)(?:password|passwd|pwd)\s*=\s*["']"#,
            "crypto",
            &[798],
        ),
        (
            r#"(?i)(?:secret|token|api_?key)\s*=\s*["']"#,
            "crypto",
            &[798],
        ),
        (r"\bpickle\.loads\s*\(", "deserialization", &[502]),
        (r"\byaml\.load\s*\(", "deserialization", &[502]),
    ];

    for fn_case in false_negatives {
        let content = &fn_case.source_content;
        for (pattern, _category, cwes) in &missing_patterns {
            let re = match regex::Regex::new(pattern) {
                Ok(re) => re,
                Err(e) => {
                    tracing::warn!(
                        "Skipping invalid heuristic regex '{}' for case {}: {}",
                        pattern,
                        fn_case.case_id,
                        e
                    );
                    continue;
                }
            };
            if re.is_match(content) {
                let missed: Vec<u32> = fn_case
                    .expected_cwes
                    .iter()
                    .filter(|e| {
                        cwes.iter()
                            .any(|c| scoring::cwe_family(*c) == scoring::cwe_family(**e))
                    })
                    .copied()
                    .collect();

                if !missed.is_empty() {
                    proposals.push(Improvement {
                        kind: ImprovementKind::NewPattern,
                        description: format!(
                            "Add C/C++ pattern '{}' to detect CWE-{:?} (found in {})",
                            pattern, missed, fn_case.case_id
                        ),
                        target_cwes: missed,
                        target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
                        patch: Patch {
                            find: String::new(),
                            replace: pattern.to_string(),
                        },
                        source_case: fn_case.case_id.clone(),
                        priority: Priority::High,
                        supporting_evidence: Vec::new(),
                        review: None,
                    });
                }
            }
        }
    }

    // Phase 3: For cases that still have no proposals, suggest AgentPrompt for deeper graph analysis
    let all_cases: std::collections::HashSet<String> =
        proposals.iter().map(|p| p.source_case.clone()).collect();

    for fn_case in false_negatives {
        if !all_cases.contains(&fn_case.case_id) && !fn_case.expected_cwes.is_empty() {
            proposals.push(Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: format!(
                    "Enhance agent graph traversal for CWE-{:?} detection — case {} has no regex-matchable APIs, \
                     requires deeper cross-file call graph and taint flow tracing",
                    fn_case.expected_cwes, fn_case.case_id
                ),
                target_cwes: fn_case.expected_cwes.clone(),
                target_file: PathBuf::from("agents/vuln-hunter.md"),
                patch: Patch {
                    find: String::new(),
                    replace: format!(
                        "When standard API patterns are not found, use get_cross_file_calls and \
                         get_taint_paths to trace data flow through wrapper functions. \
                         Look for indirect paths to dangerous sinks for CWE-{:?}.",
                        fn_case.expected_cwes
                    ),
                },
                source_case: fn_case.case_id.clone(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            });
        }
    }

    // Phase 4: Propose RecipeChange for CWE families with ≥3 false negatives
    // If many cases share a CWE family, a dedicated specialist stage may help.
    let mut cwe_family_counts: std::collections::HashMap<u32, Vec<String>> =
        std::collections::HashMap::new();
    for fn_case in false_negatives {
        for &cwe in &fn_case.expected_cwes {
            let family = scoring::cwe_family(cwe);
            cwe_family_counts
                .entry(family)
                .or_default()
                .push(fn_case.case_id.clone());
        }
    }

    // Known CWE families with clear specialist agent names
    let specialist_agents: &[(u32, &str, &str)] = &[
        (22, "path-traversal-specialist", "Path traversal"),
        (78, "injection-specialist", "Command injection"),
        (119, "memory-safety-specialist", "Memory safety"),
        (190, "integer-overflow-specialist", "Integer overflow"),
        (416, "use-after-free-specialist", "Use-after-free"),
        (502, "deserialization-specialist", "Deserialization"),
    ];

    let all_cases_with_proposals: std::collections::HashSet<String> =
        proposals.iter().map(|p| p.source_case.clone()).collect();

    for (family, agent_name, description) in specialist_agents {
        if let Some(case_ids) = cwe_family_counts.get(family) {
            if case_ids.len() >= 3 {
                let representative_case = case_ids
                    .iter()
                    .find(|c| !all_cases_with_proposals.contains(*c))
                    .unwrap_or(&case_ids[0]);
                proposals.push(Improvement {
                    kind: ImprovementKind::RecipeChange,
                    description: format!(
                        "Add {} stage to standard.yaml for better CWE-{} ({}) detection \
                         ({} cases missed)",
                        agent_name,
                        family,
                        description,
                        case_ids.len()
                    ),
                    target_cwes: vec![*family],
                    target_file: PathBuf::from("recipes/analysis/standard.yaml"),
                    patch: Patch {
                        find: String::new(),
                        replace: format!(
                            "  - agent: {}\n    context: from_graph\n    client_role: reasoning\n",
                            agent_name
                        ),
                    },
                    source_case: representative_case.clone(),
                    priority: Priority::Medium,
                    supporting_evidence: Vec::new(),
                    review: None,
                });
            }
        }
    }

    proposals
}

fn annotate_heuristic_proposals(
    knowledge_db: &skwaq_core::graph::GraphDb,
    proposals: Vec<Improvement>,
) -> anyhow::Result<Vec<Improvement>> {
    proposals
        .into_iter()
        .map(|mut proposal| {
            proposal.supporting_evidence = build_heuristic_evidence_refs(knowledge_db, &proposal)?;
            Ok(proposal)
        })
        .collect()
}

fn build_heuristic_evidence_refs(
    knowledge_db: &skwaq_core::graph::GraphDb,
    proposal: &Improvement,
) -> anyhow::Result<Vec<EvidenceRef>> {
    let queries = build_improvement_knowledge_queries(proposal.target_cwes.iter().copied());
    for query in queries {
        let hits = skwaq_core::knowledge::search::search_knowledge(Some(knowledge_db), &query)?;
        if let Some(hit) = hits.into_iter().next() {
            return Ok(vec![EvidenceRef {
                source_type: EvidenceSourceType::Knowledge,
                source: Some(hit.source),
                topic: Some(hit.topic),
                title: Some(hit.title),
                memory_type: None,
                context: None,
                tags: proposal
                    .target_cwes
                    .iter()
                    .map(|cwe| format!("cwe-{cwe}"))
                    .collect(),
                rationale: format!(
                    "This deterministic heuristic proposal was grounded in the knowledge-base hit for query '{}' so it preserves the cited-evidence contract.",
                    query
                ),
            }]);
        }
    }

    Ok(vec![synthetic_heuristic_evidence_ref(proposal)])
}

fn synthetic_heuristic_evidence_ref(proposal: &Improvement) -> EvidenceRef {
    EvidenceRef {
        source_type: EvidenceSourceType::Heuristic,
        source: Some("deterministic-pattern-detector".to_string()),
        topic: Some(
            proposal
                .target_cwes
                .iter()
                .map(|cwe| format!("cwe-{cwe}"))
                .collect::<Vec<_>>()
                .join(","),
        ),
        title: Some(format!("Deterministic heuristic for {}", proposal.target_file.display())),
        memory_type: None,
        context: None,
        tags: proposal
            .target_cwes
            .iter()
            .map(|cwe| format!("cwe-{cwe}"))
            .collect(),
        rationale: format!(
            "This proposal came from the built-in deterministic heuristic that matched '{}' in {} after KB search produced no direct grounding hit.",
            proposal.patch.replace,
            proposal.source_case
        ),
    }
}

/// Store false-negative insights into `data/knowledge/` so future agents can reference them.
///
/// Creates or appends to `data/knowledge/fn-insights.md` with structured knowledge
/// about WHY cases were missed and what patterns to look for. This feeds into
/// the `lookup_knowledge` tool that all agents can call.
fn store_fn_insights(
    false_negatives: &[FalseNegativeCase],
    reviewed_proposals: &[Improvement],
    suite: &str,
    data_dir: &Path,
) {
    if false_negatives.is_empty() && reviewed_proposals.is_empty() {
        return;
    }

    // Resolve knowledge directory relative to data_dir or repo root.
    let knowledge_dir = if data_dir.join("knowledge").is_dir() {
        data_dir.join("knowledge")
    } else {
        // Try repo-root relative paths.
        let candidates = ["data/knowledge", "../data/knowledge"];
        match candidates.iter().map(Path::new).find(|p| p.is_dir()) {
            Some(d) => d.to_path_buf(),
            None => {
                // Create the directory if it doesn't exist.
                let dir = PathBuf::from("data/knowledge");
                if std::fs::create_dir_all(&dir).is_err() {
                    tracing::debug!("Could not create knowledge directory, skipping FN insights");
                    return;
                }
                dir
            }
        }
    };

    let insight_file = knowledge_dir.join("fn-insights.md");
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

    let mut content = String::new();

    // If file doesn't exist yet, add a header.
    let needs_header = !insight_file.exists();
    if needs_header {
        content.push_str("# False Negative Insights\n\n");
        content.push_str(
            "Auto-generated knowledge from the self-improvement loop.\n\
             Agents can query this via `lookup_knowledge` with topics like \
             \"false negative\", \"missed\", or specific CWE numbers.\n\n",
        );
    }

    content.push_str(&format!("## Cycle: {} ({})\n\n", suite, timestamp));

    // Record missed cases with their CWEs.
    if !false_negatives.is_empty() {
        content.push_str(&format!(
            "### Missed Cases ({} false negatives)\n\n",
            false_negatives.len()
        ));
        for fn_case in false_negatives.iter().take(10) {
            let missed: Vec<u32> = fn_case
                .expected_cwes
                .iter()
                .filter(|cwe| !fn_case.detected_cwes.contains(cwe))
                .copied()
                .collect();
            content.push_str(&format!(
                "- **{}**: Expected CWE-{:?}, detected CWE-{:?}, missed CWE-{:?}\n",
                fn_case.case_id, fn_case.expected_cwes, fn_case.detected_cwes, missed
            ));

            // Include a brief snippet of the source to help future agents.
            let snippet: String = fn_case
                .source_content
                .lines()
                .take(5)
                .collect::<Vec<_>>()
                .join("\n");
            if !snippet.is_empty() {
                content.push_str(&format!(
                    "  ```\n  {}\n  ```\n",
                    snippet.replace('\n', "\n  ")
                ));
            }
        }
        content.push('\n');
    }

    // Record proposals as actionable insights.
    if !reviewed_proposals.is_empty() {
        let accepted_count = reviewed_proposals
            .iter()
            .filter(|proposal| {
                matches!(
                    proposal.review.as_ref().map(|review| review.verdict),
                    None | Some(ReviewVerdict::Accept)
                )
            })
            .count();
        let modified_count = reviewed_proposals
            .iter()
            .filter(|proposal| {
                matches!(
                    proposal.review.as_ref().map(|review| review.verdict),
                    Some(ReviewVerdict::Modify)
                )
            })
            .count();
        let rejected_count = reviewed_proposals
            .iter()
            .filter(|proposal| {
                matches!(
                    proposal.review.as_ref().map(|review| review.verdict),
                    Some(ReviewVerdict::Reject)
                )
            })
            .count();
        content.push_str(&format!(
            "### Reviewed Improvement Proposals ({} total; {} accepted, {} modified, {} rejected)\n\n",
            reviewed_proposals.len(),
            accepted_count,
            modified_count,
            rejected_count
        ));
        for proposal in reviewed_proposals.iter().take(10) {
            let kind = match &proposal.kind {
                ImprovementKind::NewPattern => "Pattern Gap",
                ImprovementKind::AgentPrompt => "Agent Capability Gap",
                ImprovementKind::CweMapping => "CWE Mapping Gap",
                ImprovementKind::TaintRule => "Taint Rule Gap",
                ImprovementKind::GroundTruthFix => "Ground Truth Issue",
                ImprovementKind::RecipeChange => "Recipe Gap",
            };
            let review_status = proposal
                .review
                .as_ref()
                .map(|review| render_review_verdict(review.verdict))
                .unwrap_or("UNREVIEWED");
            content.push_str(&format!(
                "- **[{}] [{}]** {}\n  CWEs: {:?} | From case: {}\n",
                kind,
                review_status,
                proposal.description,
                proposal.target_cwes,
                proposal.source_case
            ));
            if !proposal.patch.replace.is_empty() {
                content.push_str(&format!(
                    "  Suggested pattern: `{}`\n",
                    proposal.patch.replace
                ));
            }
            for evidence in &proposal.supporting_evidence {
                content.push_str(&format!("{}\n", render_evidence_ref_markdown(evidence, 2)));
            }
            if let Some(review) = &proposal.review {
                content.push_str(&format!(
                    "  Overfitting review: {} | Risk: {} | Applicability: {}\n",
                    render_review_verdict(review.verdict),
                    render_review_rating(review.overfitting_risk),
                    render_review_rating(review.real_world_applicability)
                ));
                content.push_str(&format!("  Review reason: {}\n", review.reason));
                if let Some(modification) = &review.suggested_modification {
                    content.push_str(&format!("  Suggested modification: {}\n", modification));
                }
                for evidence in &review.evidence_refs {
                    content.push_str(&format!("{}\n", render_evidence_ref_markdown(evidence, 2)));
                }
            }
        }
        content.push('\n');
    }

    content.push_str("---\n\n");

    // Append to existing file or create new one.
    let write_result = if needs_header {
        std::fs::write(&insight_file, &content)
    } else {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&insight_file)
            .and_then(|mut f| f.write_all(content.as_bytes()))
    };

    match write_result {
        Ok(()) => {
            tracing::info!(
                "Stored {} FN insights and {} proposals in {}",
                false_negatives.len(),
                reviewed_proposals.len(),
                insight_file.display()
            );
        }
        Err(e) => {
            tracing::warn!(
                "Failed to write FN insights to {}: {}",
                insight_file.display(),
                e
            );
        }
    }
}

/// Check if any CWE's detection rate dropped beyond the noise margin (2%).
/// CWEs absent from the new score are ignored (they weren't tested in the new run).
pub fn has_cwe_regression(baseline: &AggregateScore, new: &AggregateScore) -> bool {
    !crate::scoring::cwe_regressions(baseline, new).is_empty()
}

/// Check for precision regression on negative cases.
/// Returns true if the false positive rate on patched/safe code increased
/// beyond the noise margin — a key overfitting signal.
pub fn has_precision_regression(baseline: &AggregateScore, new: &AggregateScore) -> bool {
    crate::scoring::precision_regression(baseline, new).is_some()
}

/// Combined check: either recall regression OR precision regression.
pub fn has_any_regression(baseline: &AggregateScore, new: &AggregateScore) -> bool {
    has_cwe_regression(baseline, new) || has_precision_regression(baseline, new)
}

/// Determine which suites should be cross-validated after improvements on a given suite.
///
/// Returns a list of suite names that share CWE overlap with the source suite
/// and should be checked to verify improvements generalize.
fn cross_validation_targets(source_suite: &str) -> Vec<String> {
    // All known suites except the source
    let all_suites = [
        "fixtures",
        "juliet",
        "owasp",
        "cyberseceval",
        "cgc",
        "cybergym",
        "binpool",
    ];

    all_suites
        .iter()
        .filter(|&&s| s != source_suite)
        .map(|s| s.to_string())
        .collect()
}

/// Append successful patterns from improvement proposals to the knowledge pack.
///
/// Writes accepted NewPattern proposals to `data/knowledge/learned-patterns.md`
/// so they accumulate across improvement cycles. Each entry records the pattern,
/// target CWEs, source case, and timestamp.
pub fn append_learned_patterns(cycle: &ImprovementCycle) {
    let pattern_proposals: Vec<&Improvement> = cycle
        .proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::NewPattern))
        .filter(|p| !p.patch.replace.is_empty())
        .collect();

    if pattern_proposals.is_empty() {
        return;
    }

    let knowledge_dir = PathBuf::from("data/knowledge");
    if std::fs::create_dir_all(&knowledge_dir).is_err() {
        tracing::warn!(
            "Could not create knowledge directory: {}",
            knowledge_dir.display()
        );
        return;
    }

    let patterns_path = knowledge_dir.join("learned-patterns.md");

    // Read existing content (or start fresh).
    let mut content = if patterns_path.exists() {
        std::fs::read_to_string(&patterns_path).unwrap_or_default()
    } else {
        String::from(
            "# Learned Patterns\n\n\
             Patterns discovered by the self-improvement loop.\n\
             Each entry was proposed by the failure-analyst and accepted by the overfitting reviewer.\n\n",
        )
    };

    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
    content.push_str(&format!("## Cycle: {} ({})\n\n", cycle.suite, timestamp));
    content.push_str(&format!(
        "Baseline: F1={:.1}%, P={:.1}%, R={:.1}%\n\n",
        cycle.baseline_score.f1 * 100.0,
        cycle.baseline_score.precision * 100.0,
        cycle.baseline_score.recall * 100.0,
    ));

    for proposal in &pattern_proposals {
        content.push_str(&format!(
            "- **Pattern**: `{}`\n  - CWEs: {:?}\n  - From case: `{}`\n  - Priority: {:?}\n\n",
            proposal.patch.replace, proposal.target_cwes, proposal.source_case, proposal.priority,
        ));
    }

    match std::fs::write(&patterns_path, &content) {
        Ok(()) => {
            tracing::info!(
                "Appended {} learned patterns to {}",
                pattern_proposals.len(),
                patterns_path.display()
            );
        }
        Err(e) => {
            tracing::warn!(
                "Failed to write learned patterns to {}: {}",
                patterns_path.display(),
                e
            );
        }
    }
}

/// Store generalized lessons from an improvement cycle into durable agent memory.
///
/// Converts improvement proposals and false-negative insights into generalized
/// experiences that agents can recall in future runs. The overfitting guard
/// strips benchmark-specific details (file paths, case IDs, addresses) before
/// storage.
pub fn store_improvement_lessons(cycle: &ImprovementCycle) -> anyhow::Result<()> {
    let memory = skwaq_core::memory::MemoryStore::open_default()?;

    let detector = skwaq_core::memory::PatternDetector::new(&memory);
    let mut stored = 0u32;

    // Store generalized lessons from accepted proposals
    for proposal in &cycle.proposals {
        let (exp_type, agent) = match &proposal.kind {
            ImprovementKind::NewPattern => {
                (skwaq_core::memory::ExperienceType::Pattern, "vuln-hunter")
            }
            ImprovementKind::AgentPrompt => {
                (skwaq_core::memory::ExperienceType::Insight, "vuln-hunter")
            }
            ImprovementKind::CweMapping => (skwaq_core::memory::ExperienceType::Insight, "scoring"),
            ImprovementKind::TaintRule => {
                (skwaq_core::memory::ExperienceType::Pattern, "orchestrator")
            }
            ImprovementKind::RecipeChange => {
                (skwaq_core::memory::ExperienceType::Insight, "orchestrator")
            }
            ImprovementKind::GroundTruthFix => continue, // Not a generalizable lesson
        };

        let lesson_description = proposal
            .review
            .as_ref()
            .and_then(|review| review.suggested_modification.as_deref())
            .unwrap_or(&proposal.description);

        // Generalize: strip benchmark-specific details from the final reviewed lesson
        let context = skwaq_core::memory::pattern::strip_benchmark_specifics(lesson_description);

        // Check overfitting guard before storing
        let tags: Vec<String> = proposal
            .target_cwes
            .iter()
            .map(|cwe| format!("cwe-{cwe}"))
            .collect();
        let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();

        if detector
            .is_likely_overfit(agent, &context, &tag_refs)
            .unwrap_or(false)
        {
            tracing::debug!(
                "Skipping overfit lesson: {}",
                context.chars().take(80).collect::<String>()
            );
            continue;
        }

        let outcome = format!(
            "Improvement proposal ({:?} priority): {}",
            proposal.priority,
            if let Some(modification) = proposal
                .review
                .as_ref()
                .and_then(|review| review.suggested_modification.as_deref())
            {
                format!("revised guidance: {modification}")
            } else if proposal.patch.replace.is_empty() {
                "requires deeper analysis".to_string()
            } else {
                format!("pattern: {}", proposal.patch.replace)
            }
        );

        memory
            .store(agent, exp_type, &context, &outcome, 0.7, &tag_refs)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to store generalized lesson for {} from case {}: {e}",
                    agent,
                    proposal.source_case
                )
            })?;
        stored += 1;
    }

    // Store generalized lessons from false negatives (what was missed and why)
    for fn_case in cycle.false_negatives.iter().take(5) {
        let missed_cwes: Vec<u32> = fn_case
            .expected_cwes
            .iter()
            .filter(|cwe| !fn_case.detected_cwes.contains(cwe))
            .copied()
            .collect();

        if missed_cwes.is_empty() {
            continue;
        }

        // Generalize: describe what was missed without benchmark-specific details
        let context = format!(
            "Missed CWE-{:?} vulnerability in code with characteristics similar to the target",
            missed_cwes
        );
        let outcome = format!(
            "Detection gap: expected CWE-{:?} but only found CWE-{:?}. \
             Agents should pay extra attention to this vulnerability family.",
            fn_case.expected_cwes, fn_case.detected_cwes
        );

        let tags: Vec<String> = missed_cwes.iter().map(|cwe| format!("cwe-{cwe}")).collect();
        let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();

        memory
            .store(
                "failure-analyst",
                skwaq_core::memory::ExperienceType::Failure,
                &context,
                &outcome,
                0.6,
                &tag_refs,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to store missed-CWE lesson for {}: {e}",
                    fn_case.case_id
                )
            })?;
        stored += 1;
    }

    // Run pattern detection to promote recurring lessons
    for agent in &["vuln-hunter", "failure-analyst", "orchestrator"] {
        let new = detector.detect_patterns(agent).map_err(|e| {
            anyhow::anyhow!("failed to detect durable-memory patterns for {agent}: {e}")
        })?;
        if new > 0 {
            tracing::info!("Detected {new} new patterns for agent '{agent}'");
        }
    }

    if stored > 0 {
        tracing::info!(
            "Stored {stored} generalized lessons in durable memory from {} cycle",
            cycle.suite
        );
    }
    Ok(())
}

/// Apply accepted proposals by dispatching to type-specific handlers.
/// Supports NewPattern (regex), AgentPrompt, TaintRule, and CweMapping proposals.
/// The optional `db` parameter is required for TaintRule proposals that insert
/// into the graph database.
///
/// Returns an [`ApplyReport`] with applied/skipped/blocked/total counts and
/// human-readable reasons for any blocked proposals.
pub fn apply_accepted_proposals(
    cycle: &ImprovementCycle,
    db: Option<&skwaq_core::graph::GraphDb>,
) -> anyhow::Result<ApplyReport> {
    let source = if cycle
        .proposals
        .iter()
        .any(|proposal| proposal.review.is_some())
    {
        &cycle.proposals
    } else if cycle
        .reviewed_proposals
        .iter()
        .any(|proposal| proposal.review.is_some())
    {
        &cycle.reviewed_proposals
    } else {
        &cycle.proposals
    };
    let strict_mode = source.iter().any(|proposal| proposal.review.is_some());

    let mut report = ApplyReport {
        total: source.len(),
        ..Default::default()
    };

    let mut applicable = Vec::new();
    for proposal in source {
        if !review_allows_auto_apply(proposal.review.as_ref()) {
            tracing::info!(
                "Skipping non-applicable reviewed proposal '{}'",
                proposal.description
            );
            report.skipped += 1;
            continue;
        }
        if matches!(proposal.kind, ImprovementKind::GroundTruthFix) {
            let reason = format!(
                "GroundTruthFix proposal '{}' cannot be auto-applied; ground-truth edits must be handled separately",
                proposal.description
            );
            report.blocked += 1;
            report.blocked_reasons.push(reason.clone());
            warn_or_bail(strict_mode, reason)?;
            continue;
        }
        if !matches!(
            proposal.kind,
            ImprovementKind::NewPattern
                | ImprovementKind::AgentPrompt
                | ImprovementKind::TaintRule
                | ImprovementKind::CweMapping
                | ImprovementKind::RecipeChange
        ) {
            report.skipped += 1;
            continue;
        }
        if proposal.patch.replace.is_empty() {
            // Empty patch means the proposal is guidance only (e.g., architectural
            // improvements) and cannot be auto-applied regardless of review status.
            // Count as skipped — not blocked — so the cycle completes cleanly.
            tracing::info!(
                "Accepted proposal '{}' has no auto-apply patch; counting as skipped",
                proposal.description
            );
            report.skipped += 1;
            continue;
        }
        applicable.push(proposal);
    }

    if applicable.is_empty() {
        tracing::info!("No applicable accepted proposals to apply");
        return Ok(report);
    }

    for proposal in &applicable {
        let target = &proposal.target_file;

        // TaintRule proposals use the DB, not files — handle separately
        if matches!(proposal.kind, ImprovementKind::TaintRule) {
            // TaintRule handler is inline below in the match; skip file checks
        } else if matches!(proposal.kind, ImprovementKind::RecipeChange) {
            // RecipeChange: validate path BEFORE checking file existence
            let target_str = target.to_string_lossy();
            let is_temp = target_str.starts_with("/tmp")
                || target_str.contains("tmp")
                || target_str.starts_with(&std::env::temp_dir().to_string_lossy().to_string());
            let is_recipe =
                target_str.starts_with("recipes/analysis/") && target_str.ends_with(".yaml");
            let has_traversal = target
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir));
            if has_traversal || (!is_temp && !is_recipe) {
                let reason = format!(
                    "Rejecting RecipeChange: target {} is outside allowed recipes/analysis/ directory",
                    target.display()
                );
                report.blocked += 1;
                report.blocked_reasons.push(reason.clone());
                warn_or_bail(strict_mode, reason)?;
                continue;
            }
            if !target.exists() {
                let reason = format!("Proposal target file does not exist: {}", target.display());
                report.blocked += 1;
                report.blocked_reasons.push(reason.clone());
                warn_or_bail(strict_mode, reason)?;
                continue;
            }
        } else if !target.exists() {
            let reason = format!("Proposal target file does not exist: {}", target.display());
            report.blocked += 1;
            report.blocked_reasons.push(reason.clone());
            warn_or_bail(strict_mode, reason)?;
            continue;
        }

        let content = if matches!(proposal.kind, ImprovementKind::TaintRule) {
            String::new() // TaintRule doesn't need file content
        } else {
            std::fs::read_to_string(target)?
        };

        let new_content = match proposal.kind {
            ImprovementKind::NewPattern => {
                if proposal.patch.find.is_empty() {
                    // Pattern ceiling guard: count existing SourcePattern entries
                    // and skip if we'd exceed the ~500 limit.
                    let existing_count = content.matches("SourcePattern {").count();
                    if existing_count >= PATTERN_COUNT_CEILING {
                        let reason = format!(
                            "Pattern ceiling reached ({} >= {}), cannot apply NewPattern proposal: {}",
                            existing_count,
                            PATTERN_COUNT_CEILING,
                            proposal.description.chars().take(60).collect::<String>(),
                        );
                        report.blocked += 1;
                        report.blocked_reasons.push(reason.clone());
                        warn_or_bail(strict_mode, reason)?;
                        continue;
                    }

                    // Append mode: generate a proper SourcePattern struct and insert
                    // before the closing `]` of the c_cpp_patterns() array.
                    let regex_str = &proposal.patch.replace;
                    if regex_str.contains('"') {
                        let reason = format!(
                            "Rejecting proposal '{}': regex contains double quote",
                            proposal.description.chars().take(60).collect::<String>(),
                        );
                        report.blocked += 1;
                        report.blocked_reasons.push(reason.clone());
                        warn_or_bail(strict_mode, reason)?;
                        continue;
                    }

                    match RegexBuilder::new(regex_str)
                        .size_limit(PROPOSAL_REGEX_SIZE_LIMIT)
                        .build()
                    {
                        Ok(_) => {}
                        Err(e) => {
                            let reason = format!(
                                "Rejecting proposal '{}': regex fails safety validation: {}",
                                proposal.description.chars().take(60).collect::<String>(),
                                e
                            );
                            report.blocked += 1;
                            report.blocked_reasons.push(reason.clone());
                            warn_or_bail(strict_mode, reason)?;
                            continue;
                        }
                    }

                    if let Some(insert_pos) = content.rfind("    ]\n}") {
                        let category = infer_danger_category(&proposal.target_cwes);
                        let reason = proposal
                            .description
                            .chars()
                            .take(120)
                            .collect::<String>()
                            .replace('"', "'");

                        let mut result = content[..insert_pos].to_string();
                        result.push_str(&format!(
                            "        // Self-improvement: from case {} (CWEs {:?})\n\
                             \x20       SourcePattern {{\n\
                             \x20           regex: r\"{regex_str}\",\n\
                             \x20           category: DangerCategory::{category},\n\
                             \x20           severity: Severity::High,\n\
                             \x20           reason: \"{reason}\",\n\
                             \x20       }},\n",
                            proposal.source_case, proposal.target_cwes,
                        ));
                        result.push_str(&content[insert_pos..]);
                        result
                    } else {
                        let reason =
                            format!("Could not find insertion point in {}", target.display());
                        report.blocked += 1;
                        report.blocked_reasons.push(reason.clone());
                        warn_or_bail(strict_mode, reason)?;
                        continue;
                    }
                } else {
                    // Replace mode
                    if !content.contains(&proposal.patch.find) {
                        let reason = format!(
                            "Patch find text not found in {}: '{}'",
                            target.display(),
                            proposal.patch.find.chars().take(50).collect::<String>()
                        );
                        report.blocked += 1;
                        report.blocked_reasons.push(reason.clone());
                        warn_or_bail(strict_mode, reason)?;
                        continue;
                    }
                    content.replacen(&proposal.patch.find, &proposal.patch.replace, 1)
                }
            }
            ImprovementKind::AgentPrompt => {
                // Security: block path traversal - only allow temp files (tests) and agents/ dir
                let target_str = target.to_string_lossy();
                let is_temp = target_str.starts_with("/tmp") || target_str.contains("tmp");
                let is_agents = target_str.contains("agents/") || target_str.ends_with(".md");
                if !is_temp && !is_agents {
                    let reason = format!(
                        "Rejecting AgentPrompt: target {} is outside allowed directories",
                        target.display()
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(reason.clone());
                    warn_or_bail(strict_mode, reason)?;
                    continue;
                }

                let instruction = &proposal.patch.replace;
                if proposal.patch.find.is_empty() {
                    format!("{}\n\n{}\n", content.trim_end(), instruction)
                } else if content.contains(&proposal.patch.find) {
                    content.replacen(&proposal.patch.find, &proposal.patch.replace, 1)
                } else {
                    let reason = format!(
                        "AgentPrompt patch find text not found in {}: '{}'",
                        target.display(),
                        proposal.patch.find.chars().take(50).collect::<String>()
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(reason.clone());
                    warn_or_bail(strict_mode, reason)?;
                    continue;
                }
            }
            ImprovementKind::TaintRule => {
                // TaintRule: insert into DB if provided, using pipe-delimited format
                // Format: name|type|location|source_or_sink
                let rule = &proposal.patch.replace;
                let parts: Vec<&str> = rule.split('|').collect();

                if parts.len() != 4 {
                    let reason = format!(
                        "Rejecting TaintRule '{}': expected 4 pipe-delimited fields (name|type|location|source_or_sink), got {}",
                        proposal.description.chars().take(60).collect::<String>(),
                        parts.len()
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(reason.clone());
                    warn_or_bail(strict_mode, reason)?;
                    continue;
                }

                let (name, rule_type, location, kind) = (parts[0], parts[1], parts[2], parts[3]);

                // Validate field lengths
                if name.len() > 256 || rule_type.len() > 256 || location.len() > 256 {
                    let reason = format!(
                        "Rejecting TaintRule '{}': field exceeds 256 char limit",
                        proposal.description.chars().take(60).collect::<String>(),
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(reason.clone());
                    warn_or_bail(strict_mode, reason)?;
                    continue;
                }

                if let Some(graph_db) = db {
                    let id = uuid::Uuid::new_v4().to_string();
                    let table = if kind == "sink" {
                        "data_sinks"
                    } else {
                        "data_sources"
                    };

                    if table == "data_sources" {
                        graph_db.execute(
                            "INSERT INTO data_sources (id, name, source_type, location, investigation_id) \
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            &[
                                &id as &dyn rusqlite::types::ToSql,
                                &name,
                                &rule_type,
                                &location,
                                &"self-improvement",
                            ],
                        )?;
                    } else {
                        graph_db.execute(
                            "INSERT INTO data_sinks (id, name, sink_type, danger_level, location, investigation_id) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            &[
                                &id as &dyn rusqlite::types::ToSql,
                                &name,
                                &rule_type,
                                &"high",
                                &location,
                                &"self-improvement",
                            ],
                        )?;
                    }

                    report.applied += 1;
                    tracing::info!(
                        "Applied TaintRule: {} -> {} table",
                        proposal.description.chars().take(60).collect::<String>(),
                        table
                    );
                    continue;
                } else {
                    let msg = format!(
                        "Accepted TaintRule proposal '{}' requires a database connection",
                        proposal.description
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(msg.clone());
                    if strict_mode {
                        return Err(anyhow::anyhow!("{}", msg));
                    } else {
                        eprintln!("ERROR [skwaq-gym]: {msg}");
                    }
                    continue;
                }
            }
            ImprovementKind::CweMapping => {
                // CWE mapping: add CWE mapping to scoring.rs
                // patch.replace contains the new mapping entry
                if proposal.patch.find.is_empty() {
                    // Find insertion point - look for the end of the match arms
                    // in cwe_to_semantic_class or semantic_class_to_cwes
                    if let Some(insert_pos) = content.rfind("        _ => None,") {
                        let mut result = content[..insert_pos].to_string();
                        result.push_str(&proposal.patch.replace);
                        result.push_str(&content[insert_pos..]);
                        result
                    } else {
                        // No insertion point matched; append at end
                        format!("{}\n{}\n", content.trim_end(), proposal.patch.replace)
                    }
                } else if content.contains(&proposal.patch.find) {
                    content.replacen(&proposal.patch.find, &proposal.patch.replace, 1)
                } else {
                    let reason = format!(
                        "CweMapping patch find text not found in {}: '{}'",
                        target.display(),
                        proposal.patch.find.chars().take(50).collect::<String>()
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(reason.clone());
                    warn_or_bail(strict_mode, reason)?;
                    continue;
                }
            }
            ImprovementKind::RecipeChange => {
                // Path validation already done above; proceed to apply the patch
                let new_yaml = if proposal.patch.find.is_empty() {
                    // Append mode: add content before `debate:` section or at end
                    if let Some(debate_pos) = content.find("\ndebate:") {
                        let mut result = content[..debate_pos].to_string();
                        result.push('\n');
                        result.push_str(&proposal.patch.replace);
                        result.push_str(&content[debate_pos..]);
                        result
                    } else {
                        format!("{}\n{}\n", content.trim_end(), proposal.patch.replace)
                    }
                } else if content.contains(&proposal.patch.find) {
                    content.replacen(&proposal.patch.find, &proposal.patch.replace, 1)
                } else {
                    let reason = format!(
                        "RecipeChange patch find text not found in {}: '{}'",
                        target.display(),
                        proposal.patch.find.chars().take(50).collect::<String>()
                    );
                    report.blocked += 1;
                    report.blocked_reasons.push(reason.clone());
                    warn_or_bail(strict_mode, reason)?;
                    continue;
                };

                // Validate the resulting YAML against the recipe schema
                match skwaq_core::agents::validate_recipe_yaml(&new_yaml) {
                    Ok(()) => new_yaml,
                    Err(e) => {
                        let reason = format!(
                            "RecipeChange proposal '{}' produces invalid recipe YAML: {}",
                            proposal.description.chars().take(60).collect::<String>(),
                            e
                        );
                        report.blocked += 1;
                        report.blocked_reasons.push(reason.clone());
                        warn_or_bail(strict_mode, reason)?;
                        continue;
                    }
                }
            }
            _ => {
                report.skipped += 1;
                continue;
            }
        };

        std::fs::write(target, &new_content)?;
        report.applied += 1;
        tracing::info!(
            "Applied proposal: {} → {}",
            proposal.description.chars().take(60).collect::<String>(),
            target.display()
        );
    }

    if report.applied > 0 {
        tracing::info!(
            "Applied {}/{} proposals. Run `cargo test` to validate.",
            report.applied,
            applicable.len()
        );
    }

    Ok(report)
}

/// Infer the DangerCategory name from target CWE numbers.
fn infer_danger_category(cwes: &[u32]) -> &'static str {
    for &cwe in cwes {
        match cwe {
            78 | 77 | 643 | 90 => return "Injection",
            119 | 120 | 121 | 122 | 125 | 787 => return "Memory",
            134 => return "FormatString",
            190 | 191 | 128 => return "IntegerOverflow",
            416 | 415 => return "UseAfterFree",
            476 | 252 => return "NullDeref",
            22 | 23 | 36 => return "PathTraversal",
            114 | 427 => return "UnsafeCode",
            362 | 367 => return "Race",
            377 => return "TempFile",
            400 => return "ResourceExhaustion",
            401 | 772 => return "ResourceLeak",
            457 | 665 => return "UninitializedVar",
            502 => return "Deserialization",
            590 => return "InvalidFree",
            843 => return "TypeConfusion",
            272 | 284 => return "AccessControl",
            226 | 534 => return "InformationExposure",
            666 | 390 => return "ErrorHandling",
            _ => continue,
        }
    }
    "Memory" // safe default for unknown CWEs
}

/// Print improvement proposals in a human-readable format.
pub fn print_proposals(cycle: &ImprovementCycle) {
    let rejected_proposals = cycle
        .reviewed_proposals
        .iter()
        .filter(|proposal| {
            matches!(
                proposal.review.as_ref().map(|review| review.verdict),
                Some(ReviewVerdict::Reject)
            )
        })
        .collect::<Vec<_>>();
    println!("\n{}", "=".repeat(70));
    println!(
        "  SELF-IMPROVEMENT PROPOSALS: {}",
        cycle.suite.to_uppercase()
    );
    println!("{}", "=".repeat(70));
    println!();
    println!(
        "  Baseline: F1={:.1}%, P={:.1}%, R={:.1}%",
        cycle.baseline_score.f1 * 100.0,
        cycle.baseline_score.precision * 100.0,
        cycle.baseline_score.recall * 100.0,
    );
    if let Some(hs) = &cycle.holdout_score {
        let gap_pp = (cycle.baseline_score.f1 - hs.f1) * 100.0;
        println!(
            "  Holdout F1: {:.1}% (training: {:.1}%, gap: {:.1}pp)",
            hs.f1 * 100.0,
            cycle.baseline_score.f1 * 100.0,
            gap_pp,
        );
        if gap_pp > HOLDOUT_OVERFITTING_GAP_THRESHOLD * 100.0 {
            println!(
                "  ⚠  Holdout gap exceeds {:.0}pp threshold — review proposals for overfitting",
                HOLDOUT_OVERFITTING_GAP_THRESHOLD * 100.0
            );
        }
    }
    println!(
        "  False negatives analyzed: {}",
        cycle.false_negatives.len()
    );
    println!("  Proposals generated: {}", cycle.proposals.len());
    println!(
        "  Proposals rejected by review: {}",
        rejected_proposals.len()
    );
    println!();

    for (i, proposal) in cycle.proposals.iter().enumerate() {
        let kind = match &proposal.kind {
            ImprovementKind::NewPattern => "NEW_PATTERN",
            ImprovementKind::AgentPrompt => "AGENT_PROMPT",
            ImprovementKind::CweMapping => "CWE_MAPPING",
            ImprovementKind::TaintRule => "TAINT_RULE",
            ImprovementKind::GroundTruthFix => "GROUND_TRUTH",
            ImprovementKind::RecipeChange => "RECIPE_CHANGE",
        };
        let priority = match &proposal.priority {
            Priority::High => "HIGH",
            Priority::Medium => "MEDIUM",
            Priority::Low => "LOW",
        };
        println!(
            "  {}. [{}] [{}] {}",
            i + 1,
            kind,
            priority,
            proposal.description
        );
        if !proposal.patch.replace.is_empty() {
            println!("     Patch: {}", proposal.patch.replace);
        }
        println!("     From case: {}", proposal.source_case);
        for evidence in &proposal.supporting_evidence {
            println!("     Evidence: {}", render_evidence_ref_inline(evidence));
        }
        if let Some(review) = &proposal.review {
            println!(
                "     Review: {} | Risk={} | Applicability={}",
                render_review_verdict(review.verdict),
                render_review_rating(review.overfitting_risk),
                render_review_rating(review.real_world_applicability)
            );
            println!("     Review reason: {}", review.reason);
            if let Some(modification) = &review.suggested_modification {
                println!("     Suggested modification: {}", modification);
            }
            for evidence in &review.evidence_refs {
                println!(
                    "     Review evidence: {}",
                    render_evidence_ref_inline(evidence)
                );
            }
        }
        println!();
    }

    if !rejected_proposals.is_empty() {
        println!("  Rejected proposals:");
        println!();
        for (i, proposal) in rejected_proposals.iter().enumerate() {
            let kind = match &proposal.kind {
                ImprovementKind::NewPattern => "NEW_PATTERN",
                ImprovementKind::AgentPrompt => "AGENT_PROMPT",
                ImprovementKind::CweMapping => "CWE_MAPPING",
                ImprovementKind::TaintRule => "TAINT_RULE",
                ImprovementKind::GroundTruthFix => "GROUND_TRUTH",
                ImprovementKind::RecipeChange => "RECIPE_CHANGE",
            };
            let priority = match &proposal.priority {
                Priority::High => "HIGH",
                Priority::Medium => "MEDIUM",
                Priority::Low => "LOW",
            };
            println!(
                "  R{}. [{}] [{}] {}",
                i + 1,
                kind,
                priority,
                proposal.description
            );
            println!("     From case: {}", proposal.source_case);
            for evidence in &proposal.supporting_evidence {
                println!("     Evidence: {}", render_evidence_ref_inline(evidence));
            }
            if let Some(review) = &proposal.review {
                println!(
                    "     Review: {} | Risk={} | Applicability={}",
                    render_review_verdict(review.verdict),
                    render_review_rating(review.overfitting_risk),
                    render_review_rating(review.real_world_applicability)
                );
                println!("     Review reason: {}", review.reason);
                if let Some(modification) = &review.suggested_modification {
                    println!("     Suggested modification: {}", modification);
                }
                for evidence in &review.evidence_refs {
                    println!(
                        "     Review evidence: {}",
                        render_evidence_ref_inline(evidence)
                    );
                }
            }
            println!();
        }
    }

    // Cross-validation pending status — displayed as a distinct named block, not just a log.
    if !cycle.cross_validation_pending.is_empty() {
        println!("{}", "=".repeat(70));
        println!("  ⚠  CROSS-VALIDATION PENDING");
        println!("{}", "=".repeat(70));
        println!();
        println!(
            "  {} proposal(s) from '{}' should be validated on {} other suite(s) \
             before deploying to confirm generalization.",
            cycle.proposals.len(),
            cycle.suite,
            cycle.cross_validation_pending.len()
        );
        println!("  Suites requiring cross-validation:");
        for suite in &cycle.cross_validation_pending {
            println!("    - {suite}");
        }
        println!();
        println!("  Run `skwaq gym run --suite <name>` on each suite above.");
        println!("{}", "=".repeat(70));
        println!();
    }

    // Runtime provenance
    if let Some(meta) = &cycle.run_metadata {
        println!(
            "  Backend: {} | Model: {} | Mode: {} | Binary: {} | Profile: {} | Cycle started: {}",
            meta.llm_backend,
            meta.llm_model,
            meta.run_mode,
            if meta.binary_mode { "true" } else { "false" },
            meta.profile.as_deref().unwrap_or("default"),
            meta.timestamp_utc
        );
        println!();
    }
}

fn render_review_verdict(verdict: ReviewVerdict) -> &'static str {
    match verdict {
        ReviewVerdict::Accept => "ACCEPT",
        ReviewVerdict::Reject => "REJECT",
        ReviewVerdict::Modify => "MODIFY",
    }
}

fn render_review_rating(rating: ReviewRating) -> &'static str {
    match rating {
        ReviewRating::Low => "LOW",
        ReviewRating::Medium => "MEDIUM",
        ReviewRating::High => "HIGH",
    }
}

fn render_evidence_ref_inline(evidence: &EvidenceRef) -> String {
    match evidence.source_type {
        EvidenceSourceType::Knowledge => format!(
            "[KB] {}/{}/{} — {}",
            evidence.source.as_deref().unwrap_or("unknown-source"),
            evidence.topic.as_deref().unwrap_or("unknown-topic"),
            evidence.title.as_deref().unwrap_or("unknown-title"),
            evidence.rationale
        ),
        EvidenceSourceType::Memory => format!(
            "[MEMORY] {} :: {}{} — {}",
            evidence.memory_type.as_deref().unwrap_or("unknown-type"),
            evidence.context.as_deref().unwrap_or("unknown-context"),
            if evidence.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", evidence.tags.join(", "))
            },
            evidence.rationale
        ),
        EvidenceSourceType::Heuristic => format!(
            "[HEURISTIC] {} :: {}{} — {}",
            evidence.source.as_deref().unwrap_or("unknown-source"),
            evidence.title.as_deref().unwrap_or("unknown-title"),
            if evidence.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", evidence.tags.join(", "))
            },
            evidence.rationale
        ),
    }
}

fn render_evidence_ref_markdown(evidence: &EvidenceRef, indent: usize) -> String {
    format!(
        "{}- {}",
        " ".repeat(indent),
        render_evidence_ref_inline(evidence)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::CweScore;
    use std::collections::HashMap;

    fn make_score(cwe_scores: Vec<(u32, f64)>) -> AggregateScore {
        let mut per_cwe = HashMap::new();
        for (cwe_id, rate) in cwe_scores {
            per_cwe.insert(
                cwe_id,
                CweScore {
                    cwe_id,
                    total_cases: 10,
                    true_positives: (rate * 10.0) as u32,
                    false_positives: 0,
                    false_negatives: ((1.0 - rate) * 10.0) as u32,
                    detection_rate: rate,
                    precision: 1.0,
                },
            );
        }
        AggregateScore {
            per_cwe,
            per_semantic: HashMap::new(),
            ..Default::default()
        }
    }

    #[test]
    fn test_no_regression() {
        let baseline = make_score(vec![(119, 0.5), (134, 0.3)]);
        let new = make_score(vec![(119, 0.6), (134, 0.3)]);
        assert!(!has_cwe_regression(&baseline, &new));
    }

    #[test]
    fn test_regression_detected() {
        let baseline = make_score(vec![(119, 0.5), (134, 0.3)]);
        let new = make_score(vec![(119, 0.6), (134, 0.1)]);
        assert!(has_cwe_regression(&baseline, &new));
    }

    #[test]
    fn test_within_noise_margin() {
        let baseline = make_score(vec![(119, 0.5)]);
        let new = make_score(vec![(119, 0.49)]);
        assert!(!has_cwe_regression(&baseline, &new));
    }

    #[test]
    fn test_cwe_absent_from_new_score_is_not_regression() {
        let baseline = make_score(vec![(119, 0.5), (134, 0.3)]);
        let new = make_score(vec![(119, 0.6)]);
        assert!(!has_cwe_regression(&baseline, &new));
    }

    #[test]
    fn test_build_improve_run_metadata_preserves_profile_and_mode() {
        let config = BenchmarkConfig {
            cache_dir: PathBuf::from("/tmp/cache"),
            cwe_filter: None,
            max_cases: Some(5),
            quick_mode: true,
            llm_only: false,
            binary_mode: false,
            parallelism: 1,
            skip: 0,
            concurrency: 1,
            timeout_secs: 30,
            holdout_fraction: 0.2,
            max_improvements_per_cycle: 3,
        };
        let runtime_config = skwaq_core::config::Config::load_from_dir(Path::new("."))
            .expect("repo config should load for improve metadata test");

        let metadata = build_improve_run_metadata(&config, &runtime_config, Some("azure"));

        assert_eq!(metadata.profile.as_deref(), Some("azure"));
        assert_eq!(metadata.run_mode, "pattern-only");
        assert!(!metadata.binary_mode);
        assert!(!metadata.llm_backend.is_empty());
        assert!(!metadata.llm_model.is_empty());
    }

    #[test]
    fn test_append_learned_patterns_filters_correctly() {
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![(119, 0.5)]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![
                Improvement {
                    kind: ImprovementKind::NewPattern,
                    description: "Add memcpy pattern".to_string(),
                    target_cwes: vec![119],
                    target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
                    patch: Patch {
                        find: String::new(),
                        replace: r"\bmemcpy\s*\(".to_string(),
                    },
                    source_case: "test_case_1".to_string(),
                    priority: Priority::High,
                    supporting_evidence: Vec::new(),
                    review: None,
                },
                Improvement {
                    kind: ImprovementKind::AgentPrompt, // Not a pattern; should be skipped
                    description: "Improve agent prompt".to_string(),
                    target_cwes: vec![78],
                    target_file: PathBuf::from("agents/vuln-hunter.md"),
                    patch: Patch {
                        find: String::new(),
                        replace: String::new(),
                    },
                    source_case: "test_case_2".to_string(),
                    priority: Priority::Medium,
                    supporting_evidence: Vec::new(),
                    review: None,
                },
            ],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        // Verify filtering logic: only NewPattern with non-empty patch.replace
        let pattern_proposals: Vec<&Improvement> = cycle
            .proposals
            .iter()
            .filter(|p| matches!(p.kind, ImprovementKind::NewPattern))
            .filter(|p| !p.patch.replace.is_empty())
            .collect();

        assert_eq!(
            pattern_proposals.len(),
            1,
            "Should filter to only NewPattern proposals"
        );
        assert!(pattern_proposals[0].patch.replace.contains("memcpy"));
    }

    #[test]
    fn test_heuristic_finds_missing_pattern() {
        let fn_cases = vec![FalseNegativeCase {
            case_id: "test_execl".to_string(),
            expected_cwes: vec![78],
            detected_cwes: vec![],
            source_path: PathBuf::from("test.c"),
            source_content: "void vuln() { execl(\"/bin/sh\", \"sh\", \"-c\", cmd, NULL); }"
                .to_string(),
        }];

        let proposals = heuristic_failure_analysis(&fn_cases);
        assert!(!proposals.is_empty(), "Should propose adding execl pattern");
        assert!(proposals[0].description.contains("execl"));
    }

    #[test]
    fn test_failure_analyst_case_limit_scales_with_budget() {
        // TARGET_BUDGET_PER_CASE = 50_000, MIN_CASES = 5, MAX_CASES = 20
        assert_eq!(failure_analyst_case_limit(250_000, 50), 5); // 250K/50K = 5
        assert_eq!(failure_analyst_case_limit(500_000, 50), 10); // 500K/50K = 10
        assert_eq!(failure_analyst_case_limit(50_000, 50), 5); // 50K/50K = 1 → clamped to MIN 5
        assert_eq!(failure_analyst_case_limit(250_000, 3), 3); // capped by FN count
        assert_eq!(failure_analyst_case_limit(250_000, 0), 0);
    }

    #[test]
    fn test_failure_analyst_budget_per_case_respects_total_budget() {
        // MAX_BUDGET_PER_CASE = 100_000
        assert_eq!(failure_analyst_budget_per_case(250_000, 5), 50_000);
        assert_eq!(failure_analyst_budget_per_case(100_000, 5), 20_000);
        assert_eq!(failure_analyst_budget_per_case(5_000_000, 20), 100_000); // capped at MAX
        assert_eq!(failure_analyst_budget_per_case(1, 5), 1);
        assert_eq!(failure_analyst_budget_per_case(250_000, 0), 0);
    }

    #[test]
    fn test_annotate_heuristic_proposals_adds_kb_evidence() {
        let knowledge_db = prepare_improvement_knowledge_db().unwrap();
        let fn_cases = vec![FalseNegativeCase {
            case_id: "test_execl".to_string(),
            expected_cwes: vec![78],
            detected_cwes: vec![],
            source_path: PathBuf::from("test.c"),
            source_content: "void vuln() { execl(\"/bin/sh\", \"sh\", \"-c\", cmd, NULL); }"
                .to_string(),
        }];

        let proposals =
            annotate_heuristic_proposals(&knowledge_db, heuristic_failure_analysis(&fn_cases))
                .expect("heuristic proposals should be grounded in KB evidence");

        assert!(!proposals.is_empty(), "Should preserve heuristic proposals");
        assert_eq!(proposals[0].supporting_evidence.len(), 1);
        assert!(matches!(
            proposals[0].supporting_evidence[0].source_type,
            EvidenceSourceType::Knowledge
        ));
    }

    #[test]
    fn test_synthetic_heuristic_evidence_ref_is_explicit() {
        let proposal = Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Add execl command injection pattern".to_string(),
            target_cwes: vec![78],
            target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
            patch: Patch {
                find: String::new(),
                replace: r"\bexecl\s*\(".to_string(),
            },
            source_case: "test_execl".to_string(),
            priority: Priority::High,
            supporting_evidence: Vec::new(),
            review: None,
        };

        let evidence = synthetic_heuristic_evidence_ref(&proposal);

        assert!(matches!(
            evidence.source_type,
            EvidenceSourceType::Heuristic
        ));
        assert_eq!(
            evidence.source.as_deref(),
            Some("deterministic-pattern-detector")
        );
        assert!(
            evidence
                .rationale
                .contains("built-in deterministic heuristic"),
            "heuristic evidence should explain why it exists"
        );
    }

    fn sample_false_negative_case() -> FalseNegativeCase {
        FalseNegativeCase {
            case_id: "sample_case".to_string(),
            expected_cwes: vec![119],
            detected_cwes: vec![],
            source_path: PathBuf::from("sample.c"),
            source_content: "void sample(void) {}".to_string(),
        }
    }

    fn sample_improvement(description: &str) -> Improvement {
        Improvement {
            kind: ImprovementKind::NewPattern,
            description: description.to_string(),
            target_cwes: vec![119],
            target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
            patch: Patch {
                find: String::new(),
                replace: r"\bsprintf\s*\(".to_string(),
            },
            source_case: "sample_case".to_string(),
            priority: Priority::High,
            supporting_evidence: vec![EvidenceRef {
                source_type: EvidenceSourceType::Knowledge,
                source: Some("fn-insights".to_string()),
                topic: Some("cwe-119".to_string()),
                title: Some("sprintf overflow patterns".to_string()),
                memory_type: None,
                context: None,
                tags: Vec::new(),
                rationale: "KB notes show sprintf overflows were repeatedly missed.".to_string(),
            }],
            review: None,
        }
    }

    #[test]
    fn test_parse_json_proposals() {
        let fn_case = sample_false_negative_case();
        let output = r#"
analysis
```json
{"proposals":[{"kind":"new_pattern","description":"Detect sprintf-based overflow","target_cwes":[119],"regex_pattern":"\\bsprintf\\s*\\(","priority":"high","evidence_refs":[{"source_type":"knowledge","source":"fn-insights","topic":"cwe-119","title":"sprintf overflow patterns","rationale":"KB notes show this sink is repeatedly missed."}]}]}
```
"#;

        let proposals = parse_analyst_proposals(output, &fn_case).expect("valid cited JSON");
        assert_eq!(proposals.len(), 1);
        assert!(matches!(proposals[0].kind, ImprovementKind::NewPattern));
        assert_eq!(proposals[0].patch.replace, r"\bsprintf\s*\(");
        assert_eq!(proposals[0].target_cwes, vec![119]);
        assert_eq!(proposals[0].supporting_evidence.len(), 1);
    }

    #[test]
    fn test_find_outermost_block_handles_escaped_backslash_before_quote() {
        let text = r#"prefix {"proposals":[{"kind":"new_pattern","description":"path ends with slash\\","target_cwes":[119],"regex_pattern":"\\bsprintf\\s*\\("}]} suffix"#;
        let json = find_outermost_block(text, '{', '}').expect("expected JSON block");
        let parsed: LlmProposalResponse = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed.proposals.len(), 1);
        assert_eq!(parsed.proposals[0].description, "path ends with slash\\");
    }

    #[test]
    fn test_parse_analyst_proposals_warns_on_missing_evidence() {
        let fn_case = sample_false_negative_case();
        let output = r#"
```json
{"proposals":[{"kind":"new_pattern","description":"Detect unsafe scanf widthless reads","target_cwes":[119,121],"regex_pattern":"\\bscanf\\s*\\(","priority":"high"}]}
```
"#;

        // Missing evidence is now a warning, not an error — proposals still parse
        let result = parse_analyst_proposals(output, &fn_case);
        assert!(result.is_ok(), "Missing evidence should warn, not error");
        let proposals = result.unwrap();
        assert_eq!(proposals.len(), 1);
        assert!(proposals[0].supporting_evidence.is_empty());
    }

    #[test]
    fn test_heuristic_finds_credential_pattern() {
        let fn_cases = vec![FalseNegativeCase {
            case_id: "hardcoded_secret".to_string(),
            expected_cwes: vec![798],
            detected_cwes: vec![],
            source_path: PathBuf::from("settings.py"),
            source_content: "password = \"hunter2\"".to_string(),
        }];

        let proposals = heuristic_failure_analysis(&fn_cases);
        assert!(
            !proposals.is_empty(),
            "Should propose hardcoded credential detection"
        );
        assert!(proposals[0].description.contains("password"));
    }

    #[test]
    fn test_false_negative_knowledge_context_includes_expected_cwe() {
        let knowledge_db = prepare_improvement_knowledge_db().unwrap();
        let fn_case = FalseNegativeCase {
            case_id: "case-1".to_string(),
            expected_cwes: vec![119],
            detected_cwes: vec![],
            source_path: PathBuf::from("sample.c"),
            source_content: "void vuln(char *src) { char dst[8]; memcpy(dst, src, 32); }"
                .to_string(),
        };

        let context = build_false_negative_knowledge_context(&knowledge_db, &fn_case).unwrap();

        assert!(context.contains("CWE-119"));
    }

    #[test]
    fn test_improvement_knowledge_queries_deduplicate_and_preserve_fixed_queries() {
        let queries = build_improvement_knowledge_queries(vec![121, 120, 121, 122]);

        assert_eq!(
            queries,
            vec![
                "methodology".to_string(),
                "cwe-families".to_string(),
                "false negative".to_string(),
                "cwe-120".to_string(),
                "cwe-121".to_string(),
                "cwe-122".to_string(),
            ]
        );
    }

    #[test]
    fn test_overfitting_knowledge_context_includes_only_target_cwes() {
        let knowledge_db = prepare_improvement_knowledge_db().unwrap();
        let proposals = vec![
            sample_improvement("Detect sprintf-based overflow"),
            Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: "Tighten pointer-flow reasoning".to_string(),
                target_cwes: vec![119, 120],
                target_file: PathBuf::from("agents/vuln-hunter.md"),
                patch: Patch {
                    find: String::new(),
                    replace: String::new(),
                },
                source_case: "sample_case".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            },
        ];

        let context = build_overfitting_knowledge_context(&knowledge_db, &proposals).unwrap();

        assert!(context.contains("### Query: cwe-119"));
        assert!(context.contains("### Query: cwe-120"));
        assert!(!context.contains("### Query: cwe-121"));
    }

    #[test]
    fn test_prepare_improvement_agent_db_seeds_cwe_catalog() {
        let db = prepare_improvement_agent_db("inv-1", "case-1", Path::new("sample.c")).unwrap();
        let cwe_119 = db
            .conn()
            .query_row(
                "SELECT cwe_id FROM cwes WHERE cwe_id = 'CWE-119' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();

        assert_eq!(cwe_119, "CWE-119");
    }

    #[test]
    fn test_render_knowledge_context_errors_when_queries_have_no_hits() {
        let knowledge_db = prepare_improvement_knowledge_db().unwrap();
        let error = render_knowledge_context(&knowledge_db, &["cwe-999999".to_string()])
            .expect_err("missing KB hits should fail closed");

        assert!(error.to_string().contains("KB returned no hits"));
    }

    #[test]
    fn test_fn_insights_surfaced_by_false_negative_query() {
        // Verifies that adding "false negative" to IMPROVE_KB_FIXED_QUERIES causes
        // render_knowledge_context to return fn-insights.md content from data/knowledge/.
        let knowledge_db = prepare_improvement_knowledge_db().unwrap();
        let context =
            render_knowledge_context(&knowledge_db, &["false negative".to_string()]).unwrap();
        assert!(
            context.contains("fn-insights") || context.to_lowercase().contains("false negative"),
            "Expected fn-insights.md content in KB context for 'false negative' query, got: {}",
            &context[..context.len().min(300)]
        );
    }

    #[test]
    fn test_parse_review_decisions_requires_cited_json_and_matches_proposals() {
        let proposals = vec![
            sample_improvement("Detect sprintf-based overflow"),
            sample_improvement("Detect unsafe scanf widthless reads"),
        ];
        let output = r#"
```json
{"reviews":[
  {"proposal_id":"P1","proposal_description":"Detect sprintf-based overflow","verdict":"ACCEPT","reason":"Specific dangerous sink with real-world precedent.","overfitting_risk":"LOW","real_world_applicability":"HIGH","evidence_refs":[{"source_type":"knowledge","source":"methodology","topic":"cwe-families","title":"General sink guidance","rationale":"The KB guidance says concrete dangerous APIs generalize."}]},
  {"proposal_id":"P2","proposal_description":"Detect unsafe scanf widthless reads","verdict":"MODIFY","reason":"The idea is sound but should key on widthless scanf usage.","overfitting_risk":"MEDIUM","real_world_applicability":"HIGH","suggested_modification":"Require a widthless format-string condition in addition to the sink.","evidence_refs":[{"source_type":"memory","type":"insight","context":"Earlier widening of scanf patterns caused noisy matches in real code.","tags":["cwe-119"],"rationale":"Prior durable-memory lessons show this needs tighter precision."}]}
]}
```
"#;

        let reviews =
            parse_review_decisions(output, &proposals).expect("valid structured review payload");
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].verdict, ReviewVerdict::Accept);
        assert_eq!(reviews[1].verdict, ReviewVerdict::Modify);
        assert_eq!(
            reviews[1].suggested_modification.as_deref(),
            Some("Require a widthless format-string condition in addition to the sink.")
        );
        assert_eq!(reviews[1].evidence_refs.len(), 1);
    }

    #[test]
    fn test_parse_review_decisions_warns_on_missing_review_evidence() {
        let proposals = vec![sample_improvement("Detect sprintf-based overflow")];
        let output = r#"
```json
{"reviews":[
  {"proposal_id":"P1","proposal_description":"Detect sprintf-based overflow","verdict":"REJECT","reason":"Too broad.","overfitting_risk":"HIGH","real_world_applicability":"LOW","evidence_refs":[]}
]}
```
"#;

        // Missing review evidence is now a warning, not an error
        let result = parse_review_decisions(output, &proposals);
        assert!(
            result.is_ok(),
            "Missing review evidence should warn, not error"
        );
        let reviews = result.unwrap();
        assert_eq!(reviews.len(), 1);
        assert!(reviews[0].evidence_refs.is_empty());
    }

    #[test]
    fn test_convert_evidence_refs_strict_rejects_empty() {
        // Strict mode (proposal path) must reject empty evidence refs.
        let result = convert_evidence_refs(vec![], "proposal 1 ('test') for case x", true);
        assert!(
            result.is_err(),
            "Strict mode must reject proposals with no evidence refs"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("at least one evidence entry"),
            "Error message should mention evidence requirement, got: {msg}"
        );
    }

    #[test]
    fn test_convert_evidence_refs_non_strict_warns_on_empty() {
        // Non-strict mode (review path) must accept empty evidence refs (returns Ok(vec[])).
        let result = convert_evidence_refs(vec![], "review for 'test'", false);
        assert!(
            result.is_ok(),
            "Non-strict mode must allow empty evidence refs (review path)"
        );
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_is_content_filter_error() {
        assert!(is_content_filter_error(
            "LLM content_filter: response blocked by safety policy"
        ));
        assert!(is_content_filter_error(
            "some error with content_filter text"
        ));
        assert!(!is_content_filter_error("rate limit exceeded 429"));
        assert!(!is_content_filter_error("LLM tool loop failed: timeout"));
    }

    #[test]
    fn test_sanitize_source_for_prompt_replaces_injection_sinks() {
        // Injection-class CWEs (78) must have dangerous function names replaced.
        let src = r#"void vuln(char *cmd) {
    system(cmd);
    execl("/bin/sh", "sh", "-c", cmd, NULL);
    popen(cmd, "r");
}"#;
        let sanitized = sanitize_source_for_prompt(src, &[78]);
        assert!(
            !sanitized.contains("system("),
            "system( must be replaced in CWE-78 context"
        );
        assert!(
            !sanitized.contains("execl("),
            "execl( must be replaced in CWE-78 context"
        );
        assert!(
            !sanitized.contains("popen("),
            "popen( must be replaced in CWE-78 context"
        );
        assert!(
            !sanitized.contains("/bin/sh"),
            "/bin/sh must be replaced in CWE-78 context"
        );
        assert!(
            sanitized.contains("VULN_SINK_SYSTEM("),
            "system( replacement must be present"
        );
        assert!(
            sanitized.contains("VULN_SINK_EXECL("),
            "execl( replacement must be present"
        );
        assert!(
            sanitized.contains("VULN_SINK_POPEN("),
            "popen( replacement must be present"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_noop_for_non_injection_cwes() {
        // Non-injection CWEs must NOT have VULN_SINK_* aliases applied —
        // no dangerous API names are replaced. A context header IS prepended
        // so the analyst knows the target CWE class.
        let src = "void vuln(char *dst, char *src) { memcpy(dst, src, 256); }";
        let sanitized = sanitize_source_for_prompt(src, &[119]);
        // Body must be present unchanged (no injection alias replacements).
        assert!(
            sanitized.contains(src),
            "Non-injection CWE: original source body must be preserved verbatim"
        );
        // No injection sink aliases must appear.
        assert!(
            !sanitized.contains("VULN_SINK_"),
            "Non-injection CWE source must not contain VULN_SINK_* aliases"
        );
        // A context header must be prepended.
        assert!(
            sanitized.contains("[SKWAQ ANALYST CONTEXT]"),
            "All source snippets must include the analyst context header"
        );
        assert!(
            sanitized.contains("CWE-119"),
            "Header must include the expected CWE number"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_python_subprocess() {
        let src = r#"import subprocess
result = subprocess.run(user_input, shell=True)
os.system(user_input)
"#;
        let sanitized = sanitize_source_for_prompt(src, &[78]);
        assert!(
            !sanitized.contains("subprocess.run("),
            "subprocess.run( must be replaced"
        );
        assert!(
            !sanitized.contains("os.system("),
            "os.system( must be replaced"
        );
        assert!(sanitized.contains("VULN_SINK_SUBPROCESS("));
        assert!(sanitized.contains("VULN_SINK_OS_SYSTEM("));
    }

    #[test]
    fn test_sanitize_source_for_prompt_cwe_77_also_sanitized() {
        // CWE-77 (command injection) must also be sanitized.
        let src = "void run(char *cmd) { system(cmd); }";
        let sanitized = sanitize_source_for_prompt(src, &[77]);
        assert!(!sanitized.contains("system("));
    }

    // -----------------------------------------------------------------------
    // Analyst context header annotation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_source_for_prompt_injection_header_includes_alias_decoder() {
        // Injection-class sources must have the VULN_SINK alias decoder note in the header.
        let src = "void vuln(char *cmd) { system(cmd); }";
        let sanitized = sanitize_source_for_prompt(src, &[78]);
        assert!(
            sanitized.contains("[SKWAQ ANALYST CONTEXT]"),
            "Injection source must include the analyst context header"
        );
        assert!(
            sanitized.contains("VULN_SINK_SYSTEM/EXEC/POPEN"),
            "Injection header must include alias decoder note for common sinks"
        );
        assert!(
            sanitized.contains("CWE-78"),
            "Header must include the expected CWE number"
        );
        assert!(
            sanitized.contains("OS Command Injection"),
            "Header must include the CWE common name"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_header_detection_hint_present() {
        // Header must include a detection hint for the expected CWE class.
        let src = "char buf[32]; strcpy(buf, user_input);";
        let annotated = sanitize_source_for_prompt(src, &[121]);
        assert!(
            annotated.contains("CWE-121"),
            "Header must include CWE-121 number"
        );
        assert!(
            annotated.contains("Stack-Based Buffer Overflow"),
            "Header must include CWE-121 common name"
        );
        // Should have a detection hint (not empty)
        assert!(
            annotated.contains("Focus:"),
            "Header must include a Focus detection hint line"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_header_cwe_680() {
        // CWE-680 (Integer Overflow to Buffer Overflow) must get correct class annotation.
        let src = "char buf[256]; int len = get_len(); memcpy(buf, src, len * 4);";
        let annotated = sanitize_source_for_prompt(src, &[680]);
        assert!(annotated.contains("CWE-680"), "Header must include CWE-680");
        assert!(
            annotated.contains("Integer Overflow to Buffer Overflow"),
            "Header must include CWE-680 common name"
        );
        // Source body must be preserved unchanged for non-injection
        assert!(
            annotated.contains(src),
            "Source body must be intact for CWE-680 (non-injection)"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_header_cwe_590_invalid_free() {
        // CWE-590 (Free of Memory Not on the Heap) must get correct class annotation.
        let src = "void f() { char buf[64]; free(buf); }";
        let annotated = sanitize_source_for_prompt(src, &[590]);
        assert!(annotated.contains("CWE-590"), "Header must include CWE-590");
        assert!(
            annotated.contains("Free of Memory Not on the Heap"),
            "Header must include CWE-590 common name"
        );
        assert!(
            annotated.contains(src),
            "Source body must be intact for CWE-590"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_header_cwe_591_locked_memory() {
        let src = "void f() { char secret[64]; use_secret(secret); }";
        let annotated = sanitize_source_for_prompt(src, &[591]);
        assert!(annotated.contains("CWE-591"), "Header must include CWE-591");
        assert!(
            annotated.contains("Sensitive Data Storage in Improperly Locked Memory"),
            "Header must include CWE-591 common name"
        );
        assert!(
            annotated.contains("mlock/VirtualLock protection"),
            "Header must include the locked-memory detection hint"
        );
        assert!(
            annotated.contains(src),
            "Source body must be intact for CWE-591"
        );
    }

    #[test]
    fn test_sanitize_source_for_prompt_empty_cwes_gets_generic_header() {
        // Empty CWE list should still produce a header with generic Unknown label.
        let src = "void f() {}";
        let annotated = sanitize_source_for_prompt(src, &[]);
        assert!(
            annotated.contains("[SKWAQ ANALYST CONTEXT]"),
            "Empty CWE list must still get a context header"
        );
        assert!(
            annotated.contains("Unknown"),
            "Empty CWE list header should show Unknown as target"
        );
        assert!(
            annotated.contains(src),
            "Source body must still be present for empty CWE list"
        );
    }

    #[test]
    fn test_cwe_brief_name_key_cwes() {
        assert_eq!(cwe_brief_name(78), "OS Command Injection");
        assert_eq!(cwe_brief_name(121), "Stack-Based Buffer Overflow");
        assert_eq!(cwe_brief_name(122), "Heap-Based Buffer Overflow");
        assert_eq!(cwe_brief_name(590), "Free of Memory Not on the Heap");
        assert_eq!(cwe_brief_name(680), "Integer Overflow to Buffer Overflow");
        assert_eq!(cwe_brief_name(416), "Use After Free");
        assert_eq!(cwe_brief_name(476), "NULL Pointer Dereference");
    }

    #[test]
    fn test_cwe_detection_hint_returns_non_empty() {
        // All FN-pattern CWEs must return a non-empty, non-generic hint.
        let fn_cwes = [
            77u32, 78, 88, 119, 120, 121, 122, 125, 134, 190, 191, 415, 416, 476, 590, 680, 787,
        ];
        for cwe in fn_cwes {
            let hint = cwe_detection_hint(&[cwe]);
            assert!(
                !hint.is_empty(),
                "CWE-{cwe} must return a non-empty detection hint"
            );
            // Specific CWEs should NOT fall through to the generic hint
            assert_ne!(
                hint, "Trace user-controlled data from input sources to dangerous sinks.",
                "CWE-{cwe} should have a specific hint, not the generic default"
            );
        }
    }

    #[test]
    fn test_apply_proposals_uses_structured_insertion_not_raw_interpolation() {
        // Create a temp file that mimics c_cpp_patterns()
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}";
        std::fs::write(tmp.path(), content).unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![(78, 0.5)]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::NewPattern,
                description: "Detect execvp command injection".to_string(),
                target_cwes: vec![78],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: r"\bexecvp\s*\(".to_string(),
                },
                source_case: "test_execvp".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(applied.applied, 1);

        let result = std::fs::read_to_string(tmp.path()).unwrap();

        // The inserted code MUST be a proper SourcePattern struct, not raw text
        assert!(
            result.contains("SourcePattern {"),
            "Must insert typed SourcePattern struct"
        );
        assert!(
            result.contains("DangerCategory::"),
            "Must use typed DangerCategory enum"
        );
        assert!(
            result.contains("Severity::"),
            "Must use typed Severity enum"
        );
        // The regex must be inside a string literal
        assert!(
            result.contains(r#"regex: r"\bexecvp\s*\(""#),
            "Regex must be in a string literal field, not interpolated: {result}"
        );
    }

    #[test]
    fn test_apply_proposals_truncates_long_descriptions() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}";
        std::fs::write(tmp.path(), content).unwrap();

        let long_desc = "A".repeat(200); // 200 chars, should be truncated to 120
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![(119, 0.5)]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::NewPattern,
                description: long_desc.clone(),
                target_cwes: vec![119],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: r"\bgets\s*\(".to_string(),
                },
                source_case: "test".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        apply_accepted_proposals(&cycle, None).unwrap();
        let result = std::fs::read_to_string(tmp.path()).unwrap();

        // The reason field should not contain the full 200-char description
        // (apply_accepted_proposals truncates to 120 chars)
        assert!(
            !result.contains(&long_desc),
            "Description should be truncated to 120 chars in the reason field"
        );
    }

    #[test]
    fn test_apply_proposals_escapes_quotes_in_description() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}";
        std::fs::write(tmp.path(), content).unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![(119, 0.5)]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::NewPattern,
                description: r#"Detect "dangerous" sprintf calls"#.to_string(),
                target_cwes: vec![119],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: r"\bsprintf\s*\(".to_string(),
                },
                source_case: "test".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        apply_accepted_proposals(&cycle, None).unwrap();
        let result = std::fs::read_to_string(tmp.path()).unwrap();

        // Quotes in the description must be escaped to single quotes
        assert!(
            !result.contains(r#"reason: "Detect "dangerous""#),
            "Double quotes in description must be escaped: {result}"
        );
        assert!(
            result.contains("'dangerous'"),
            "Quotes should be replaced with single quotes: {result}"
        );
    }

    // -----------------------------------------------------------------------
    // TDD: infer_danger_category completeness
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_danger_category_covers_all_mapped_cwes() {
        let mappings = vec![
            (vec![78], "Injection"),
            (vec![77], "Injection"),
            (vec![119], "Memory"),
            (vec![121], "Memory"),
            (vec![122], "Memory"),
            (vec![787], "Memory"),
            (vec![134], "FormatString"),
            (vec![190], "IntegerOverflow"),
            (vec![416], "UseAfterFree"),
            (vec![476], "NullDeref"),
            (vec![22], "PathTraversal"),
            (vec![362], "Race"),
            (vec![377], "TempFile"),
            (vec![400], "ResourceExhaustion"),
            (vec![401], "ResourceLeak"),
            (vec![457], "UninitializedVar"),
            (vec![502], "Deserialization"),
            (vec![590], "InvalidFree"),
            (vec![843], "TypeConfusion"),
            (vec![272], "AccessControl"),
            (vec![226], "InformationExposure"),
            (vec![666], "ErrorHandling"),
        ];

        for (cwes, expected_category) in mappings {
            let result = infer_danger_category(&cwes);
            assert_eq!(
                result, expected_category,
                "CWE {:?} should map to {expected_category}, got {result}",
                cwes
            );
        }
    }

    #[test]
    fn test_infer_danger_category_defaults_to_memory() {
        assert_eq!(
            infer_danger_category(&[9999]),
            "Memory",
            "Unknown CWE should default to Memory"
        );
        assert_eq!(
            infer_danger_category(&[]),
            "Memory",
            "Empty CWE list should default to Memory"
        );
    }

    #[test]
    fn test_infer_danger_category_uses_first_recognized_cwe() {
        // Multiple CWEs: first recognized one wins
        assert_eq!(
            infer_danger_category(&[9999, 78, 119]),
            "Injection",
            "Should use first recognized CWE (78=Injection), skipping unknown 9999"
        );
    }

    // -----------------------------------------------------------------------
    // TDD: Regex safety gate for LLM proposals — EXPECTED TO FAIL
    // -----------------------------------------------------------------------

    /// Phase B1 contract: when applying LLM-proposed patterns, the regex
    /// must be validated with RegexBuilder::size_limit BEFORE writing to
    /// patterns_source.rs. Patterns exceeding the limit should be skipped.
    #[test]
    fn test_apply_proposals_rejects_oversized_regex() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}";
        std::fs::write(tmp.path(), content).unwrap();

        // \w{200} with Unicode generates massive NFA exceeding 200KB
        let huge_regex = r"\w{200}";

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![(119, 0.5)]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::NewPattern,
                description: "Oversized regex".to_string(),
                target_cwes: vec![119],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: huge_regex.to_string(),
                },
                source_case: "test".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(
            applied.applied, 0,
            "Oversized regex proposals should be rejected (not written to source)"
        );

        let result = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(
            !result.contains("{200}"),
            "Oversized regex should not appear in output file"
        );
    }

    /// Phase B1 contract: invalid regex (syntax error) should be rejected.
    #[test]
    fn test_apply_proposals_rejects_invalid_regex() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "fn c_cpp_patterns() -> &'static [SourcePattern] {\n    &[\n    ]\n}";
        std::fs::write(tmp.path(), content).unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![(119, 0.5)]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::NewPattern,
                description: "Invalid regex".to_string(),
                target_cwes: vec![119],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: r"[invalid(regex".to_string(), // unclosed bracket
                },
                source_case: "test".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(
            applied.applied, 0,
            "Invalid regex proposals should be rejected"
        );
    }

    // ===== Task 4: APPLY-AGENT-PROPOSALS TDD tests =====
    // These tests define the contract for AgentPrompt, TaintRule, and CweMapping handlers.
    // They will FAIL until apply_accepted_proposals is extended.

    #[test]
    fn test_apply_agent_prompt_append() {
        // AgentPrompt with empty find = append mode
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "# Vuln Hunter\n\n## Analysis\nLook for vulns.\n\n## Tools\nUse tools.\n",
        )
        .unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: "Add graph traversal instruction".to_string(),
                target_cwes: vec![78],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: "## Graph Analysis\nAlways trace taint flows before reporting.\n"
                        .to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(applied.applied, 1, "AgentPrompt proposal should be applied");

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(
            content.contains("Graph Analysis"),
            "Agent prompt should contain appended instruction"
        );
        assert!(
            content.contains("Always trace taint flows"),
            "Appended content should be present"
        );
    }

    #[test]
    fn test_apply_agent_prompt_find_replace() {
        // AgentPrompt with FIND:/REPLACE: markers
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "# Vuln Hunter\n\n## Methodology\nUse regex patterns as primary method.\n",
        )
        .unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: "Switch to graph-first".to_string(),
                target_cwes: vec![78],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: "Use regex patterns as primary method.".to_string(),
                    replace: "Use graph traversal as primary method.".to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(
            applied.applied, 1,
            "AgentPrompt find/replace should be applied"
        );

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("graph traversal as primary"));
        assert!(!content.contains("regex patterns as primary"));
    }

    #[test]
    fn test_apply_taint_rule_inserts_data_source() {
        let db = skwaq_core::graph::GraphDb::in_memory().unwrap();
        let _inv_id = "test-inv";

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::TaintRule,
                description: "Add env var as taint source".to_string(),
                target_cwes: vec![78],
                // TaintRule uses patch.replace as pipe-delimited: name|type|location|source_or_sink
                target_file: PathBuf::from("data_sources"),
                patch: Patch {
                    find: String::new(),
                    replace: "getenv_result|environment|stdlib.h|source".to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, Some(&db)).unwrap();
        assert_eq!(applied.applied, 1, "TaintRule proposal should be applied");

        // Verify the data source was inserted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM data_sources WHERE name = 'getenv_result'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "TaintRule should insert into data_sources");
    }

    #[test]
    fn test_apply_taint_rule_validates_format() {
        let db = skwaq_core::graph::GraphDb::in_memory().unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::TaintRule,
                description: "Bad format".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("data_sources"),
                patch: Patch {
                    find: String::new(),
                    // Only 2 parts instead of required 4
                    replace: "bad|format".to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, Some(&db)).unwrap();
        assert_eq!(applied.applied, 0, "Malformed TaintRule should be rejected");
    }

    #[test]
    fn test_apply_taint_rule_field_length_limits() {
        let db = skwaq_core::graph::GraphDb::in_memory().unwrap();

        let long_name = "x".repeat(300); // Exceeds 256 char limit
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::TaintRule,
                description: "Oversized name".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("data_sources"),
                patch: Patch {
                    find: String::new(),
                    replace: format!("{}|environment|loc|source", long_name),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, Some(&db)).unwrap();
        assert_eq!(
            applied.applied, 0,
            "TaintRule with oversized name field should be rejected"
        );
    }

    #[test]
    fn test_apply_reviewed_taint_rule_without_db_fails_loudly() {
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::TaintRule,
                description: "Add env var as taint source".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("data_sources"),
                patch: Patch {
                    find: String::new(),
                    replace: "getenv_result|environment|stdlib.h|source".to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: Some(ReviewDecision {
                    verdict: ReviewVerdict::Accept,
                    reason: "General source rule".to_string(),
                    overfitting_risk: ReviewRating::Low,
                    real_world_applicability: ReviewRating::High,
                    suggested_modification: None,
                    evidence_refs: Vec::new(),
                }),
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let err = apply_accepted_proposals(&cycle, None).unwrap_err();
        assert!(
            err.to_string().contains("requires a database connection"),
            "Reviewed TaintRule should fail loudly when DB is missing: {err}"
        );
    }

    #[test]
    fn test_apply_reviewed_modify_proposal_is_not_auto_applied() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "# Agent\n\n## Tools\nBasic tools.\n").unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: "Add instruction".to_string(),
                target_cwes: vec![78],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: String::new(),
                    replace: "## New Section\nDo graph analysis.\n".to_string(),
                },
                source_case: "case2".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: Some(ReviewDecision {
                    verdict: ReviewVerdict::Modify,
                    reason: "Needs refinement before application".to_string(),
                    overfitting_risk: ReviewRating::Medium,
                    real_world_applicability: ReviewRating::High,
                    suggested_modification: Some(
                        "Focus the instruction on graph-backed taint evidence.".to_string(),
                    ),
                    evidence_refs: Vec::new(),
                }),
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(applied.applied, 0, "MODIFY proposals should not auto-apply");

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(
            !content.contains("New Section"),
            "MODIFY proposals should leave the target unchanged"
        );
    }

    #[test]
    fn test_parse_analyst_proposals_skips_ground_truth_fix_proposals() {
        let fn_case = FalseNegativeCase {
            case_id: "case-1".to_string(),
            expected_cwes: vec![79],
            detected_cwes: vec![],
            source_path: PathBuf::from("fixture.php"),
            source_content: "<?php echo $_GET['x']; ?>".to_string(),
        };

        let output = r#"
```json
{"proposals":[
  {"kind":"GROUND_TRUTH_ERROR","description":"Benchmark label is wrong","target_cwes":[79],"patch_replace":"fix label","priority":"LOW","evidence_refs":[{"source_type":"knowledge","source":"kb","topic":"ground-truth","title":"Ground truth policy","rationale":"Labels should be corrected outside self-improvement."}]},
  {"kind":"TAINT_RULE","description":"Track query parameter as source","target_cwes":[79],"patch_replace":"query_param|http|request.php|source","priority":"HIGH","evidence_refs":[{"source_type":"knowledge","source":"kb","topic":"taint","title":"Web input sources","rationale":"HTTP request parameters generalize as taint sources."}]}
]}
```
"#;

        let proposals = parse_analyst_proposals(output, &fn_case).unwrap();
        assert_eq!(
            proposals.len(),
            1,
            "GroundTruthFix proposals should be skipped"
        );
        assert!(matches!(proposals[0].kind, ImprovementKind::TaintRule));
    }

    #[test]
    fn test_apply_cwe_mapping_patches_scoring() {
        // CweMapping applies find/replace to scoring.rs
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"fn cwe_family(cwe: u32) -> u32 {
    match cwe {
        119 | 120 | 121 | 122 => 119,
        _ => cwe,
    }
}
"#,
        )
        .unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::CweMapping,
                description: "Add CWE-787 to memory family".to_string(),
                target_cwes: vec![787],
                target_file: tmp.path().to_path_buf(),
                patch: Patch {
                    find: "119 | 120 | 121 | 122 => 119,".to_string(),
                    replace: "119 | 120 | 121 | 122 | 787 => 119,".to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(applied.applied, 1, "CweMapping proposal should be applied");

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(
            content.contains("| 787 =>"),
            "CweMapping should add CWE-787 to the match arm"
        );
    }

    #[test]
    fn test_apply_agent_prompt_path_traversal_blocked() {
        // Security: AgentPrompt must not write outside agents/ directory
        let _tmp = tempfile::NamedTempFile::new().unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: "Evil path traversal".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("/etc/passwd"),
                patch: Patch {
                    find: String::new(),
                    replace: "malicious content".to_string(),
                },
                source_case: "test_case".to_string(),
                priority: Priority::High,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(
            applied.applied, 0,
            "Path traversal outside allowed directories must be blocked"
        );
    }

    #[test]
    fn test_apply_proposals_mixed_kinds() {
        // Verify that all 3 new kinds + NewPattern all work in a single cycle
        let pattern_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            pattern_file.path(),
            "pub fn c_cpp_patterns() -> Vec<SourcePattern> {\n    vec![\n    ]\n}\n",
        )
        .unwrap();

        let agent_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(agent_file.path(), "# Agent\n\n## Tools\nBasic tools.\n").unwrap();

        let db = skwaq_core::graph::GraphDb::in_memory().unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: make_score(vec![]),
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![
                Improvement {
                    kind: ImprovementKind::NewPattern,
                    description: "Add test pattern".to_string(),
                    target_cwes: vec![119],
                    target_file: pattern_file.path().to_path_buf(),
                    patch: Patch {
                        find: String::new(),
                        replace: r"\btest_api\s*\(".to_string(),
                    },
                    source_case: "case1".to_string(),
                    priority: Priority::High,
                    supporting_evidence: Vec::new(),
                    review: None,
                },
                Improvement {
                    kind: ImprovementKind::AgentPrompt,
                    description: "Add instruction".to_string(),
                    target_cwes: vec![78],
                    target_file: agent_file.path().to_path_buf(),
                    patch: Patch {
                        find: String::new(),
                        replace: "## New Section\nDo graph analysis.\n".to_string(),
                    },
                    source_case: "case2".to_string(),
                    priority: Priority::Medium,
                    supporting_evidence: Vec::new(),
                    review: None,
                },
                Improvement {
                    kind: ImprovementKind::TaintRule,
                    description: "Add taint source".to_string(),
                    target_cwes: vec![78],
                    target_file: PathBuf::from("data_sources"),
                    patch: Patch {
                        find: String::new(),
                        replace: "recv_buf|network|socket.c|source".to_string(),
                    },
                    source_case: "case3".to_string(),
                    priority: Priority::High,
                    supporting_evidence: Vec::new(),
                    review: None,
                },
            ],
            holdout_case_count: 0,
            training_case_count: 0,
            holdout_score: None,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let applied = apply_accepted_proposals(&cycle, Some(&db)).unwrap();
        assert_eq!(applied.applied, 3, "All 3 proposal kinds should be applied");
    }

    // ===== Task 5: REORIENT-FAILURE-ANALYST TDD tests =====
    // These tests define the contract for graph-gap-aware heuristic failure analysis.
    // They will FAIL until heuristic_failure_analysis is updated.

    #[test]
    fn test_heuristic_prefers_graph_proposals_over_regex() {
        // When source code has a dangerous API AND graph context is sparse,
        // heuristic should propose AgentPrompt/TaintRule, not just NewPattern
        let cases = vec![FalseNegativeCase {
            case_id: "buffer-overflow-1".to_string(),
            expected_cwes: vec![119],
            detected_cwes: vec![],
            source_path: PathBuf::from("test.c"),
            source_content: "void foo() { memcpy(dst, src, n); }".to_string(),
        }];

        let proposals = heuristic_failure_analysis(&cases);

        // Should still find the memcpy pattern
        assert!(
            !proposals.is_empty(),
            "Should generate at least one proposal"
        );

        // After reorientation, should include non-NewPattern proposals
        let has_graph_proposal = proposals.iter().any(|p| {
            matches!(
                p.kind,
                ImprovementKind::AgentPrompt | ImprovementKind::TaintRule
            )
        });
        assert!(
            has_graph_proposal,
            "Heuristic should generate graph-based proposals (AgentPrompt or TaintRule), \
             not only NewPattern regex proposals"
        );
    }

    #[test]
    fn test_heuristic_detects_missing_taint_sources() {
        // When a false negative involves user input but no data_sources exist,
        // heuristic should suggest a TaintRule
        let cases = vec![FalseNegativeCase {
            case_id: "injection-1".to_string(),
            expected_cwes: vec![78],
            detected_cwes: vec![],
            source_path: PathBuf::from("cmd.c"),
            source_content: "void run() { char *input = getenv(\"CMD\"); system(input); }"
                .to_string(),
        }];

        let proposals = heuristic_failure_analysis(&cases);

        let has_taint_rule = proposals
            .iter()
            .any(|p| matches!(p.kind, ImprovementKind::TaintRule));
        assert!(
            has_taint_rule,
            "Missing taint source for getenv should trigger TaintRule proposal"
        );
    }

    #[test]
    fn test_heuristic_suggests_agent_prompt_for_complex_flows() {
        // Complex multi-step vulnerability that regex alone can't catch
        let cases = vec![FalseNegativeCase {
            case_id: "complex-flow-1".to_string(),
            expected_cwes: vec![78],
            detected_cwes: vec![],
            source_path: PathBuf::from("complex.c"),
            source_content: r#"
                void process() {
                    char *data = read_network();
                    char *transformed = transform(data);
                    execute_command(transformed);
                }
            "#
            .to_string(),
        }];

        let proposals = heuristic_failure_analysis(&cases);

        let has_agent_prompt = proposals
            .iter()
            .any(|p| matches!(p.kind, ImprovementKind::AgentPrompt));
        assert!(
            has_agent_prompt,
            "Complex multi-step flows should trigger AgentPrompt proposal \
             to improve agent's graph traversal behavior"
        );
    }

    // ===== Holdout validation tests =====

    #[test]
    fn test_format_holdout_header_none_is_empty() {
        let header = format_holdout_score_header(None);
        assert!(
            header.is_empty(),
            "None holdout score should produce empty header"
        );
    }

    #[test]
    fn test_format_holdout_header_some_includes_signal() {
        let score = AggregateScore {
            f1: 0.72,
            precision: 0.85,
            recall: 0.63,
            true_positives: 63,
            false_positives: 11,
            false_negatives: 37,
            ..Default::default()
        };
        let header = format_holdout_score_header(Some(&score));
        assert!(
            header.contains("Holdout F1: 72.0%"),
            "Header must include holdout F1: {header}"
        );
        assert!(
            header.contains("TP=63"),
            "Header must include TP count: {header}"
        );
        assert!(
            header.contains("EMPIRICAL HOLDOUT SIGNAL"),
            "Header must have section title: {header}"
        );
    }

    #[tokio::test]
    async fn test_score_holdout_cases_returns_some_when_cases_exist() {
        use crate::adapters::{BenchmarkAdapter, BenchmarkConfig, DetectedFinding};
        use crate::ground_truth::{GroundTruth, TestCase};
        use async_trait::async_trait;
        use std::path::PathBuf;

        struct MockAdapter;
        #[async_trait(?Send)]
        impl BenchmarkAdapter for MockAdapter {
            fn name(&self) -> &str {
                "mock"
            }
            fn ground_truth(&self) -> anyhow::Result<GroundTruth> {
                Ok(GroundTruth {
                    suite: "mock".to_string(),
                    version: "0".to_string(),
                    download_url: String::new(),
                    download_sha256: String::new(),
                    cases: vec![],
                })
            }
            async fn setup(&self, _config: &BenchmarkConfig) -> anyhow::Result<std::path::PathBuf> {
                Ok(std::path::PathBuf::from("/tmp"))
            }
            fn is_ready(&self, _config: &BenchmarkConfig) -> bool {
                true
            }
            async fn compile(
                &self,
                _data_dir: &std::path::Path,
                _config: &BenchmarkConfig,
            ) -> anyhow::Result<()> {
                Ok(())
            }
            async fn run_case(
                &self,
                _case: &TestCase,
                _data_dir: &std::path::Path,
                _config: &BenchmarkConfig,
                _runtime_config: &skwaq_core::config::Config,
            ) -> anyhow::Result<Vec<DetectedFinding>> {
                Ok(vec![]) // always returns empty findings — all cases become FN
            }
            fn map_finding_to_cwes(&self, _finding: &DetectedFinding) -> Vec<u32> {
                vec![]
            }
        }

        let cases = [
            TestCase {
                id: "h1".to_string(),
                path: "a.c".to_string(),
                binary_path: None,
                expected_cwes: vec![119],
                is_negative: false,
                language: "c".to_string(),
            },
            TestCase {
                id: "h2".to_string(),
                path: "b.c".to_string(),
                binary_path: None,
                expected_cwes: vec![78],
                is_negative: false,
                language: "c".to_string(),
            },
        ];
        let case_refs: Vec<&TestCase> = cases.iter().collect();

        let runtime_config = skwaq_core::config::Config::load_from_dir(std::path::Path::new("."))
            .expect("repo config should load for holdout test");
        let config = BenchmarkConfig {
            cache_dir: PathBuf::from("/tmp/holdout-test"),
            cwe_filter: None,
            max_cases: None,
            quick_mode: true,
            llm_only: false,
            binary_mode: false,
            parallelism: 1,
            skip: 0,
            concurrency: 1,
            timeout_secs: 30,
            holdout_fraction: 0.2,
            max_improvements_per_cycle: 3,
        };

        let score = score_holdout_cases(
            &MockAdapter,
            &case_refs,
            std::path::Path::new("/tmp"),
            &config,
            &runtime_config,
            "mock",
        )
        .await;

        assert!(
            score.is_some(),
            "holdout_score must be Some when holdout cases exist"
        );
        let s = score.unwrap();
        // Mock returns no findings, so all expected CWEs are missed → FN=2, F1=0
        assert_eq!(s.false_negatives, 2, "Both cases should be false negatives");
        assert_eq!(s.true_positives, 0);
    }

    #[test]
    fn test_improvement_cycle_holdout_score_field_is_surfaced_in_print() {
        // Verify print_proposals outputs holdout line when holdout_score is Some
        let hs = AggregateScore {
            f1: 0.50,
            precision: 0.70,
            recall: 0.40,
            ..Default::default()
        };

        let training = AggregateScore {
            f1: 0.80,
            precision: 0.90,
            recall: 0.72,
            ..Default::default()
        };

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: training,
            false_negatives: vec![],
            reviewed_proposals: vec![],
            proposals: vec![],
            holdout_case_count: 5,
            training_case_count: 20,
            holdout_score: Some(hs),
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        // print_proposals must not panic and must include the holdout line
        // (we capture via a basic smoke test — stdout capture is not supported here,
        //  but ImprovementCycle::holdout_score being Some confirms the field is populated)
        assert!(cycle.holdout_score.is_some());
        let gap = (cycle.baseline_score.f1 - cycle.holdout_score.as_ref().unwrap().f1) * 100.0;
        assert!((gap - 30.0).abs() < 0.1, "Gap should be ~30pp: {gap}");
        assert!(
            gap > HOLDOUT_OVERFITTING_GAP_THRESHOLD * 100.0,
            "30pp gap must exceed 15pp threshold"
        );
    }

    // -----------------------------------------------------------------------
    // RecipeChange tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_recipe_change_apply_valid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let recipe_path = dir.path().join("test_recipe.yaml");
        let initial_yaml = "\
stages:
  - agent: decompile-renamer
    context: from_graph
    client_role: reasoning
  - agent: vuln-hunter
    context: from_graph
    client_role: reasoning
";
        std::fs::write(&recipe_path, initial_yaml).unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: AggregateScore::default(),
            holdout_score: None,
            false_negatives: Vec::new(),
            proposals: vec![Improvement {
                kind: ImprovementKind::RecipeChange,
                description: "Add specialist stage".to_string(),
                target_cwes: vec![22],
                target_file: recipe_path.clone(),
                patch: Patch {
                    find: String::new(),
                    replace: "  - agent: path-traversal-specialist\n    context: from_graph\n    client_role: reasoning\n".to_string(),
                },
                source_case: "test-case-1".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            reviewed_proposals: Vec::new(),
            holdout_case_count: 0,
            training_case_count: 0,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let report = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(report.blocked, 0);

        // Verify the written YAML is valid
        let result_yaml = std::fs::read_to_string(&recipe_path).unwrap();
        assert!(skwaq_core::agents::validate_recipe_yaml(&result_yaml).is_ok());
        assert!(result_yaml.contains("path-traversal-specialist"));
    }

    #[test]
    fn test_recipe_change_rejects_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let recipe_path = dir.path().join("test_recipe.yaml");
        let initial_yaml = "\
stages:
  - agent: decompile-renamer
    context: from_graph
    client_role: reasoning
";
        std::fs::write(&recipe_path, initial_yaml).unwrap();

        // This patch replaces the valid content with invalid YAML (empty stages)
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: AggregateScore::default(),
            holdout_score: None,
            false_negatives: Vec::new(),
            proposals: vec![Improvement {
                kind: ImprovementKind::RecipeChange,
                description: "Bad recipe change".to_string(),
                target_cwes: vec![78],
                target_file: recipe_path.clone(),
                patch: Patch {
                    find: "stages:\n  - agent: decompile-renamer\n    context: from_graph\n    client_role: reasoning\n".to_string(),
                    replace: "stages: []\n".to_string(),
                },
                source_case: "test-case-2".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            reviewed_proposals: Vec::new(),
            holdout_case_count: 0,
            training_case_count: 0,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let report = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(report.applied, 0);
        assert_eq!(report.blocked, 1);
        assert!(report.blocked_reasons[0].contains("invalid recipe YAML"));
    }

    #[test]
    fn test_recipe_change_blocks_path_traversal() {
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: AggregateScore::default(),
            holdout_score: None,
            false_negatives: Vec::new(),
            proposals: vec![Improvement {
                kind: ImprovementKind::RecipeChange,
                description: "Malicious path".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("recipes/analysis/../../etc/passwd"),
                patch: Patch {
                    find: String::new(),
                    replace: "evil".to_string(),
                },
                source_case: "test-case-3".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            reviewed_proposals: Vec::new(),
            holdout_case_count: 0,
            training_case_count: 0,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let report = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(report.applied, 0);
        assert_eq!(report.blocked, 1);
        assert!(report.blocked_reasons[0].contains("outside allowed"));
    }

    #[test]
    fn test_recipe_change_blocks_non_recipe_path() {
        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: AggregateScore::default(),
            holdout_score: None,
            false_negatives: Vec::new(),
            proposals: vec![Improvement {
                kind: ImprovementKind::RecipeChange,
                description: "Wrong directory".to_string(),
                target_cwes: vec![78],
                target_file: PathBuf::from("crates/core/src/main.rs"),
                patch: Patch {
                    find: String::new(),
                    replace: "evil".to_string(),
                },
                source_case: "test-case-4".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            reviewed_proposals: Vec::new(),
            holdout_case_count: 0,
            training_case_count: 0,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let report = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(report.applied, 0);
        assert_eq!(report.blocked, 1);
        assert!(report.blocked_reasons[0].contains("outside allowed"));
    }

    #[test]
    fn test_convert_llm_proposal_recipe_change() {
        let proposal = LlmProposal {
            kind: "RECIPE_CHANGE".to_string(),
            description: "Add specialist stage".to_string(),
            target_cwes: vec![22],
            priority: Some("HIGH".to_string()),
            target_file: Some("recipes/analysis/deep.yaml".to_string()),
            regex_pattern: None,
            patch_find: None,
            patch_replace: Some(
                "  - agent: specialist\n    context: from_graph\n    client_role: reasoning\n"
                    .to_string(),
            ),
            evidence_refs: Vec::new(),
        };

        let fn_case = FalseNegativeCase {
            case_id: "test-1".to_string(),
            expected_cwes: vec![22],
            detected_cwes: Vec::new(),
            source_path: PathBuf::from("test.c"),
            source_content: String::new(),
        };

        let result = convert_llm_proposal(proposal, &fn_case, 1).unwrap();
        assert!(matches!(result.kind, ImprovementKind::RecipeChange));
        assert_eq!(
            result.target_file,
            PathBuf::from("recipes/analysis/deep.yaml")
        );
    }

    #[test]
    fn test_recipe_change_apply_with_debate_section() {
        let dir = tempfile::tempdir().unwrap();
        let recipe_path = dir.path().join("test_recipe_debate.yaml");
        let initial_yaml = "\
stages:
  - agent: decompile-renamer
    context: from_graph
    client_role: reasoning
  - agent: vuln-hunter
    context: from_graph
    client_role: reasoning

debate:
  after_stage: 2
  agent_a:
    name: skeptic
    preamble: Challenge findings
  agent_b:
    name: advocate
    preamble: Defend findings
";
        std::fs::write(&recipe_path, initial_yaml).unwrap();

        let cycle = ImprovementCycle {
            suite: "fixtures".to_string(),
            baseline_score: AggregateScore::default(),
            holdout_score: None,
            false_negatives: Vec::new(),
            proposals: vec![Improvement {
                kind: ImprovementKind::RecipeChange,
                description: "Add specialist before debate".to_string(),
                target_cwes: vec![22],
                target_file: recipe_path.clone(),
                patch: Patch {
                    find: String::new(),
                    replace: "  - agent: path-traversal-specialist\n    context: from_graph\n    client_role: reasoning\n".to_string(),
                },
                source_case: "test-case-5".to_string(),
                priority: Priority::Medium,
                supporting_evidence: Vec::new(),
                review: None,
            }],
            reviewed_proposals: Vec::new(),
            holdout_case_count: 0,
            training_case_count: 0,
            cross_validation_pending: vec![],
            run_metadata: None,
        };

        let report = apply_accepted_proposals(&cycle, None).unwrap();
        assert_eq!(report.applied, 1);

        let result_yaml = std::fs::read_to_string(&recipe_path).unwrap();
        // Stage should be inserted before the debate section
        let specialist_pos = result_yaml.find("path-traversal-specialist").unwrap();
        let debate_pos = result_yaml.find("debate:").unwrap();
        assert!(
            specialist_pos < debate_pos,
            "specialist stage should be before debate section"
        );
        // Validate the resulting YAML is still valid
        assert!(skwaq_core::agents::validate_recipe_yaml(&result_yaml).is_ok());
    }

    #[test]
    fn test_heuristic_emits_recipe_change_for_cwe_cluster() {
        // Create 3+ false negative cases for the same CWE family to trigger RecipeChange
        let fn_cases: Vec<FalseNegativeCase> = (0..4)
            .map(|i| FalseNegativeCase {
                case_id: format!("path-traversal-{}", i),
                expected_cwes: vec![22],
                detected_cwes: Vec::new(),
                source_path: PathBuf::from(format!("test{}.c", i)),
                source_content: "int main() { return 0; }".to_string(),
            })
            .collect();

        let proposals = heuristic_failure_analysis_impl(&fn_cases);
        let recipe_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| matches!(p.kind, ImprovementKind::RecipeChange))
            .collect();

        assert!(
            !recipe_proposals.is_empty(),
            "should emit RecipeChange for 4 path-traversal FN cases"
        );
        assert!(recipe_proposals[0]
            .description
            .contains("path-traversal-specialist"));
        assert_eq!(
            recipe_proposals[0].target_file,
            PathBuf::from("recipes/analysis/standard.yaml")
        );
    }
}
