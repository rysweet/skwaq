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
const IMPROVE_KB_HITS_PER_QUERY: usize = 2;
const IMPROVE_KB_SNIPPET_CHAR_LIMIT: usize = 700;
const IMPROVE_KB_FIXED_QUERIES: [&str; 2] = ["methodology", "cwe-families"];
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
    /// Suites that SHOULD be cross-validated but were not (logged for visibility).
    pub cross_validation_pending: Vec<String>,
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
) -> anyhow::Result<ImprovementCycle> {
    let suite_name = adapter.name().to_string();
    tracing::info!("Starting self-improvement cycle for {}", suite_name);

    // Step 1: Run benchmark and collect outcomes
    let gt = adapter.ground_truth()?;
    let all_cases: Vec<_> = gt
        .cases
        .iter()
        .filter(|c| {
            config.cwe_filter.as_ref().is_none_or(|f| {
                c.expected_cwes.iter().any(|cwe| f.contains(cwe)) || c.expected_cwes.is_empty()
            })
        })
        .take(config.max_cases.unwrap_or(usize::MAX))
        .collect();

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
        match adapter.run_case(case, data_dir, config).await {
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
        let source_content = std::fs::read_to_string(&source_path).unwrap_or_default();

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

    // Step 3: Analyze false negatives and generate proposals
    let reviewed_proposals = analyze_false_negatives(&false_negatives, &suite_name).await?;
    let mut proposals: Vec<_> = reviewed_proposals
        .iter()
        .filter(|proposal| {
            !matches!(
                proposal.review.as_ref().map(|review| review.verdict),
                Some(ReviewVerdict::Reject)
            )
        })
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
        cross_validation_pending,
    })
}

/// Analyze false negatives using the failure-analyst agent plus explicit heuristics.
async fn analyze_false_negatives(
    false_negatives: &[FalseNegativeCase],
    suite: &str,
) -> anyhow::Result<Vec<Improvement>> {
    if false_negatives.is_empty() {
        return Ok(Vec::new());
    }

    let knowledge_db = prepare_improvement_knowledge_db()?;
    let mut proposals = Vec::new();

    let llm_proposals = run_failure_analyst_agent(false_negatives, suite, &knowledge_db).await?;
    tracing::info!(
        "Failure analyst produced {} proposal(s) for {}",
        llm_proposals.len(),
        suite
    );
    proposals.extend(llm_proposals);

    // Heuristics are an explicit second signal, not a hidden fallback path.
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
    proposals = run_overfitting_review(proposals, suite, &knowledge_db).await?;

    Ok(proposals)
}

/// Run the failure-analyst LLM agent on false negative cases.
async fn run_failure_analyst_agent(
    false_negatives: &[FalseNegativeCase],
    suite: &str,
    knowledge_db: &skwaq_core::graph::GraphDb,
) -> anyhow::Result<Vec<Improvement>> {
    let config = skwaq_core::config::Config::load()?;
    let llm_client = skwaq_core::llm::create_client(&config.llm).await?;
    let memory = skwaq_core::memory::MemoryStore::open_default()?;

    let agent = skwaq_core::agents::definition::load_agent("failure-analyst")?;
    let runner = skwaq_core::agents::runner::AgentRunner::new(llm_client);

    let mut proposals = Vec::new();
    let case_limit =
        failure_analyst_case_limit(config.analysis.default_token_budget, false_negatives.len());
    let budget_per_case =
        failure_analyst_budget_per_case(config.analysis.default_token_budget, case_limit);

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
             Proposed fix: {{NEW_PATTERN|DEEPER_ANALYSIS|NEW_AGENT_CAPABILITY|GROUND_TRUTH_ERROR|CWE_MAPPING|TAINT_RULE}}\n\
             Details: {{specific actionable proposal}}\n\
             Priority: {{HIGH|MEDIUM|LOW}}\n\
             Evidence:\n\
             - KNOWLEDGE | source=... | topic=... | title=... | rationale=...\n\
             - MEMORY | type=... | context=... | tags=tag1,tag2 | rationale=...\n\
             Every proposal must include at least one Evidence entry. Do not emit prose \
             before ## Case:.",
            suite,
            fn_case.case_id,
            fn_case.expected_cwes,
            fn_case.detected_cwes,
            gap_context,
            fn_case.source_path.display(),
            &fn_case.source_content[..source_excerpt_len],
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

        let result = runner
            .run_agent_with_db_and_memory(&agent, &inv_id, &context, &db, &memory, &mut budget)
            .await
            .map_err(|e| {
                anyhow::anyhow!("failure analyst failed on case {}: {e}", fn_case.case_id)
            })?;

        let mut formatter_budget = skwaq_core::llm::TokenBudget::new(budget_per_case.min(50_000));
        let formatted_output = format_failure_analyst_output(
            &config,
            agent.model.as_str(),
            fn_case,
            &result.output,
            &mut formatter_budget,
        )
        .await?;

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
    let system_prompt = "You convert analyst reports into strict JSON. Do not add commentary.";
    let formatter_prompt = format!(
        "Convert the analyst report below into a single ```json fenced block using this schema:\n\
         {{\"proposals\":[{{\"kind\":\"NEW_PATTERN|DEEPER_ANALYSIS|NEW_AGENT_CAPABILITY|GROUND_TRUTH_ERROR|CWE_MAPPING|TAINT_RULE\",\
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

    raw_proposals
        .into_iter()
        .enumerate()
        .map(|(index, proposal)| convert_llm_proposal(proposal, fn_case, index + 1))
        .collect()
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
        "GROUND_TRUTH_ERROR" | "GROUNDTRUTHERROR" | "GROUND_TRUTH" | "GROUNDTRUTH" => {
            ImprovementKind::GroundTruthFix
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
) -> anyhow::Result<Vec<EvidenceRef>> {
    if raw_refs.is_empty() {
        // Warn but don't fail — early improve cycles may have empty memory,
        // making it hard for agents to cite evidence. The overfitting reviewer
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
) -> anyhow::Result<Vec<Improvement>> {
    if proposals.is_empty() {
        return Ok(proposals);
    }

    // Batch proposals to avoid LLM output truncation.
    // The reviewer generates verbose structured JSON per proposal;
    // more than ~5 proposals per call risks exceeding output limits.
    const BATCH_SIZE: usize = 5;

    if proposals.len() <= BATCH_SIZE {
        return run_overfitting_review_batch(proposals, suite, knowledge_db).await;
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
        let reviewed = run_overfitting_review_batch(batch, suite, knowledge_db).await?;
        all_reviewed.extend(reviewed);
    }

    Ok(all_reviewed)
}

async fn run_overfitting_review_batch(
    proposals: Vec<Improvement>,
    suite: &str,
    knowledge_db: &skwaq_core::graph::GraphDb,
) -> anyhow::Result<Vec<Improvement>> {
    if proposals.is_empty() {
        return Ok(proposals);
    }

    let config = skwaq_core::config::Config::load().map_err(|e| {
        anyhow::anyhow!("overfitting review requires config loading to succeed: {e}")
    })?;

    let llm_client = skwaq_core::llm::create_client(&config.llm)
        .await
        .map_err(|e| anyhow::anyhow!("overfitting review requires an LLM client: {e}"))?;

    // Use full budget — the reviewer needs enough tokens to evaluate all proposals
    // with detailed structured JSON output.
    let budget_amount = config.analysis.default_token_budget;
    let knowledge_context = build_overfitting_knowledge_context(knowledge_db, &proposals)?;

    let mut proposal_text = format!(
        "Use the knowledge-base guidance below as grounding when judging \
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
         - Do not emit prose outside the JSON block.\n\n\
         Review these proposals:\n\n",
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
    let output = skwaq_core::llm::execute_with_tools(
        &llm_client,
        &config.llm.copilot.model,
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
    .map_err(|e| anyhow::anyhow!("overfitting reviewer failed: {e}"))?;

    let decisions = parse_review_decisions(&output, &proposals).map_err(|e| {
        anyhow::anyhow!("overfitting reviewer returned invalid review payload: {e}")
    })?;
    let total_count = proposals.len();
    let mut reviewed = Vec::new();
    let mut accepted_count = 0usize;

    for (proposal, review) in proposals.into_iter().zip(decisions.into_iter()) {
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
    skwaq_core::knowledge::search::initialize_cwe_catalog(&db)?;
    Ok(db)
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
/// Identifies common patterns we're missing based on source code content.
fn heuristic_failure_analysis(false_negatives: &[FalseNegativeCase]) -> Vec<Improvement> {
    let mut proposals = Vec::new();

    // Known dangerous APIs that we might not have patterns for
    let missing_patterns: Vec<(&str, &str, &[u32])> = vec![
        (r"\bexecl\s*\(", "injection", &[78]),
        (r"\bexecv\s*\(", "injection", &[78]),
        (r"\bexecvp\s*\(", "injection", &[78]),
        (r"\bexecle\s*\(", "injection", &[78]),
        (r"\bsystem\s*\(", "injection", &[78]),
        (r"\bpopen\s*\(", "injection", &[78]),
        (r"\bmemcpy\s*\(", "memory", &[119, 120]),
        (r"\bmemmove\s*\(", "memory", &[119, 120]),
        (r"\bwcscpy\s*\(", "memory", &[120]),
        (r"\bwcscat\s*\(", "memory", &[120]),
        (r"\bsprintf\s*\(", "memory", &[119, 120, 121, 122]),
        (r"\bscanf\s*\(", "memory", &[119, 120, 121, 122]),
        (r"\bfscanf\s*\(", "memory", &[119, 120, 121, 122]),
        (r"\bsscanf\s*\(", "memory", &[119, 120, 121, 122]),
        (r"\brecv\s*\(", "memory", &[119]),
        (r"\bread\s*\(", "memory", &[119]),
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
            // Check if this pattern appears in the missed case
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
                // Check if this CWE was among the missed ones
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
                !matches!(
                    proposal.review.as_ref().map(|review| review.verdict),
                    Some(ReviewVerdict::Reject)
                )
            })
            .count();
        let rejected_count = reviewed_proposals.len().saturating_sub(accepted_count);
        content.push_str(&format!(
            "### Reviewed Improvement Proposals ({} total; {} accepted, {} rejected)\n\n",
            reviewed_proposals.len(),
            accepted_count,
            rejected_count
        ));
        for proposal in reviewed_proposals.iter().take(10) {
            let kind = match &proposal.kind {
                ImprovementKind::NewPattern => "Pattern Gap",
                ImprovementKind::AgentPrompt => "Agent Capability Gap",
                ImprovementKind::CweMapping => "CWE Mapping Gap",
                ImprovementKind::TaintRule => "Taint Rule Gap",
                ImprovementKind::GroundTruthFix => "Ground Truth Issue",
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

/// Apply accepted NewPattern proposals by appending regex patterns to the
/// source pattern file. Only applies NewPattern proposals with non-empty
/// patches and a target file that exists.
///
/// Returns the number of proposals successfully applied.
pub fn apply_accepted_proposals(cycle: &ImprovementCycle) -> anyhow::Result<usize> {
    let applicable: Vec<&Improvement> = cycle
        .proposals
        .iter()
        .filter(|p| matches!(p.kind, ImprovementKind::NewPattern))
        .filter(|p| !p.patch.replace.is_empty())
        .collect();

    if applicable.is_empty() {
        tracing::info!("No applicable NewPattern proposals to apply");
        return Ok(0);
    }

    let mut applied = 0;
    for proposal in &applicable {
        let target = &proposal.target_file;
        if !target.exists() {
            tracing::warn!("Proposal target file does not exist: {}", target.display());
            continue;
        }

        let content = std::fs::read_to_string(target)?;

        let new_content = if proposal.patch.find.is_empty() {
            // Append mode: generate a proper SourcePattern struct and insert
            // before the closing `]` of the c_cpp_patterns() array.
            //
            // Safety gate: validate the proposed regex compiles within size_limit
            // before writing it into source code. This prevents both invalid regex
            // syntax and ReDoS patterns from reaching the codebase.
            let regex_str = &proposal.patch.replace;
            // Reject patterns containing double quotes — they would break
            // the r"..." raw string literal in generated Rust source.
            if regex_str.contains('"') {
                tracing::warn!(
                    "Rejecting proposal '{}': regex contains double quote",
                    proposal.description.chars().take(60).collect::<String>(),
                );
                continue;
            }

            match RegexBuilder::new(regex_str)
                .size_limit(PROPOSAL_REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(_) => {} // valid, proceed
                Err(e) => {
                    tracing::warn!(
                        "Rejecting proposal '{}': regex fails safety validation: {}",
                        proposal.description.chars().take(60).collect::<String>(),
                        e
                    );
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
                tracing::warn!("Could not find insertion point in {}", target.display());
                continue;
            }
        } else {
            // Replace mode
            if !content.contains(&proposal.patch.find) {
                tracing::warn!(
                    "Patch find text not found in {}: '{}'",
                    target.display(),
                    proposal.patch.find.chars().take(50).collect::<String>()
                );
                continue;
            }
            content.replacen(&proposal.patch.find, &proposal.patch.replace, 1)
        };

        std::fs::write(target, &new_content)?;
        applied += 1;
        tracing::info!(
            "Applied proposal: {} → {}",
            proposal.description.chars().take(60).collect::<String>(),
            target.display()
        );
    }

    if applied > 0 {
        tracing::info!(
            "Applied {}/{} NewPattern proposals. Run `cargo test` to validate.",
            applied,
            applicable.len()
        );
    }

    Ok(applied)
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
            cross_validation_pending: vec![],
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
                "cwe-120".to_string(),
                "cwe-121".to_string(),
                "cwe-122".to_string(),
            ]
        );
    }

    #[test]
    fn test_overfitting_knowledge_context_deduplicates_repeated_cwes() {
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

        assert_eq!(context.matches("### Query: cwe-119").count(), 1);
        assert_eq!(context.matches("### Query: cwe-120").count(), 1);
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

    // -----------------------------------------------------------------------
    // TDD: Structured SourcePattern insertion safety
    // -----------------------------------------------------------------------

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
            cross_validation_pending: vec![],
        };

        let applied = apply_accepted_proposals(&cycle).unwrap();
        assert_eq!(applied, 1);

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
            cross_validation_pending: vec![],
        };

        apply_accepted_proposals(&cycle).unwrap();
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
            cross_validation_pending: vec![],
        };

        apply_accepted_proposals(&cycle).unwrap();
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
            cross_validation_pending: vec![],
        };

        let applied = apply_accepted_proposals(&cycle).unwrap();
        assert_eq!(
            applied, 0,
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
            cross_validation_pending: vec![],
        };

        let applied = apply_accepted_proposals(&cycle).unwrap();
        assert_eq!(applied, 0, "Invalid regex proposals should be rejected");
    }
}
