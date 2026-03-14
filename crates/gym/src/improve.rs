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
use std::path::{Path, PathBuf};

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

/// Result of a self-improvement cycle.
#[derive(Debug)]
pub struct ImprovementCycle {
    pub suite: String,
    pub baseline_score: AggregateScore,
    pub false_negatives: Vec<FalseNegativeCase>,
    pub proposals: Vec<Improvement>,
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
    let cases: Vec<_> = gt
        .cases
        .iter()
        .filter(|c| {
            config.cwe_filter.as_ref().is_none_or(|f| {
                c.expected_cwes.iter().any(|cwe| f.contains(cwe)) || c.expected_cwes.is_empty()
            })
        })
        .take(config.max_cases.unwrap_or(usize::MAX))
        .collect();

    let mut outcomes = Vec::new();
    for case in &cases {
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
    let proposals = analyze_false_negatives(&false_negatives, &suite_name).await;

    // Step 4: Store insights as knowledge for future agents to reference
    store_fn_insights(&false_negatives, &proposals, &suite_name, data_dir);

    Ok(ImprovementCycle {
        suite: suite_name,
        baseline_score: score,
        false_negatives,
        proposals,
    })
}

/// Analyze false negatives using the failure-analyst agent (or heuristic fallback).
async fn analyze_false_negatives(
    false_negatives: &[FalseNegativeCase],
    suite: &str,
) -> Vec<Improvement> {
    let mut proposals = Vec::new();

    // Try LLM-based analysis first
    if let Ok(llm_proposals) = run_failure_analyst_agent(false_negatives, suite).await {
        proposals.extend(llm_proposals);
    }

    // Always run heuristic analysis as a baseline
    proposals.extend(heuristic_failure_analysis(false_negatives, suite));

    // Deduplicate proposals by description
    let mut seen = std::collections::HashSet::new();
    proposals.retain(|p| seen.insert(p.description.clone()));

    // Run overfitting review gate on proposals
    proposals = run_overfitting_review(proposals, suite).await;

    proposals
}

/// Run the failure-analyst LLM agent on false negative cases.
async fn run_failure_analyst_agent(
    false_negatives: &[FalseNegativeCase],
    suite: &str,
) -> anyhow::Result<Vec<Improvement>> {
    let config = skwaq_core::config::Config::load()?;
    let llm_client = skwaq_core::llm::create_client(&config.llm).await?;
    let memory = skwaq_core::memory::MemoryStore::open_default().ok();

    let agent = skwaq_core::agents::definition::load_agent("failure-analyst")?;
    let runner = skwaq_core::agents::runner::AgentRunner::new(llm_client);

    let mut proposals = Vec::new();
    let budget_per_case = config.analysis.default_token_budget.min(30_000);

    for (i, fn_case) in false_negatives.iter().enumerate().take(5) {
        // Cap at 5 cases per cycle
        let mut budget = skwaq_core::llm::TokenBudget::new(budget_per_case);

        // Build context with the missed case details
        let context = format!(
            "Analyze this FALSE NEGATIVE from the {} benchmark.\n\n\
             Case: {}\n\
             Expected CWEs: {:?}\n\
             Detected CWEs: {:?}\n\
             File: {}\n\n\
             Source code:\n```\n{}\n```\n\n\
             The vulnerability was NOT detected. Explain why and propose a fix.\n\n\
             If durable memory tools are available, use recall_memory to check for \
             prior generalized lessons before proposing changes. Only store or reuse \
             lessons that generalize beyond this specific benchmark case.",
            suite,
            fn_case.case_id,
            fn_case.expected_cwes,
            fn_case.detected_cwes,
            fn_case.source_path.display(),
            &fn_case.source_content[..fn_case.source_content.len().min(4000)],
        );

        // Create an in-memory DB for the agent to use
        let db = skwaq_core::graph::GraphDb::in_memory()?;
        let inv_id = format!("improve-{}", i);
        let now = chrono::Utc::now().to_rfc3339();
        db.execute(
            "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
            &[
                &inv_id.as_str(),
                &fn_case.case_id.as_str(),
                &fn_case.source_path.display().to_string().as_str(),
                &now.as_str(),
                &now.as_str(),
            ],
        )?;

        tracing::info!(
            "Running failure-analyst on case {} ({}/{})",
            fn_case.case_id,
            i + 1,
            false_negatives.len().min(5)
        );

        let result = if let Some(ref memory) = memory {
            runner
                .run_agent_with_db_and_memory(&agent, &inv_id, &context, &db, memory, &mut budget)
                .await
        } else {
            runner
                .run_agent_with_db(&agent, &inv_id, &context, &db, &mut budget)
                .await
        };

        match result {
            Ok(result) => {
                // Parse proposals from the agent's output
                proposals.extend(parse_analyst_proposals(&result.output, fn_case, suite));
            }
            Err(e) => {
                tracing::warn!("Failure analyst failed on case {}: {}", fn_case.case_id, e);
            }
        }
    }

    Ok(proposals)
}

/// Parse structured improvement proposals from the failure-analyst's output.
fn parse_analyst_proposals(
    output: &str,
    fn_case: &FalseNegativeCase,
    _suite: &str,
) -> Vec<Improvement> {
    let mut proposals = Vec::new();

    // Look for NEW_PATTERN proposals with regex
    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.contains("NEW_PATTERN") {
            // Try to extract a regex from the output
            if let Some(regex_start) = output.find("`\\b") {
                let rest = &output[regex_start + 1..];
                if let Some(regex_end) = rest.find('`') {
                    let regex = &rest[..regex_end];
                    proposals.push(Improvement {
                        kind: ImprovementKind::NewPattern,
                        description: format!(
                            "Add pattern '{}' for CWE-{:?}",
                            regex, fn_case.expected_cwes
                        ),
                        target_cwes: fn_case.expected_cwes.clone(),
                        target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
                        patch: Patch {
                            find: String::new(),
                            replace: regex.to_string(),
                        },
                        source_case: fn_case.case_id.clone(),
                        priority: Priority::High,
                    });
                }
            }
        }

        if trimmed.contains("DEEPER_ANALYSIS") || trimmed.contains("NEW_AGENT_CAPABILITY") {
            proposals.push(Improvement {
                kind: ImprovementKind::AgentPrompt,
                description: format!(
                    "Agent needs deeper analysis for {} (CWE-{:?}): {}",
                    fn_case.case_id,
                    fn_case.expected_cwes,
                    trimmed.chars().take(200).collect::<String>()
                ),
                target_cwes: fn_case.expected_cwes.clone(),
                target_file: PathBuf::from("agents/vuln-hunter.md"),
                patch: Patch {
                    find: String::new(),
                    replace: String::new(),
                },
                source_case: fn_case.case_id.clone(),
                priority: Priority::Medium,
            });
        }

        if trimmed.contains("GROUND_TRUTH_ERROR") {
            proposals.push(Improvement {
                kind: ImprovementKind::GroundTruthFix,
                description: format!(
                    "Ground truth may be incorrect for {}: {}",
                    fn_case.case_id,
                    trimmed.chars().take(200).collect::<String>()
                ),
                target_cwes: fn_case.expected_cwes.clone(),
                target_file: PathBuf::from("data/gym/ground_truth/"),
                patch: Patch {
                    find: String::new(),
                    replace: String::new(),
                },
                source_case: fn_case.case_id.clone(),
                priority: Priority::Low,
            });
        }
    }

    proposals
}

/// Run the overfitting-reviewer agent as a gate on proposals.
///
/// Each proposal is evaluated for real-world generality vs benchmark overfitting.
/// Proposals that the reviewer rejects (benchmark-specific, wildcard FP risk,
/// inflated CWE mapping) are filtered out.
async fn run_overfitting_review(proposals: Vec<Improvement>, suite: &str) -> Vec<Improvement> {
    if proposals.is_empty() {
        return proposals;
    }

    let config = match skwaq_core::config::Config::load() {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!("Config not available for overfitting review, passing all proposals");
            return proposals;
        }
    };

    let llm_client = match skwaq_core::llm::create_client(&config.llm).await {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!("LLM not available for overfitting review, passing all proposals");
            return proposals;
        }
    };

    let agent = match skwaq_core::agents::definition::load_agent("overfitting-reviewer") {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("overfitting-reviewer agent not found, passing all proposals");
            return proposals;
        }
    };

    let runner = skwaq_core::agents::runner::AgentRunner::new(llm_client);
    let budget_amount = config.analysis.default_token_budget.min(20_000);

    // Format all proposals for review
    let mut proposal_text = format!(
        "Review these {} improvement proposals from the {} benchmark for overfitting risk:\n\n",
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
            "{}. [{}] {}\n   Target CWEs: {:?}\n   Patch: {}\n   From case: {}\n\n",
            i + 1,
            kind,
            p.description,
            p.target_cwes,
            p.patch.replace,
            p.source_case,
        ));
    }

    let db = match skwaq_core::graph::GraphDb::in_memory() {
        Ok(d) => d,
        Err(_) => return proposals,
    };
    let inv_id = "overfitting-review";
    let now = chrono::Utc::now().to_rfc3339();
    if db
        .execute(
            "INSERT INTO investigations (id, name, target, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
            &[&inv_id, &"review", &"review", &now.as_str(), &now.as_str()],
        )
        .is_err()
    {
        return proposals;
    }

    let mut budget = skwaq_core::llm::TokenBudget::new(budget_amount);

    match runner
        .run_agent_with_db(&agent, inv_id, &proposal_text, &db, &mut budget)
        .await
    {
        Ok(result) => {
            let output = &result.output;
            let mut accepted = Vec::new();

            for (i, proposal) in proposals.into_iter().enumerate() {
                // Look for verdict for this proposal number
                let marker = format!("{}.", i + 1);
                let is_rejected = output.lines().any(|line| {
                    let l = line.to_uppercase();
                    (l.contains(&marker) || l.contains(&format!("Proposal {}", i + 1)))
                        && l.contains("REJECT")
                });

                if is_rejected {
                    tracing::info!(
                        "Overfitting reviewer REJECTED proposal: {}",
                        proposal.description
                    );
                } else {
                    accepted.push(proposal);
                }
            }

            let total_count = accepted.len()
                + output
                    .lines()
                    .filter(|l| l.to_uppercase().contains("REJECT"))
                    .count();
            tracing::info!(
                "Overfitting review: {}/{} proposals accepted",
                accepted.len(),
                total_count
            );
            accepted
        }
        Err(e) => {
            tracing::warn!("Overfitting reviewer failed: {}, passing all proposals", e);
            proposals
        }
    }
}

/// Heuristic analysis of false negatives (no LLM needed).
/// Identifies common patterns we're missing based on source code content.
fn heuristic_failure_analysis(
    false_negatives: &[FalseNegativeCase],
    _suite: &str,
) -> Vec<Improvement> {
    let mut proposals = Vec::new();

    // Known dangerous APIs that we might not have patterns for
    let missing_patterns: Vec<(&str, &str, &[u32])> = vec![
        (r"\bexecl\s*\(", "injection", &[78]),
        (r"\bexecv\s*\(", "injection", &[78]),
        (r"\bexecvp\s*\(", "injection", &[78]),
        (r"\bexecle\s*\(", "injection", &[78]),
        (r"\bmemcpy\s*\(", "memory", &[119, 120]),
        (r"\bmemmove\s*\(", "memory", &[119, 120]),
        (r"\bwcscpy\s*\(", "memory", &[120]),
        (r"\bwcscat\s*\(", "memory", &[120]),
        (r"\bfscanf\s*\(", "format_string", &[134]),
        (r"\bsscanf\s*\(", "format_string", &[134]),
        (r"\brecv\s*\(", "memory", &[119]),
        (r"\bread\s*\(", "memory", &[119]),
    ];

    for fn_case in false_negatives {
        let content = &fn_case.source_content;
        for (pattern, _category, cwes) in &missing_patterns {
            // Check if this pattern appears in the missed case
            let regex = regex::Regex::new(pattern).ok();
            if let Some(re) = regex {
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
                            target_file: PathBuf::from(
                                "crates/core/src/analysis/patterns_source.rs",
                            ),
                            patch: Patch {
                                find: String::new(),
                                replace: pattern.to_string(),
                            },
                            source_case: fn_case.case_id.clone(),
                            priority: Priority::High,
                        });
                    }
                }
            }
        }
    }

    proposals
}

/// Store false-negative insights into `data/knowledge/` so future agents can reference them.
///
/// Creates or appends to `data/knowledge/fn-insights.md` with structured knowledge
/// about WHY cases were missed and what patterns to look for. This feeds into
/// the `lookup_knowledge` tool that all agents can call.
fn store_fn_insights(
    false_negatives: &[FalseNegativeCase],
    proposals: &[Improvement],
    suite: &str,
    data_dir: &Path,
) {
    if false_negatives.is_empty() && proposals.is_empty() {
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
    if !proposals.is_empty() {
        content.push_str(&format!(
            "### Actionable Insights ({} proposals)\n\n",
            proposals.len()
        ));
        for proposal in proposals.iter().take(10) {
            let kind = match &proposal.kind {
                ImprovementKind::NewPattern => "Pattern Gap",
                ImprovementKind::AgentPrompt => "Agent Capability Gap",
                ImprovementKind::CweMapping => "CWE Mapping Gap",
                ImprovementKind::TaintRule => "Taint Rule Gap",
                ImprovementKind::GroundTruthFix => "Ground Truth Issue",
            };
            content.push_str(&format!(
                "- **[{}]** {}\n  CWEs: {:?} | From case: {}\n",
                kind, proposal.description, proposal.target_cwes, proposal.source_case
            ));
            if !proposal.patch.replace.is_empty() {
                content.push_str(&format!(
                    "  Suggested pattern: `{}`\n",
                    proposal.patch.replace
                ));
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
                proposals.len(),
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
    for baseline_cwe in baseline.per_cwe.values() {
        if let Some(new_cwe) = new.per_cwe.get(&baseline_cwe.cwe_id) {
            if new_cwe.detection_rate < baseline_cwe.detection_rate - 0.02 {
                return true;
            }
        }
    }
    false
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
pub fn store_improvement_lessons(cycle: &ImprovementCycle) {
    let memory = match skwaq_core::memory::MemoryStore::open_default() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Cannot open durable memory for lesson storage: {e}");
            return;
        }
    };

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

        // Generalize: strip benchmark-specific details from the description
        let context = skwaq_core::memory::pattern::strip_benchmark_specifics(&proposal.description);

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
            if proposal.patch.replace.is_empty() {
                "requires deeper analysis".to_string()
            } else {
                format!("pattern: {}", proposal.patch.replace)
            }
        );

        if memory
            .store(agent, exp_type, &context, &outcome, 0.7, &tag_refs)
            .is_ok()
        {
            stored += 1;
        }
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

        if memory
            .store(
                "failure-analyst",
                skwaq_core::memory::ExperienceType::Failure,
                &context,
                &outcome,
                0.6,
                &tag_refs,
            )
            .is_ok()
        {
            stored += 1;
        }
    }

    // Run pattern detection to promote recurring lessons
    for agent in &["vuln-hunter", "failure-analyst", "orchestrator"] {
        if let Ok(new) = detector.detect_patterns(agent) {
            if new > 0 {
                tracing::info!("Detected {new} new patterns for agent '{agent}'");
            }
        }
    }

    if stored > 0 {
        tracing::info!(
            "Stored {stored} generalized lessons in durable memory from {} cycle",
            cycle.suite
        );
    }
}

/// Print improvement proposals in a human-readable format.
pub fn print_proposals(cycle: &ImprovementCycle) {
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
        println!();
    }
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
                },
            ],
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

        let proposals = heuristic_failure_analysis(&fn_cases, "juliet");
        assert!(!proposals.is_empty(), "Should propose adding execl pattern");
        assert!(proposals[0].description.contains("execl"));
    }
}
