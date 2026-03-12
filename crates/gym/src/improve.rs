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
             The vulnerability was NOT detected. Explain why and propose a fix.",
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

        match runner
            .run_agent_with_db(&agent, &inv_id, &context, &db, &mut budget)
            .await
        {
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
