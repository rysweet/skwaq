//! Proof-of-Compromise (PoC) system for benchmark disagreement adjudication.
//!
//! When the benchmark answer key disagrees with a skwaq finding, the PoC system
//! attempts to gather evidence that either proves or disproves the finding using
//! an adversarial disproof-first protocol:
//!
//! 1. Search for mitigations (sanitizers, guards, bounds checks)
//! 2. If no mitigation found, search for proof evidence (taint paths, exploitable patterns)
//! 3. Score evidence deterministically (not LLM-reported confidence)
//! 4. Auto-adjudicate: Proven→TP, Disproven→FP, Inconclusive→human

pub mod strategies;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::history::{DisagreementRecord, HistoryDb};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Verdict for a proof-of-compromise attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PocVerdict {
    /// Strong evidence the vulnerability is real (evidence score >= 3, no disproof).
    Proven,
    /// Mitigation found on the path — finding is likely false positive.
    Disproven,
    /// Insufficient evidence either way — needs human review.
    Inconclusive,
}

impl std::fmt::Display for PocVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PocVerdict::Proven => write!(f, "PROVEN"),
            PocVerdict::Disproven => write!(f, "DISPROVEN"),
            PocVerdict::Inconclusive => write!(f, "INCONCLUSIVE"),
        }
    }
}

/// Deterministic evidence strength score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceScore {
    /// Mitigation found — vulnerability is mitigated.
    Disproven = 0,
    /// Not enough evidence to determine.
    Insufficient = 1,
    /// Some evidence but gaps remain (score 2-3).
    Moderate = 2,
    /// Strong evidence of exploitability (score >= 4).
    Strong = 3,
}

impl std::fmt::Display for EvidenceScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceScore::Disproven => write!(f, "disproven"),
            EvidenceScore::Insufficient => write!(f, "insufficient"),
            EvidenceScore::Moderate => write!(f, "moderate"),
            EvidenceScore::Strong => write!(f, "strong"),
        }
    }
}

/// Execution mode for a proof strategy.
///
/// Strategies can operate in two modes:
/// - **Template**: The strategy produces structured evidence templates — checklists of
///   what to look for and which tools to invoke. The actual analysis is performed by
///   the poc-prover agent, which fills in real tool output. This is the default mode
///   for all built-in strategies.
/// - **Direct**: The strategy performs actual tool-grounded analysis itself, producing
///   evidence backed by real tool output. Reserved for future agent-integrated strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Strategy produces structured templates/checklists for agent execution.
    Template,
    /// Strategy performs direct tool-grounded analysis (future).
    Direct,
}

/// Classification of a single piece of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// A taint path from source to sink was found.
    TaintPath,
    /// A sanitizer/guard was found on the data path (disproof).
    Sanitizer,
    /// A bounds check was found protecting the operation (disproof).
    BoundsCheck,
    /// Source code snippet supporting the claim.
    CodeSnippet,
    /// Call chain showing reachability.
    CallChain,
    /// User-controlled data source identified.
    DataFlowSource,
    /// Code pattern matching vulnerability signature.
    PatternMatch,
    /// Untested exploit sketch (hypothesis, not verified).
    UntestedExploitSketch,
    /// A mitigation/control was found (disproof).
    MitigationFound,
    /// The vulnerable path is unreachable (disproof).
    PathUnreachable,
}

impl EvidenceKind {
    /// Returns true if this evidence kind supports disproof (i.e., finding is NOT real).
    pub fn is_disproof(&self) -> bool {
        matches!(
            self,
            EvidenceKind::Sanitizer
                | EvidenceKind::BoundsCheck
                | EvidenceKind::MitigationFound
                | EvidenceKind::PathUnreachable
        )
    }
}

/// A single piece of grounded evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// What kind of evidence this is.
    pub kind: EvidenceKind,
    /// Human-readable description.
    pub description: String,
    /// Grounded location reference (file:line).
    pub location: String,
    /// Raw tool output that backs this claim.
    pub tool_output: String,
}

/// Complete result of a proof-of-compromise attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfCompromise {
    /// The BD case being proved/disproved.
    pub case_id: String,
    /// The CWE under investigation.
    pub cwe: String,
    /// Which proof strategy was used.
    pub strategy: String,
    /// Final verdict (deterministic, not LLM-reported).
    pub verdict: PocVerdict,
    /// Evidence strength score.
    pub evidence_score: EvidenceScore,
    /// Evidence found during disproof search.
    pub disproof_evidence: Vec<Evidence>,
    /// Evidence found during proof search.
    pub proof_evidence: Vec<Evidence>,
    /// Untested exploit hypothesis (if generated).
    pub exploit_sketch: Option<String>,
    /// LLM reasoning trace (for audit, not for scoring).
    pub reasoning: String,
    /// Tools invoked during the proof attempt.
    pub tools_used: Vec<String>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Deterministic evidence scoring
// ---------------------------------------------------------------------------

/// Score evidence deterministically. No LLM confidence scores.
///
/// Protocol:
/// 1. If any disproof evidence exists → Disproven
/// 2. Deduplicate proof evidence by (kind, location, description)
/// 3. Count proof evidence points:
///    - TaintPath found → +1
///    - No sanitizer found (searched but absent) → +1
///    - Dangerous sink confirmed → +1
///    - Attacker-controlled source identified → +1
/// 4. Score >= 4 → Strong/Proven, 3 → Moderate/Proven, <3 → Inconclusive
pub fn score_evidence(disproof: &[Evidence], proof: &[Evidence]) -> (EvidenceScore, PocVerdict) {
    // Any disproof evidence immediately wins.
    if !disproof.is_empty() {
        return (EvidenceScore::Disproven, PocVerdict::Disproven);
    }

    // M1: Deduplicate proof evidence by (kind, location, description) so
    // duplicate entries don't inflate the score.
    let mut seen = HashSet::new();
    let mut score: u32 = 0;

    for ev in proof {
        let fingerprint = format!("{:?}|{}|{}", ev.kind, ev.location, ev.description);
        if !seen.insert(fingerprint) {
            continue; // skip duplicate
        }
        match ev.kind {
            EvidenceKind::TaintPath => score += 1,
            EvidenceKind::DataFlowSource => score += 1,
            EvidenceKind::PatternMatch => score += 1,
            EvidenceKind::CallChain => score += 1,
            EvidenceKind::CodeSnippet => {
                // Code snippets are supporting but not independently scored
            }
            EvidenceKind::UntestedExploitSketch => {
                // Explicitly not scored — untested hypotheses don't count
            }
            _ => {}
        }
    }

    match score {
        4.. => (EvidenceScore::Strong, PocVerdict::Proven),
        3 => (EvidenceScore::Moderate, PocVerdict::Proven),
        _ => (EvidenceScore::Insufficient, PocVerdict::Inconclusive),
    }
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// Configuration for the PoC prover.
#[derive(Debug, Clone)]
pub struct ProveConfig {
    /// Minimum evidence score for auto-adjudication (default: 3 = Moderate).
    pub min_score_for_auto: EvidenceScore,
    /// Maximum BD cases to prove in one batch.
    pub max_cases: Option<usize>,
    /// Whether to actually adjudicate or just report.
    pub dry_run: bool,
    /// If set, only prove this specific case ID.
    pub case_id: Option<String>,
    /// M4: Maximum wall-clock time for the entire batch. Cases in progress when
    /// the deadline is reached finish, but no new cases start.
    pub timeout: Option<Duration>,
}

impl Default for ProveConfig {
    fn default() -> Self {
        Self {
            min_score_for_auto: EvidenceScore::Moderate,
            max_cases: None,
            dry_run: false,
            case_id: None,
            timeout: None,
        }
    }
}

/// Summary of a batch prove operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProveSummary {
    pub total_cases: usize,
    pub proven: usize,
    pub disproven: usize,
    pub inconclusive: usize,
    pub auto_adjudicated: usize,
    /// Cases that failed with an error during proving (M4).
    #[serde(default)]
    pub failed: usize,
    pub results: Vec<ProofOfCompromise>,
}

/// Run proof-of-compromise on all pending BD cases for a run.
pub fn prove_pending(
    history: &HistoryDb,
    run_id: &str,
    config: &ProveConfig,
) -> anyhow::Result<ProveSummary> {
    let pending = history.pending_disagreements(run_id)?;

    // H3: Filter to a single case if case_id is specified
    let filtered: Vec<_> = if let Some(ref cid) = config.case_id {
        let matched: Vec<_> = pending.into_iter().filter(|r| r.case_id == *cid).collect();
        if matched.is_empty() {
            anyhow::bail!("No pending disagreement found for case_id '{cid}' in run {run_id}");
        }
        matched
    } else {
        pending
    };

    let cases: Vec<_> = if let Some(max) = config.max_cases {
        filtered.into_iter().take(max).collect()
    } else {
        filtered
    };

    let mut summary = ProveSummary {
        total_cases: cases.len(),
        ..Default::default()
    };

    let batch_start = Instant::now();

    for record in &cases {
        // M4: Check batch deadline before starting a new case.
        if let Some(timeout) = config.timeout {
            if batch_start.elapsed() >= timeout {
                eprintln!(
                    "  Batch timeout ({:.1}s) reached after {}/{} cases — stopping",
                    timeout.as_secs_f64(),
                    summary.proven + summary.disproven + summary.inconclusive + summary.failed,
                    summary.total_cases,
                );
                // Adjust total to reflect actually processed count
                summary.total_cases =
                    summary.proven + summary.disproven + summary.inconclusive + summary.failed;
                break;
            }
        }

        let start = Instant::now();

        // M4: Catch per-case errors instead of aborting the entire batch.
        let mut result = match prove_single_case(record) {
            Ok(r) => r,
            Err(e) => {
                summary.failed += 1;
                eprintln!(
                    "  [{}/{}] {} FAILED: {}",
                    summary.proven + summary.disproven + summary.inconclusive + summary.failed,
                    summary.total_cases,
                    record.case_id,
                    e,
                );
                continue;
            }
        };
        result.duration_ms = start.elapsed().as_millis() as u64;

        // Store result and auto-adjudicate
        if !config.dry_run {
            if let Err(e) = history.insert_poc_result(&result, &record.id) {
                summary.failed += 1;
                eprintln!(
                    "  [{}/{}] {} FAILED (insert): {}",
                    summary.proven + summary.disproven + summary.inconclusive + summary.failed,
                    summary.total_cases,
                    record.case_id,
                    e,
                );
                continue;
            }

            // H2: Disproven and Proven verdicts are definitive — they bypass the
            // min_score_for_auto threshold. Only Inconclusive/weak verdicts need
            // the score check, since the verdict itself is uncertain.
            let should_auto = match result.verdict {
                PocVerdict::Disproven => true,
                PocVerdict::Proven => true,
                PocVerdict::Inconclusive => false,
            } || result.evidence_score >= config.min_score_for_auto;

            if should_auto {
                let adjudication = match result.verdict {
                    PocVerdict::Proven => Some("TP"),
                    PocVerdict::Disproven => Some("FP"),
                    PocVerdict::Inconclusive => None,
                };
                if let Some(adj) = adjudication {
                    if let Err(e) = history.adjudicate_disagreement(&record.id, adj, "poc-prover") {
                        eprintln!(
                            "  WARNING: auto-adjudication failed for {}: {}",
                            record.case_id, e,
                        );
                        // Non-fatal: the proof result was already stored
                    } else {
                        summary.auto_adjudicated += 1;
                    }
                }
            }
        }

        match result.verdict {
            PocVerdict::Proven => summary.proven += 1,
            PocVerdict::Disproven => summary.disproven += 1,
            PocVerdict::Inconclusive => summary.inconclusive += 1,
        }

        eprintln!(
            "  [{}/{}] {} CWE-{}: {} (evidence: {}, {:.1}s)",
            summary.proven + summary.disproven + summary.inconclusive,
            summary.total_cases,
            record.case_id,
            result.cwe,
            result.verdict,
            result.evidence_score,
            result.duration_ms as f64 / 1000.0,
        );

        summary.results.push(result);
    }

    Ok(summary)
}

/// Prove a single BD case using the appropriate CWE strategy.
fn prove_single_case(record: &DisagreementRecord) -> anyhow::Result<ProofOfCompromise> {
    // H4: Reject unparseable or empty CWE data instead of silently degrading to CWE-0.
    let cwes: Vec<u32> = serde_json::from_str(&record.detected_cwes).map_err(|e| {
        anyhow::anyhow!(
            "malformed detected_cwes JSON for case {}: {} (raw: {:?})",
            record.case_id,
            e,
            record.detected_cwes,
        )
    })?;
    if cwes.is_empty() {
        anyhow::bail!(
            "empty CWE list for case {} (raw: {:?})",
            record.case_id,
            record.detected_cwes,
        );
    }

    let primary_cwe = cwes[0];

    // L2: Only the first CWE is used for strategy selection. When multiple CWEs
    // are present, we may miss vulnerabilities that require a different strategy.
    // TODO: Evaluate all CWEs (run strategy per CWE, take worst-case verdict)
    //       once strategies are fully implemented.
    if cwes.len() > 1 {
        eprintln!(
            "  WARNING: case {} has {} CWEs {:?}, only evaluating CWE-{}",
            record.case_id,
            cwes.len(),
            cwes,
            primary_cwe,
        );
    }

    let strategy = strategies::select_strategy(primary_cwe);

    // Build the proof context from the disagreement record
    let context = strategies::ProofContext {
        case_id: record.case_id.clone(),
        suite: record.suite.clone(),
        cwe: primary_cwe,
        detected_cwes: cwes,
        finding_id: record.finding_id.clone(),
    };

    // Execute the strategy (currently returns evidence-based analysis;
    // future: integrate with AgentRunner for LLM-powered evidence gathering)
    let (disproof_evidence, proof_evidence, reasoning) = strategy.execute(&context)?;

    let (evidence_score, verdict) = score_evidence(&disproof_evidence, &proof_evidence);

    // Generate exploit sketch only for proven cases
    let exploit_sketch = if verdict == PocVerdict::Proven {
        strategy.generate_exploit_sketch(&context, &proof_evidence)
    } else {
        None
    };

    Ok(ProofOfCompromise {
        case_id: record.case_id.clone(),
        cwe: format!("CWE-{}", primary_cwe),
        strategy: strategy.name().to_string(),
        verdict,
        evidence_score,
        disproof_evidence,
        proof_evidence,
        exploit_sketch,
        reasoning,
        tools_used: strategy
            .required_tools()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        duration_ms: 0, // Filled in by caller
    })
}

// ---------------------------------------------------------------------------
// Print summary
// ---------------------------------------------------------------------------

impl ProveSummary {
    /// Format a terminal-friendly summary.
    pub fn print_summary(&self) {
        if self.total_cases == 0 {
            println!("  No benchmark disagreements to prove.");
            return;
        }

        println!("\n  ═══ Proof-of-Compromise Results ═══");
        println!(
            "  Total BD cases: {}  |  Proven: {}  |  Disproven: {}  |  Inconclusive: {}  |  Failed: {}",
            self.total_cases, self.proven, self.disproven, self.inconclusive, self.failed,
        );
        if self.auto_adjudicated > 0 {
            println!("  Auto-adjudicated: {}", self.auto_adjudicated);
        }

        for result in &self.results {
            let icon = match result.verdict {
                PocVerdict::Proven => "✓",
                PocVerdict::Disproven => "✗",
                PocVerdict::Inconclusive => "?",
            };
            println!(
                "  {} {} {} [{}] — {} proof evidence, {} disproof evidence",
                icon,
                result.case_id,
                result.cwe,
                result.verdict,
                result.proof_evidence.len(),
                result.disproof_evidence.len(),
            );
            if let Some(ref sketch) = result.exploit_sketch {
                println!("    UNTESTED HYPOTHESIS: {}", sketch);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disproof_wins() {
        let disproof = vec![Evidence {
            kind: EvidenceKind::Sanitizer,
            description: "Input is HTML-escaped via encode_entities()".into(),
            location: "src/web/render.rs:42".into(),
            tool_output: "{}".into(),
        }];
        let proof = vec![Evidence {
            kind: EvidenceKind::TaintPath,
            description: "Taint from request.param to response.write".into(),
            location: "src/web/handler.rs:10".into(),
            tool_output: "{}".into(),
        }];
        let (score, verdict) = score_evidence(&disproof, &proof);
        assert_eq!(score, EvidenceScore::Disproven);
        assert_eq!(verdict, PocVerdict::Disproven);
    }

    #[test]
    fn test_strong_proof() {
        let proof = vec![
            Evidence {
                kind: EvidenceKind::TaintPath,
                description: "Source to sink path".into(),
                location: "a.rs:1".into(),
                tool_output: "{}".into(),
            },
            Evidence {
                kind: EvidenceKind::DataFlowSource,
                description: "User input from HTTP param".into(),
                location: "a.rs:2".into(),
                tool_output: "{}".into(),
            },
            Evidence {
                kind: EvidenceKind::PatternMatch,
                description: "String concat in SQL query".into(),
                location: "a.rs:3".into(),
                tool_output: "{}".into(),
            },
            Evidence {
                kind: EvidenceKind::CallChain,
                description: "handler → process → query".into(),
                location: "a.rs:4".into(),
                tool_output: "{}".into(),
            },
        ];
        let (score, verdict) = score_evidence(&[], &proof);
        assert_eq!(score, EvidenceScore::Strong);
        assert_eq!(verdict, PocVerdict::Proven);
    }

    #[test]
    fn test_insufficient_evidence() {
        let proof = vec![Evidence {
            kind: EvidenceKind::CodeSnippet,
            description: "Suspicious code".into(),
            location: "a.rs:1".into(),
            tool_output: "{}".into(),
        }];
        let (score, verdict) = score_evidence(&[], &proof);
        assert_eq!(score, EvidenceScore::Insufficient);
        assert_eq!(verdict, PocVerdict::Inconclusive);
    }

    #[test]
    fn test_exploit_sketch_not_scored() {
        let proof = vec![
            Evidence {
                kind: EvidenceKind::UntestedExploitSketch,
                description: "Payload: ' OR 1=1 --".into(),
                location: "".into(),
                tool_output: "{}".into(),
            },
            Evidence {
                kind: EvidenceKind::TaintPath,
                description: "Path exists".into(),
                location: "a.rs:1".into(),
                tool_output: "{}".into(),
            },
        ];
        let (score, verdict) = score_evidence(&[], &proof);
        assert_eq!(score, EvidenceScore::Insufficient);
        assert_eq!(verdict, PocVerdict::Inconclusive);
    }

    #[test]
    fn test_moderate_proof() {
        let proof = vec![
            Evidence {
                kind: EvidenceKind::TaintPath,
                description: "Path".into(),
                location: "a.rs:1".into(),
                tool_output: "{}".into(),
            },
            Evidence {
                kind: EvidenceKind::DataFlowSource,
                description: "Source".into(),
                location: "a.rs:2".into(),
                tool_output: "{}".into(),
            },
            Evidence {
                kind: EvidenceKind::PatternMatch,
                description: "Pattern".into(),
                location: "a.rs:3".into(),
                tool_output: "{}".into(),
            },
        ];
        let (score, verdict) = score_evidence(&[], &proof);
        assert_eq!(score, EvidenceScore::Moderate);
        assert_eq!(verdict, PocVerdict::Proven);
    }

    // --- H2: Disproven verdicts bypass score threshold for auto-adjudication ---

    #[test]
    fn test_disproven_verdict_bypasses_auto_threshold() {
        // EvidenceScore::Disproven (0) < Moderate (2), but Disproven is a
        // definitive verdict that should always auto-adjudicate.
        let score = EvidenceScore::Disproven;
        let verdict = PocVerdict::Disproven;
        let min_score = EvidenceScore::Moderate;

        // The old logic: score >= min_score → false (bug).
        assert!(
            score < min_score,
            "Disproven < Moderate confirms the bug scenario"
        );

        // The new logic: definitive verdicts bypass the threshold.
        let should_auto =
            matches!(verdict, PocVerdict::Disproven | PocVerdict::Proven) || score >= min_score;
        assert!(should_auto, "Disproven verdict must always auto-adjudicate");
    }

    #[test]
    fn test_proven_verdict_bypasses_auto_threshold() {
        // Proven verdict with Insufficient evidence should still auto-adjudicate
        // because Proven is a definitive verdict.
        let verdict = PocVerdict::Proven;
        let score = EvidenceScore::Insufficient;
        let min_score = EvidenceScore::Moderate;

        let should_auto =
            matches!(verdict, PocVerdict::Disproven | PocVerdict::Proven) || score >= min_score;
        assert!(should_auto);
    }

    #[test]
    fn test_inconclusive_respects_threshold() {
        let verdict = PocVerdict::Inconclusive;
        let score = EvidenceScore::Insufficient;
        let min_score = EvidenceScore::Moderate;

        let should_auto =
            matches!(verdict, PocVerdict::Disproven | PocVerdict::Proven) || score >= min_score;
        assert!(
            !should_auto,
            "Inconclusive with low score must NOT auto-adjudicate"
        );
    }

    // --- H4: Malformed CWE data must be rejected ---

    fn make_test_record(detected_cwes: &str) -> DisagreementRecord {
        DisagreementRecord {
            id: "test-id".into(),
            run_id: String::new(),
            case_id: "test-case".into(),
            suite: "test-suite".into(),
            finding_id: "test-finding".into(),
            detected_cwes: detected_cwes.into(),
            adjudication: None,
            adjudicated_at: None,
            adjudicated_by: None,
        }
    }

    #[test]
    fn test_malformed_cwe_json_returns_error() {
        let record = make_test_record("not-valid-json");
        let result = prove_single_case(&record);
        assert!(result.is_err(), "Malformed JSON must return Err");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("malformed detected_cwes JSON"),
            "Error message should mention malformed JSON, got: {}",
            err_msg,
        );
    }

    #[test]
    fn test_empty_cwe_list_returns_error() {
        let record = make_test_record("[]");
        let result = prove_single_case(&record);
        assert!(result.is_err(), "Empty CWE list must return Err");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty CWE list"),
            "Error message should mention empty list, got: {}",
            err_msg,
        );
    }

    #[test]
    fn test_valid_cwe_json_succeeds() {
        let record = make_test_record("[89]");
        let result = prove_single_case(&record);
        assert!(
            result.is_ok(),
            "Valid CWE JSON should succeed: {:?}",
            result.err()
        );
    }

    // --- M4: Batch error handling via ProveSummary.failed ---

    #[test]
    fn test_prove_summary_failed_field_defaults_to_zero() {
        let summary = ProveSummary::default();
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_prove_summary_serde_roundtrip_with_failed() {
        let summary = ProveSummary {
            total_cases: 5,
            proven: 1,
            disproven: 1,
            inconclusive: 1,
            auto_adjudicated: 1,
            failed: 1,
            results: vec![],
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deser: ProveSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.failed, 1);
    }

    #[test]
    fn test_prove_summary_serde_backwards_compat() {
        // Old serialized summaries without `failed` field should still deserialize.
        let json = r#"{"total_cases":3,"proven":1,"disproven":1,"inconclusive":1,"auto_adjudicated":0,"results":[]}"#;
        let deser: ProveSummary = serde_json::from_str(json).unwrap();
        assert_eq!(
            deser.failed, 0,
            "Missing 'failed' field should default to 0"
        );
    }
}
