//! Self-improvement loop: analyze failures, propose changes, validate.
//!
//! The improvement loop requires human approval before applying changes
//! (review finding #2). Proposals are written to a staging directory
//! for review rather than applied directly.

use crate::scoring::AggregateScore;
use std::path::PathBuf;

/// A proposed improvement to skwaq.
#[derive(Debug, Clone)]
pub struct Improvement {
    pub kind: ImprovementKind,
    pub description: String,
    pub target_cwes: Vec<u32>,
    pub target_file: PathBuf,
    pub patch: Patch,
}

#[derive(Debug, Clone)]
pub enum ImprovementKind {
    NewPattern,
    AgentPrompt,
    CweMapping,
    TaintRule,
}

#[derive(Debug, Clone)]
pub struct Patch {
    pub find: String,
    pub replace: String,
}

/// Result of an improvement attempt.
#[derive(Debug)]
pub struct ImprovementResult {
    pub improvement: Improvement,
    pub baseline_score: AggregateScore,
    pub new_score: AggregateScore,
    pub accepted: bool,
    pub reason: String,
}

/// Check if any CWE's detection rate dropped.
pub fn has_cwe_regression(baseline: &AggregateScore, new: &AggregateScore) -> bool {
    for (cwe_id, baseline_cwe) in &baseline.per_cwe {
        if let Some(new_cwe) = new.per_cwe.get(cwe_id) {
            // Allow up to 2% regression (noise margin).
            if new_cwe.detection_rate < baseline_cwe.detection_rate - 0.02 {
                return true;
            }
        }
    }
    false
}
