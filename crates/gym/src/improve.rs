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
    for baseline_cwe in baseline.per_cwe.values() {
        if let Some(new_cwe) = new.per_cwe.get(&baseline_cwe.cwe_id) {
            // Allow up to 2% regression (noise margin).
            if new_cwe.detection_rate < baseline_cwe.detection_rate - 0.02 {
                return true;
            }
        }
    }
    false
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
        let new = make_score(vec![(119, 0.49)]); // 1% drop, within 2% margin
        assert!(!has_cwe_regression(&baseline, &new));
    }

    #[test]
    fn test_cwe_absent_from_new_score_is_not_regression() {
        // A CWE absent from the new score means it wasn't tested in the
        // new run (e.g., filtered by --cwe flag). Not a regression.
        let baseline = make_score(vec![(119, 0.5), (134, 0.3)]);
        let new = make_score(vec![(119, 0.6)]); // CWE-134 not in new run
        assert!(!has_cwe_regression(&baseline, &new));
    }
}
