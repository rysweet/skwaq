//! Scoring engine: TP/FP/FN computation, precision/recall/F1.

use crate::adapters::DetectedFinding;
use crate::ground_truth::TestCase;
use std::collections::{HashMap, HashSet};

/// Outcome for a single test case.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    pub case_id: String,
    pub suite: String,
    pub expected_cwes: Vec<u32>,
    pub detected_cwes: Vec<u32>,
    pub matched_finding_ids: Vec<String>,
    pub unmatched_finding_ids: Vec<String>,
    /// Per expected CWE: was it detected?
    pub cwe_hits: HashMap<u32, bool>,
}

/// Aggregate scores for a set of case outcomes.
#[derive(Debug, Clone, Default)]
pub struct AggregateScore {
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub per_cwe: HashMap<u32, CweScore>,
}

#[derive(Debug, Clone, Default)]
pub struct CweScore {
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

/// Score a single test case against ground truth.
pub fn score_case(
    case: &TestCase,
    findings: &[DetectedFinding],
    finding_to_cwes: &dyn Fn(&DetectedFinding) -> Vec<u32>,
) -> CaseOutcome {
    let detected_cwe_set: HashSet<u32> = findings.iter().flat_map(finding_to_cwes).collect();

    let expected_set: HashSet<u32> = case.expected_cwes.iter().copied().collect();

    let mut cwe_hits = HashMap::new();

    for &expected in &case.expected_cwes {
        let family = cwe_family(expected);
        let hit = detected_cwe_set
            .iter()
            .any(|&d| cwe_family(d) == family || d == expected);
        cwe_hits.insert(expected, hit);
    }

    // Classify findings as matched or unmatched.
    let mut matched_ids = Vec::new();
    let mut unmatched_ids = Vec::new();

    for f in findings {
        let f_cwes: HashSet<u32> = finding_to_cwes(f).into_iter().collect();
        let matches_any_expected = expected_set.iter().any(|&e| {
            let family = cwe_family(e);
            f_cwes.iter().any(|&d| cwe_family(d) == family || d == e)
        });
        if matches_any_expected {
            matched_ids.push(f.id.clone());
        } else {
            unmatched_ids.push(f.id.clone());
        }
    }

    CaseOutcome {
        case_id: case.id.clone(),
        suite: String::new(),
        expected_cwes: case.expected_cwes.clone(),
        detected_cwes: detected_cwe_set.into_iter().collect(),
        matched_finding_ids: matched_ids,
        unmatched_finding_ids: unmatched_ids,
        cwe_hits,
    }
}

/// Map a specific CWE to its broad family for matching purposes.
pub fn cwe_family(cwe: u32) -> u32 {
    match cwe {
        // Buffer overflow family -> CWE-119
        120 | 121 | 122 | 124 | 125 | 126 | 127 | 787 => 119,
        // Use-after-free family -> CWE-416
        415 => 416,
        // Injection family -> CWE-74
        77 | 78 | 79 | 80 | 89 | 90 | 94 | 95 | 96 => 74,
        // Race condition family -> CWE-362
        367 => 362,
        // Integer overflow family -> CWE-190
        191 | 192 | 194 | 195 | 196 | 197 => 190,
        // Null pointer family -> CWE-476
        252 | 253 => 476,
        // Everything else maps to itself.
        other => other,
    }
}

/// Default mapping from skwaq DangerCategory to CWE IDs.
pub fn category_to_cwes(category: &str) -> Vec<u32> {
    match category {
        "memory" => vec![119, 120, 121, 122, 125, 126, 787, 416, 415, 190, 191],
        "injection" => vec![77, 78, 89, 90, 94, 501, 643],
        "format_string" => vec![134],
        "race" => vec![362, 367],
        "temp_file" => vec![377],
        "path_traversal" => vec![22, 23, 36],
        "deserialization" => vec![502],
        "crypto" => vec![326, 327, 328, 330, 338],
        "unsafe_code" => vec![676],
        "prototype_pollution" => vec![1321],
        "xss" => vec![79, 80],
        _ => vec![],
    }
}

/// Compute aggregate scores from a list of case outcomes.
pub fn aggregate(outcomes: &[CaseOutcome]) -> AggregateScore {
    let mut score = AggregateScore::default();
    let mut per_cwe: HashMap<u32, CweScore> = HashMap::new();

    for outcome in outcomes {
        if outcome.expected_cwes.is_empty() {
            // Negative test case.
            if outcome.detected_cwes.is_empty() {
                score.true_negatives += 1;
            } else {
                score.false_positives += outcome.unmatched_finding_ids.len() as u32;
            }
        } else {
            // Positive test case.
            for (&cwe, &hit) in &outcome.cwe_hits {
                let entry = per_cwe.entry(cwe_family(cwe)).or_insert_with(|| CweScore {
                    cwe_id: cwe_family(cwe),
                    ..Default::default()
                });
                entry.total_cases += 1;
                if hit {
                    entry.true_positives += 1;
                    score.true_positives += 1;
                } else {
                    entry.false_negatives += 1;
                    score.false_negatives += 1;
                }
            }
            // False positives: findings that don't match any expected CWE.
            score.false_positives += outcome.unmatched_finding_ids.len() as u32;
            for &cwe in &outcome.detected_cwes {
                let family = cwe_family(cwe);
                if !outcome
                    .expected_cwes
                    .iter()
                    .any(|&e| cwe_family(e) == family)
                {
                    let entry = per_cwe.entry(family).or_insert_with(|| CweScore {
                        cwe_id: family,
                        ..Default::default()
                    });
                    entry.false_positives += 1;
                }
            }
        }
    }

    // Compute rates.
    let tp = score.true_positives as f64;
    let fp = score.false_positives as f64;
    let fn_ = score.false_negatives as f64;

    score.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
    score.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
    score.f1 = if score.precision + score.recall > 0.0 {
        2.0 * score.precision * score.recall / (score.precision + score.recall)
    } else {
        0.0
    };

    for entry in per_cwe.values_mut() {
        let tp = entry.true_positives as f64;
        let fp = entry.false_positives as f64;
        let fn_ = entry.false_negatives as f64;
        entry.detection_rate = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        entry.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
    }

    score.per_cwe = per_cwe;
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::DetectedFinding;

    fn make_finding(category: &str, cwes: Vec<u32>) -> DetectedFinding {
        DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: category.to_string(),
            severity: "high".to_string(),
            cwes,
            file: "test.c".to_string(),
            function: "main".to_string(),
            line: Some(10),
            title: "test finding".to_string(),
        }
    }

    #[test]
    fn test_cwe_family() {
        assert_eq!(cwe_family(121), 119); // stack overflow -> buffer overflow
        assert_eq!(cwe_family(122), 119); // heap overflow -> buffer overflow
        assert_eq!(cwe_family(119), 119); // identity
        assert_eq!(cwe_family(78), 74); // os command injection -> injection
        assert_eq!(cwe_family(999), 999); // unknown -> itself
    }

    #[test]
    fn test_score_case_true_positive() {
        let case = TestCase {
            id: "test".to_string(),
            path: "test.c".to_string(),
            expected_cwes: vec![121],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = vec![make_finding("memory", vec![119])];

        let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
        // CWE-119 matches CWE-121 family
        assert!(outcome.cwe_hits[&121]);
        assert_eq!(outcome.matched_finding_ids.len(), 1);
    }

    #[test]
    fn test_score_case_false_negative() {
        let case = TestCase {
            id: "test".to_string(),
            path: "test.c".to_string(),
            expected_cwes: vec![121],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = vec![]; // no findings

        let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
        assert!(!outcome.cwe_hits[&121]);
    }

    #[test]
    fn test_aggregate_basic() {
        let outcomes = vec![
            CaseOutcome {
                case_id: "hit".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "miss".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![134],
                detected_cwes: vec![],
                matched_finding_ids: vec![],
                unmatched_finding_ids: vec![],
                cwe_hits: [(134, false)].into_iter().collect(),
            },
        ];

        let score = aggregate(&outcomes);
        assert_eq!(score.true_positives, 1);
        assert_eq!(score.false_negatives, 1);
        assert_eq!(score.precision, 1.0);
        assert_eq!(score.recall, 0.5);
    }

    #[test]
    fn test_aggregate_negative_case() {
        let outcomes = vec![CaseOutcome {
            case_id: "clean".to_string(),
            suite: "test".to_string(),
            expected_cwes: vec![],
            detected_cwes: vec![],
            matched_finding_ids: vec![],
            unmatched_finding_ids: vec![],
            cwe_hits: HashMap::new(),
        }];

        let score = aggregate(&outcomes);
        assert_eq!(score.true_negatives, 1);
    }

    #[test]
    fn test_category_to_cwes() {
        assert!(!category_to_cwes("memory").is_empty());
        assert!(!category_to_cwes("injection").is_empty());
        assert!(category_to_cwes("unknown_category").is_empty());
    }
}
