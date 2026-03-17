//! Scoring engine: TP/FP/FN computation, precision/recall/F1.

use crate::adapters::DetectedFinding;
use crate::ground_truth::TestCase;
use skwaq_core::analysis::{SemanticPatternClass, SemanticPatternClassifier};
use std::collections::{BTreeSet, HashMap, HashSet};

pub const CWE_REGRESSION_NOISE_MARGIN: f64 = 0.02;

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
    pub per_semantic: HashMap<String, SemanticScore>,
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

#[derive(Debug, Clone, Default)]
pub struct SemanticScore {
    pub class_name: String,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CweRegressionDelta {
    pub cwe_id: u32,
    pub previous_detection_rate: f64,
    pub current_detection_rate: f64,
    pub delta_detection_rate: f64,
}

/// Score a single test case against ground truth.
///
/// Only findings whose CWE family overlaps with the expected CWE families
/// are counted. This prevents irrelevant detections (e.g. a memory pattern
/// in a CWE-78 injection test case) from inflating the false-positive count.
pub fn score_case(
    case: &TestCase,
    findings: &[DetectedFinding],
    finding_to_cwes: &dyn Fn(&DetectedFinding) -> Vec<u32>,
) -> CaseOutcome {
    let expected_set: HashSet<u32> = case.expected_cwes.iter().copied().collect();
    let expected_families: HashSet<u32> = expected_set.iter().map(|&e| cwe_family(e)).collect();

    // Filter findings: only keep those relevant to expected CWE families.
    let relevant_findings: Vec<&DetectedFinding> = if expected_set.is_empty() {
        // Negative test case: all findings count (any detection is a false positive).
        findings.iter().collect()
    } else {
        findings
            .iter()
            .filter(|f| {
                let f_cwes = finding_to_cwes(f);
                f_cwes.iter().any(|&d| {
                    expected_families.contains(&cwe_family(d)) || expected_set.contains(&d)
                })
            })
            .collect()
    };

    let detected_cwe_set: HashSet<u32> = if expected_set.is_empty() {
        relevant_findings
            .iter()
            .flat_map(|f| finding_to_cwes(f))
            .collect()
    } else {
        relevant_findings
            .iter()
            .flat_map(|f| finding_to_cwes(f))
            .filter(|d| expected_families.contains(&cwe_family(*d)) || expected_set.contains(d))
            .collect()
    };

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

    for f in &relevant_findings {
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
        120 | 121 | 122 | 123 | 124 | 125 | 126 | 127 | 787 | 788 => 119,
        // Use-after-free family -> CWE-416
        415 => 416,
        // Injection family -> CWE-74
        15 | 77 | 78 | 79 | 80 | 89 | 90 | 94 | 95 | 96 | 114 => 74,
        // Race condition family -> CWE-362
        367 => 362,
        // Integer overflow family -> CWE-190
        128 | 191 | 192 | 193 | 194 | 195 | 196 | 197 | 680 | 681 => 190,
        // free-of-non-heap -> Buffer overflow family
        590 => 119,
        // Null pointer family -> CWE-476
        252 | 253 | 690 => 476,
        // Out-of-bounds read/write -> Buffer overflow family
        129 | 131 | 170 | 805 => 119,
        // Path traversal family -> CWE-22
        23 | 36 => 22,
        // Crypto weakness family -> CWE-327
        326 | 328 | 330 | 338 | 310 | 295 => 327,
        // Use of potentially dangerous function -> CWE-676
        242 | 676 => 676,
        // Hardware crypto with short key -> crypto family
        1240 => 327,
        // Type confusion -> memory safety family
        843 => 119,
        // Untrusted/expired/freed pointer dereference -> memory safety family
        822 | 823 | 825 => 119,
        // Invalid release / offset free -> memory lifecycle family
        761 | 763 => 416,
        // Resource leak family -> CWE-401
        // (includes resource consumption, improper shutdown, missing fd release,
        //  and wrong-phase resource operations — 1,546 Juliet cases)
        400 | 404 | 459 | 666 | 772 | 773 | 775 | 789 => 401,
        // Uninitialized variable family -> CWE-457
        // (includes improper initialization — 224 Juliet cases)
        665 | 908 => 457,
        // Cleartext transmission / hardcoded crypto key -> crypto family CWE-327
        // (336 Juliet cases)
        319 | 321 => 327,
        // Hardcoded password / plaintext password storage -> credentials family CWE-312
        // (224 Juliet cases)
        256 | 259 => 312,
        // Race in thread / signal handler race -> race condition family CWE-362
        // (54 Juliet cases)
        364 | 366 => 362,
        // Uncontrolled search path -> path traversal family CWE-22
        // (560 Juliet cases)
        427 => 22,
        // sizeof() on pointer / path manipulation w/o max-size buffer /
        // return of stack variable address -> buffer overflow family CWE-119
        // (74 Juliet cases)
        467 | 562 | 785 => 119,
        // Everything else maps to itself.
        other => other,
    }
}

/// Default mapping from skwaq DangerCategory to CWE IDs.
pub fn category_to_cwes(category: &str) -> Vec<u32> {
    match category {
        "memory" => vec![
            119, 120, 121, 122, 125, 126, 467, 562, 785, 787, 416, 415, 190, 191, 192, 193, 194,
            195, 196, 197, 680, 681, 128, 590, 761, 763, 822, 823, 825, 843,
        ],
        "injection" => vec![15, 77, 78, 89, 90, 94, 114, 501, 643, 917],
        "format_string" => vec![134],
        "race" => vec![362, 364, 366, 367],
        "temp_file" => vec![377],
        "path_traversal" => vec![22, 23, 36, 427],
        "deserialization" => vec![502],
        "crypto" => vec![
            256, 259, 326, 327, 328, 330, 338, 310, 295, 319, 321, 614, 798, 312, 347, 1240,
        ],
        "unsafe_code" => vec![676, 242],
        "prototype_pollution" => vec![1321],
        "xss" => vec![79, 80],
        "null_deref" => vec![476, 252, 253, 690],
        "integer_overflow" => vec![128, 190, 191, 192, 193, 194, 195, 196, 197, 680, 681],
        "divide_by_zero" => vec![369],
        "resource_leak" => vec![400, 401, 404, 459, 666, 772, 773, 775, 789],
        "uninitialized_var" => vec![457, 665, 908],
        _ => vec![],
    }
}

pub fn semantic_class_to_cwes(class: SemanticPatternClass) -> &'static [u32] {
    match class {
        SemanticPatternClass::BufferOverflow => &[
            119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 170, 467, 562, 785, 787, 788,
            805,
        ],
        SemanticPatternClass::CommandInjection => &[77, 78],
        SemanticPatternClass::CrossSiteScripting => &[79, 80],
        SemanticPatternClass::CryptoWeakness => {
            &[295, 310, 319, 321, 326, 327, 328, 330, 338, 1240]
        }
        SemanticPatternClass::Deserialization => &[502],
        SemanticPatternClass::FormatString => &[134],
        SemanticPatternClass::InsecureTempFile => &[377],
        SemanticPatternClass::PathTraversal => &[22, 23, 36, 427],
        SemanticPatternClass::PrototypePollution => &[1321],
        SemanticPatternClass::RaceCondition => &[362, 364, 366, 367],
        SemanticPatternClass::UnsafeApiUsage => &[242, 676],
        SemanticPatternClass::UseAfterFree => &[415, 416, 761, 763],
        SemanticPatternClass::NullDeref => &[252, 253, 476, 690],
        SemanticPatternClass::IntegerOverflow => {
            &[128, 190, 191, 192, 193, 194, 195, 196, 197, 680, 681]
        }
        SemanticPatternClass::DivideByZero => &[369],
        SemanticPatternClass::ResourceLeak => &[400, 401, 404, 459, 666, 772, 773, 775, 789],
        SemanticPatternClass::UninitializedVar => &[457, 665, 908],
    }
}

pub fn inferred_finding_cwes(finding: &DetectedFinding) -> Vec<u32> {
    if !finding.cwes.is_empty() {
        return dedup_cwes(finding.cwes.iter().copied());
    }

    let semantic_cwes = semantic_finding_cwes(finding);
    if !semantic_cwes.is_empty() {
        return semantic_cwes;
    }

    category_to_cwes(&finding.category)
}

fn semantic_finding_cwes(finding: &DetectedFinding) -> Vec<u32> {
    dedup_cwes(
        SemanticPatternClassifier::new()
            .classify(&finding.category, &finding.title, &finding.function)
            .into_iter()
            .flat_map(semantic_class_to_cwes)
            .copied(),
    )
}

fn dedup_cwes(cwes: impl IntoIterator<Item = u32>) -> Vec<u32> {
    cwes.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn cwe_to_semantic_class(cwe: u32) -> Option<SemanticPatternClass> {
    match cwe {
        119 | 120 | 121 | 122 | 123 | 124 | 125 | 126 | 127 | 129 | 131 | 170 | 467 | 562 | 785
        | 787 | 788 | 805 => Some(SemanticPatternClass::BufferOverflow),
        77 | 78 => Some(SemanticPatternClass::CommandInjection),
        79 | 80 => Some(SemanticPatternClass::CrossSiteScripting),
        295 | 310 | 319 | 321 | 326 | 327 | 328 | 330 | 338 | 1240 => {
            Some(SemanticPatternClass::CryptoWeakness)
        }
        502 => Some(SemanticPatternClass::Deserialization),
        134 => Some(SemanticPatternClass::FormatString),
        22 | 23 | 36 | 427 => Some(SemanticPatternClass::PathTraversal),
        1321 => Some(SemanticPatternClass::PrototypePollution),
        362 | 364 | 366 | 367 => Some(SemanticPatternClass::RaceCondition),
        377 => Some(SemanticPatternClass::InsecureTempFile),
        242 | 676 => Some(SemanticPatternClass::UnsafeApiUsage),
        415 | 416 | 761 | 763 => Some(SemanticPatternClass::UseAfterFree),
        252 | 253 | 476 | 690 => Some(SemanticPatternClass::NullDeref),
        128 | 190 | 191 | 192 | 193 | 194 | 195 | 196 | 197 | 680 | 681 => {
            Some(SemanticPatternClass::IntegerOverflow)
        }
        369 => Some(SemanticPatternClass::DivideByZero),
        400 | 401 | 404 | 459 | 666 | 772 | 773 | 775 | 789 => {
            Some(SemanticPatternClass::ResourceLeak)
        }
        457 | 665 | 908 => Some(SemanticPatternClass::UninitializedVar),
        _ => None,
    }
}

/// Compute aggregate scores from a list of case outcomes.
///
/// Deduplicates outcomes by `case_id` so that overlapping parallel shards
/// do not double-count the same test case. When duplicates exist, the first
/// occurrence is kept (arbitrary but deterministic for a given input order).
pub fn aggregate(outcomes: &[CaseOutcome]) -> AggregateScore {
    let mut score = AggregateScore::default();
    let mut per_cwe: HashMap<u32, CweScore> = HashMap::new();
    let mut per_semantic: HashMap<String, SemanticScore> = HashMap::new();
    let mut seen_case_ids: HashSet<String> = HashSet::new();

    for outcome in outcomes {
        if !seen_case_ids.insert(outcome.case_id.clone()) {
            tracing::debug!(
                "Dedup: skipping duplicate case_id={} (already aggregated)",
                outcome.case_id
            );
            continue;
        }
        if outcome.expected_cwes.is_empty() {
            // Negative test case.
            if outcome.detected_cwes.is_empty() {
                score.true_negatives += 1;
            } else {
                score.false_positives += outcome.unmatched_finding_ids.len() as u32;
                let detected_semantic_classes: HashSet<_> = outcome
                    .detected_cwes
                    .iter()
                    .filter_map(|&cwe| cwe_to_semantic_class(cwe))
                    .collect();
                for class in detected_semantic_classes {
                    let class_name = class.as_str().to_string();
                    let entry =
                        per_semantic
                            .entry(class_name.clone())
                            .or_insert_with(|| SemanticScore {
                                class_name,
                                ..Default::default()
                            });
                    entry.false_positives += 1;
                }
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

            let expected_semantic_classes: HashSet<_> = outcome
                .expected_cwes
                .iter()
                .filter_map(|&cwe| cwe_to_semantic_class(cwe))
                .collect();
            let detected_semantic_classes: HashSet<_> = outcome
                .detected_cwes
                .iter()
                .filter_map(|&cwe| cwe_to_semantic_class(cwe))
                .collect();

            for class in &expected_semantic_classes {
                let class_name = class.as_str().to_string();
                let entry =
                    per_semantic
                        .entry(class_name.clone())
                        .or_insert_with(|| SemanticScore {
                            class_name,
                            ..Default::default()
                        });
                entry.total_cases += 1;
                if detected_semantic_classes.contains(class) {
                    entry.true_positives += 1;
                } else {
                    entry.false_negatives += 1;
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

            for class in detected_semantic_classes.difference(&expected_semantic_classes) {
                let class_name = class.as_str().to_string();
                let entry =
                    per_semantic
                        .entry(class_name.clone())
                        .or_insert_with(|| SemanticScore {
                            class_name,
                            ..Default::default()
                        });
                entry.false_positives += 1;
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

    for entry in per_semantic.values_mut() {
        let tp = entry.true_positives as f64;
        let fp = entry.false_positives as f64;
        let fn_ = entry.false_negatives as f64;
        entry.detection_rate = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        entry.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
    }

    score.per_cwe = per_cwe;
    score.per_semantic = per_semantic;
    score
}

pub fn cwe_regressions(baseline: &AggregateScore, new: &AggregateScore) -> Vec<CweRegressionDelta> {
    let mut regressions: Vec<_> = baseline
        .per_cwe
        .values()
        .filter_map(|baseline_cwe| {
            let new_cwe = new.per_cwe.get(&baseline_cwe.cwe_id)?;
            let delta = new_cwe.detection_rate - baseline_cwe.detection_rate;
            if delta < -CWE_REGRESSION_NOISE_MARGIN {
                Some(CweRegressionDelta {
                    cwe_id: baseline_cwe.cwe_id,
                    previous_detection_rate: baseline_cwe.detection_rate,
                    current_detection_rate: new_cwe.detection_rate,
                    delta_detection_rate: delta,
                })
            } else {
                None
            }
        })
        .collect();
    regressions.sort_by(|a, b| {
        a.delta_detection_rate
            .partial_cmp(&b.delta_detection_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.cwe_id.cmp(&b.cwe_id))
    });
    regressions
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

    fn make_semantic_finding(category: &str, function: &str, title: &str) -> DetectedFinding {
        DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: category.to_string(),
            severity: "high".to_string(),
            cwes: vec![],
            file: "test.c".to_string(),
            function: function.to_string(),
            line: Some(10),
            title: title.to_string(),
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
            binary_path: None,
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
            binary_path: None,
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
        assert_eq!(category_to_cwes("format_string"), vec![134]);
        assert!(category_to_cwes("unknown_category").is_empty());
    }

    #[test]
    fn test_score_case_filters_irrelevant_findings() {
        // CWE-78 injection test case should ignore memory findings (strcpy etc.)
        let case = TestCase {
            id: "cwe78_test".to_string(),
            path: "test.c".to_string(),
            binary_path: None,
            expected_cwes: vec![78],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = vec![
            make_finding("injection", vec![78]), // relevant: matches expected
            make_finding("memory", vec![119]),   // irrelevant: different family
            make_finding("format_string", vec![134]), // irrelevant: different family
        ];

        let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
        // CWE-78 should be detected
        assert!(outcome.cwe_hits[&78]);
        // Only the injection finding should be matched; memory/format_string filtered out
        assert_eq!(outcome.matched_finding_ids.len(), 1);
        assert_eq!(outcome.unmatched_finding_ids.len(), 0);
        // Only relevant CWEs in detected set
        assert!(!outcome.detected_cwes.contains(&119));
        assert!(!outcome.detected_cwes.contains(&134));
    }

    #[test]
    fn test_score_case_negative_case_counts_all() {
        // Negative test case: any finding is a false positive
        let case = TestCase {
            id: "negative".to_string(),
            path: "clean.c".to_string(),
            binary_path: None,
            expected_cwes: vec![],
            is_negative: true,
            language: "c".to_string(),
        };
        let findings = vec![make_finding("memory", vec![119])];

        let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
        // All findings count for negative cases
        assert_eq!(outcome.detected_cwes, vec![119]);
        assert_eq!(outcome.unmatched_finding_ids.len(), 1);
    }

    #[test]
    fn test_new_cwe_family_mappings() {
        // CWE-312 (Cleartext Storage) maps to itself, NOT to CWE-798
        assert_eq!(cwe_family(312), 312);
        // Pointer dereference issues map to memory safety (CWE-119)
        assert_eq!(cwe_family(822), 119);
        assert_eq!(cwe_family(823), 119);
        assert_eq!(cwe_family(825), 119);
        // Hardware crypto → crypto family
        assert_eq!(cwe_family(1240), 327);
        // Dangerous function
        assert_eq!(cwe_family(676), 676);
        assert_eq!(cwe_family(242), 676);
        // Type confusion → memory safety
        assert_eq!(cwe_family(843), 119);
    }

    #[test]
    fn test_aggregate_dedup_by_case_id() {
        // Simulate overlapping shards: same case_id appears twice
        let outcomes = vec![
            CaseOutcome {
                case_id: "case1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "case1".to_string(), // duplicate
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "case2".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![134],
                detected_cwes: vec![],
                matched_finding_ids: vec![],
                unmatched_finding_ids: vec![],
                cwe_hits: [(134, false)].into_iter().collect(),
            },
        ];

        let score = aggregate(&outcomes);
        // Without dedup this would be TP=2, FN=1. With dedup: TP=1, FN=1.
        assert_eq!(score.true_positives, 1);
        assert_eq!(score.false_negatives, 1);
        assert_eq!(score.precision, 1.0);
        assert_eq!(score.recall, 0.5);
    }

    #[test]
    fn test_updated_category_to_cwes() {
        let crypto = category_to_cwes("crypto");
        assert!(crypto.contains(&798));
        assert!(crypto.contains(&312));
        assert!(crypto.contains(&347));
        assert!(crypto.contains(&1240));

        let memory = category_to_cwes("memory");
        assert!(memory.contains(&128));
        assert!(memory.contains(&761));
        assert!(memory.contains(&763));
        assert!(memory.contains(&822));
        assert!(memory.contains(&825));
        assert!(!memory.contains(&242));

        let unsafe_code = category_to_cwes("unsafe_code");
        assert!(unsafe_code.contains(&676));
        assert!(unsafe_code.contains(&242));
    }

    #[test]
    fn test_inferred_finding_cwes_prefers_semantic_mapping() {
        let finding =
            make_semantic_finding("memory", "strcpy", "Dangerous pattern: strcpy (test.c:10)");

        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&119));
        assert!(inferred.contains(&121));
        assert!(!inferred.contains(&416));
        assert!(!inferred.contains(&190));
    }

    #[test]
    fn test_inferred_finding_cwes_falls_back_to_category_mapping() {
        let finding = make_semantic_finding("memory", "allocator", "Potential memory issue");

        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&119));
        assert!(inferred.contains(&416));
        assert!(inferred.contains(&190));
    }

    #[test]
    fn test_inferred_finding_cwes_does_not_overlap_mktemp_into_race_family() {
        let finding = make_semantic_finding(
            "temp_file",
            "mktemp",
            "Pattern: insecure temporary file via mktemp",
        );

        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&377));
        assert!(!inferred.contains(&362));
        assert!(!inferred.contains(&367));
    }

    #[test]
    fn test_aggregate_tracks_per_semantic_scores() {
        let outcomes = vec![
            CaseOutcome {
                case_id: "overflow-hit".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "fmt-miss".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![134],
                detected_cwes: vec![],
                matched_finding_ids: vec![],
                unmatched_finding_ids: vec![],
                cwe_hits: [(134, false)].into_iter().collect(),
            },
        ];

        let score = aggregate(&outcomes);
        let overflow = score.per_semantic.get("buffer_overflow").unwrap();
        assert_eq!(overflow.total_cases, 1);
        assert_eq!(overflow.true_positives, 1);
        assert_eq!(overflow.false_negatives, 0);

        let format = score.per_semantic.get("format_string").unwrap();
        assert_eq!(format.total_cases, 1);
        assert_eq!(format.true_positives, 0);
        assert_eq!(format.false_negatives, 1);
    }

    #[test]
    fn test_semantic_class_to_cwes_new_classes() {
        let div_zero = semantic_class_to_cwes(SemanticPatternClass::DivideByZero);
        assert!(div_zero.contains(&369));

        let xss = semantic_class_to_cwes(SemanticPatternClass::CrossSiteScripting);
        assert!(xss.contains(&79));
        assert!(xss.contains(&80));

        let crypto = semantic_class_to_cwes(SemanticPatternClass::CryptoWeakness);
        assert!(crypto.contains(&327));
        assert!(crypto.contains(&338));
        assert!(crypto.contains(&1240));

        let deser = semantic_class_to_cwes(SemanticPatternClass::Deserialization);
        assert!(deser.contains(&502));

        let int_overflow = semantic_class_to_cwes(SemanticPatternClass::IntegerOverflow);
        assert!(int_overflow.contains(&128));
        assert!(int_overflow.contains(&190));
        assert!(int_overflow.contains(&681));

        let null = semantic_class_to_cwes(SemanticPatternClass::NullDeref);
        assert!(null.contains(&476));
        assert!(null.contains(&690));

        let proto = semantic_class_to_cwes(SemanticPatternClass::PrototypePollution);
        assert!(proto.contains(&1321));

        let leak = semantic_class_to_cwes(SemanticPatternClass::ResourceLeak);
        assert!(leak.contains(&401));
        assert!(leak.contains(&775));
        assert!(!leak.contains(&761));
        assert!(!leak.contains(&763));

        let unsafe_api = semantic_class_to_cwes(SemanticPatternClass::UnsafeApiUsage);
        assert!(unsafe_api.contains(&676));
        assert!(unsafe_api.contains(&242));

        let uninitialized = semantic_class_to_cwes(SemanticPatternClass::UninitializedVar);
        assert!(uninitialized.contains(&457));
        assert!(uninitialized.contains(&908));

        let memory_lifecycle = semantic_class_to_cwes(SemanticPatternClass::UseAfterFree);
        assert!(memory_lifecycle.contains(&761));
        assert!(memory_lifecycle.contains(&763));
    }

    #[test]
    fn test_cwe_to_semantic_class_new_mappings() {
        use SemanticPatternClass::*;
        assert_eq!(cwe_to_semantic_class(79), Some(CrossSiteScripting));
        assert_eq!(cwe_to_semantic_class(80), Some(CrossSiteScripting));
        assert_eq!(cwe_to_semantic_class(327), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(338), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(1240), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(502), Some(Deserialization));
        assert_eq!(cwe_to_semantic_class(128), Some(IntegerOverflow));
        assert_eq!(cwe_to_semantic_class(369), Some(DivideByZero));
        assert_eq!(cwe_to_semantic_class(476), Some(NullDeref));
        assert_eq!(cwe_to_semantic_class(690), Some(NullDeref));
        assert_eq!(cwe_to_semantic_class(1321), Some(PrototypePollution));
        assert_eq!(cwe_to_semantic_class(401), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(761), Some(UseAfterFree));
        assert_eq!(cwe_to_semantic_class(763), Some(UseAfterFree));
        assert_eq!(cwe_to_semantic_class(789), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(676), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(242), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(457), Some(UninitializedVar));
        assert_eq!(cwe_to_semantic_class(908), Some(UninitializedVar));
    }

    #[test]
    fn test_inferred_cwes_for_deserialization_finding() {
        let finding = make_semantic_finding(
            "deserialization",
            "load_data",
            "Pattern: insecure deserialization via pickle.loads",
        );
        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&502));
    }

    #[test]
    fn test_inferred_cwes_for_crypto_finding() {
        let finding = make_semantic_finding("crypto", "md5_init", "Pattern: weak hash MD5 usage");
        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&327));
    }

    #[test]
    fn test_aggregate_tracks_semantic_false_positives_for_negative_cases() {
        let outcomes = vec![CaseOutcome {
            case_id: "negative-semantic-fp".to_string(),
            suite: "test".to_string(),
            expected_cwes: vec![],
            detected_cwes: vec![119],
            matched_finding_ids: vec![],
            unmatched_finding_ids: vec!["f1".to_string()],
            cwe_hits: HashMap::new(),
        }];

        let score = aggregate(&outcomes);
        let overflow = score.per_semantic.get("buffer_overflow").unwrap();
        assert_eq!(overflow.false_positives, 1);
        assert_eq!(overflow.true_positives, 0);
        assert_eq!(overflow.precision, 0.0);
    }

    fn make_score(per_cwe: Vec<(u32, f64)>) -> AggregateScore {
        let mut score = AggregateScore::default();
        for (cwe_id, detection_rate) in per_cwe {
            score.per_cwe.insert(
                cwe_id,
                CweScore {
                    cwe_id,
                    detection_rate,
                    ..Default::default()
                },
            );
        }
        score
    }

    #[test]
    fn test_cwe_regressions_reports_only_drops_beyond_margin() {
        let baseline = make_score(vec![(119, 0.75), (134, 0.50), (190, 0.40)]);
        let new = make_score(vec![(119, 0.72), (134, 0.49), (190, 0.39)]);

        let regressions = cwe_regressions(&baseline, &new);

        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].cwe_id, 119);
        assert!((regressions[0].delta_detection_rate + 0.03).abs() < 1e-9);
    }

    #[test]
    fn test_cwe_regressions_ignores_missing_cwe_in_new_score() {
        let baseline = make_score(vec![(119, 0.75), (134, 0.50)]);
        let new = make_score(vec![(119, 0.75)]);

        let regressions = cwe_regressions(&baseline, &new);

        assert!(regressions.is_empty());
    }

    #[test]
    fn test_cwe_family_null_deref() {
        assert_eq!(cwe_family(476), 476);
        assert_eq!(cwe_family(252), 476);
        assert_eq!(cwe_family(253), 476);
        assert_eq!(cwe_family(690), 476);
    }

    #[test]
    fn test_cwe_family_divide_by_zero() {
        assert_eq!(cwe_family(369), 369);
    }

    #[test]
    fn test_cwe_family_integer_overflow_wraparound() {
        assert_eq!(cwe_family(128), 190);
    }

    #[test]
    fn test_cwe_family_resource_leak() {
        assert_eq!(cwe_family(401), 401);
        assert_eq!(cwe_family(459), 401);
        assert_eq!(cwe_family(772), 401);
        assert_eq!(cwe_family(775), 401);
        assert_eq!(cwe_family(789), 401);
        // Expanded: resource consumption, improper shutdown, missing fd release, wrong phase
        assert_eq!(cwe_family(400), 401);
        assert_eq!(cwe_family(404), 401);
        assert_eq!(cwe_family(773), 401);
        assert_eq!(cwe_family(666), 401);
    }

    #[test]
    fn test_cwe_family_invalid_release_maps_to_memory_lifecycle() {
        assert_eq!(cwe_family(761), 416);
        assert_eq!(cwe_family(763), 416);
    }

    #[test]
    fn test_cwe_family_uninitialized_var() {
        assert_eq!(cwe_family(457), 457);
        assert_eq!(cwe_family(908), 457);
        // Expanded: improper initialization
        assert_eq!(cwe_family(665), 457);
    }

    #[test]
    fn test_category_to_cwes_new_categories() {
        let null = category_to_cwes("null_deref");
        assert!(null.contains(&476));
        assert!(null.contains(&690));

        let int_overflow = category_to_cwes("integer_overflow");
        assert!(int_overflow.contains(&128));
        assert!(int_overflow.contains(&190));
        assert!(int_overflow.contains(&680));

        let div_zero = category_to_cwes("divide_by_zero");
        assert!(div_zero.contains(&369));
        assert!(!div_zero.contains(&128));

        let leak = category_to_cwes("resource_leak");
        assert!(leak.contains(&401));
        assert!(leak.contains(&772));
        assert!(!leak.contains(&761));
        assert!(!leak.contains(&763));

        let uninit = category_to_cwes("uninitialized_var");
        assert!(uninit.contains(&457));
        assert!(uninit.contains(&908));
    }

    // --- Tests for expanded Juliet CWE family mappings (PR #203) ---

    #[test]
    fn test_cwe_family_expanded_crypto() {
        // Cleartext transmission -> crypto family
        assert_eq!(cwe_family(319), 327);
        // Hardcoded crypto key -> crypto family
        assert_eq!(cwe_family(321), 327);
    }

    #[test]
    fn test_cwe_family_expanded_credentials() {
        // Hardcoded password -> credentials family
        assert_eq!(cwe_family(259), 312);
        // Plaintext storage of password -> credentials family
        assert_eq!(cwe_family(256), 312);
    }

    #[test]
    fn test_cwe_family_expanded_race_condition() {
        // Race in thread -> race condition family
        assert_eq!(cwe_family(366), 362);
        // Signal handler race -> race condition family
        assert_eq!(cwe_family(364), 362);
    }

    #[test]
    fn test_cwe_family_expanded_path_traversal() {
        // Uncontrolled search path -> path traversal family
        assert_eq!(cwe_family(427), 22);
    }

    #[test]
    fn test_cwe_family_expanded_buffer_overflow() {
        // sizeof() on pointer -> buffer overflow family
        assert_eq!(cwe_family(467), 119);
        // Path manipulation w/o max-size buffer -> buffer overflow family
        assert_eq!(cwe_family(785), 119);
        // Return of stack variable address -> buffer overflow family
        assert_eq!(cwe_family(562), 119);
    }

    #[test]
    fn test_semantic_class_to_cwes_expanded() {
        let leak = semantic_class_to_cwes(SemanticPatternClass::ResourceLeak);
        assert!(leak.contains(&400));
        assert!(leak.contains(&404));
        assert!(leak.contains(&666));
        assert!(leak.contains(&773));

        let crypto = semantic_class_to_cwes(SemanticPatternClass::CryptoWeakness);
        assert!(crypto.contains(&319));
        assert!(crypto.contains(&321));

        let race = semantic_class_to_cwes(SemanticPatternClass::RaceCondition);
        assert!(race.contains(&364));
        assert!(race.contains(&366));

        let path = semantic_class_to_cwes(SemanticPatternClass::PathTraversal);
        assert!(path.contains(&427));

        let buf = semantic_class_to_cwes(SemanticPatternClass::BufferOverflow);
        assert!(buf.contains(&467));
        assert!(buf.contains(&562));
        assert!(buf.contains(&785));

        let uninit = semantic_class_to_cwes(SemanticPatternClass::UninitializedVar);
        assert!(uninit.contains(&665));
    }

    #[test]
    fn test_cwe_to_semantic_class_expanded() {
        use SemanticPatternClass::*;
        // Resource leak expansions
        assert_eq!(cwe_to_semantic_class(400), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(404), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(666), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(773), Some(ResourceLeak));
        // Crypto expansions
        assert_eq!(cwe_to_semantic_class(319), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(321), Some(CryptoWeakness));
        // Race condition expansions
        assert_eq!(cwe_to_semantic_class(364), Some(RaceCondition));
        assert_eq!(cwe_to_semantic_class(366), Some(RaceCondition));
        // Path traversal expansion
        assert_eq!(cwe_to_semantic_class(427), Some(PathTraversal));
        // Buffer overflow expansions
        assert_eq!(cwe_to_semantic_class(467), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(562), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(785), Some(BufferOverflow));
        // Uninitialized var expansion
        assert_eq!(cwe_to_semantic_class(665), Some(UninitializedVar));
    }

    #[test]
    fn test_category_to_cwes_expanded() {
        let leak = category_to_cwes("resource_leak");
        assert!(leak.contains(&400));
        assert!(leak.contains(&404));
        assert!(leak.contains(&666));
        assert!(leak.contains(&773));

        let crypto = category_to_cwes("crypto");
        assert!(crypto.contains(&319));
        assert!(crypto.contains(&321));
        assert!(crypto.contains(&256));
        assert!(crypto.contains(&259));

        let race = category_to_cwes("race");
        assert!(race.contains(&364));
        assert!(race.contains(&366));

        let path = category_to_cwes("path_traversal");
        assert!(path.contains(&427));

        let memory = category_to_cwes("memory");
        assert!(memory.contains(&467));
        assert!(memory.contains(&562));
        assert!(memory.contains(&785));

        let uninit = category_to_cwes("uninitialized_var");
        assert!(uninit.contains(&665));
    }

    #[test]
    fn test_all_four_mappings_consistent_for_expanded_cwes() {
        // Verify that every CWE in semantic_class_to_cwes has a matching
        // cwe_to_semantic_class reverse mapping.
        let classes = [
            SemanticPatternClass::BufferOverflow,
            SemanticPatternClass::CryptoWeakness,
            SemanticPatternClass::RaceCondition,
            SemanticPatternClass::PathTraversal,
            SemanticPatternClass::ResourceLeak,
            SemanticPatternClass::UninitializedVar,
        ];
        for class in classes {
            for &cwe in semantic_class_to_cwes(class) {
                assert_eq!(
                    cwe_to_semantic_class(cwe),
                    Some(class),
                    "CWE-{cwe} in semantic_class_to_cwes({class:?}) but cwe_to_semantic_class returns {:?}",
                    cwe_to_semantic_class(cwe)
                );
            }
        }
    }
}
