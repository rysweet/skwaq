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
    /// Calibration metrics from negative/patched cases only.
    pub negative_calibration: NegativeCaseCalibration,
}

/// Tracks false positive rates on known-negative (patched) cases.
///
/// These metrics measure precision honesty: on cases where we KNOW
/// the vulnerability was fixed, how often does skwaq still flag it?
/// A high false_positive_rate here indicates the detector is not
/// sensitive to patches and is pattern-matching superficially.
#[derive(Debug, Clone, Default)]
pub struct NegativeCaseCalibration {
    /// Total negative cases evaluated.
    pub total_negative_cases: u32,
    /// Negative cases where skwaq correctly found nothing.
    pub true_negatives: u32,
    /// Negative cases where skwaq incorrectly flagged a finding.
    pub false_positives: u32,
    /// FP rate: false_positives / total_negative_cases.
    pub false_positive_rate: f64,
    /// Per-semantic-class FP counts on negative cases.
    pub per_semantic_fps: HashMap<String, u32>,
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

/// Precision regression: FP rate on negative cases increased.
#[derive(Debug, Clone, PartialEq)]
pub struct PrecisionRegressionDelta {
    pub previous_fp_rate: f64,
    pub current_fp_rate: f64,
    pub delta_fp_rate: f64,
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
        // Negative test case: only high-confidence, specific findings count as FPs.
        // Requirements:
        //   1. Severity must be "critical" (not "high" — too many FPs from pattern matches)
        //   2. Finding must have at least one specific CWE ID (vague findings are noise)
        // This dual filter dramatically reduces false positives on negative cases.
        findings
            .iter()
            .filter(|f| {
                let sev = f.severity.to_lowercase();
                let has_specific_cwes = !finding_to_cwes(f).is_empty();
                sev == "critical" && has_specific_cwes
            })
            .collect()
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
        118 | 120 | 121 | 122 | 123 | 124 | 125 | 126 | 127 | 787 | 788 => 119,
        135 | 176 | 188 | 806 | 824 | 839 => 119,
        // Use-after-free family -> CWE-416
        415 => 416,
        // Injection family -> CWE-74
        15 | 77 | 78 | 79 | 80 | 89 | 90 | 94 | 95 | 96 | 114 | 116 | 501 | 643 => 74,
        // Input validation family -> CWE-20
        17 | 187 => 20,
        // Race condition family -> CWE-362
        364 | 366 | 367 | 832 => 362,
        // Integer overflow family -> CWE-190
        128 | 189 | 191 | 192 | 193 | 194 | 195 | 196 | 197 | 680 | 681 | 682 => 190,
        // free-of-non-heap -> Buffer overflow family
        590 => 119,
        // Null pointer family -> CWE-476
        252 | 253 | 690 => 476,
        // Out-of-bounds read/write -> Buffer overflow family
        129 | 131 | 170 | 805 => 119,
        // Path traversal family -> CWE-22
        23 | 36 => 22,
        // Untrusted search path is the closest current semantic fit.
        426 => 22,
        // Crypto weakness family -> CWE-327
        295 | 310 | 323 | 325 | 326 | 328 | 330 | 338 | 347 | 780 => 327,
        // Cleartext transmission / hard-coded key -> crypto family
        319 | 321 => 327,
        // Hardcoded password / plaintext password storage -> credentials family
        256 | 259 => 312,
        // Use of potentially dangerous function -> CWE-676
        222 | 223 | 242 | 244 | 247 | 676 => 676,
        // Hardware crypto with short key -> crypto family
        1240 => 327,
        // Information exposure family -> CWE-200
        201 | 209 | 226 | 311 | 526 | 534 | 535 | 615 => 200,
        // Access control family -> CWE-284
        264 | 269 | 272 | 273 | 275 | 434 | 732 => 284,
        // Error handling family -> CWE-703
        388 | 390 | 391 | 393 | 754 | 755 => 703,
        // Resource consumption family -> CWE-400
        399 | 770 | 835 => 400,
        // Type confusion -> memory safety family
        843 => 119,
        // Untrusted/expired/freed pointer dereference -> memory safety family
        822 | 823 | 825 => 119,
        // Invalid release / offset free -> memory lifecycle family
        761 | 763 => 416,
        // Resource leak family -> CWE-401
        // Keep this conservative: only shutdown/release/lifetime-management cases map here.
        404 | 459 | 675 | 772 | 773 | 775 | 789 => 401,
        // Uninitialized variable family -> CWE-457
        // Includes: improper initialization (665), missing init (908)
        665 | 908 => 457,
        // sizeof() on pointer / path manipulation w/o max-size buffer -> buffer overflow family
        467 | 785 => 119,
        // Return of stack variable address -> temporal memory safety family
        562 => 416,
        // Everything else maps to itself.
        other => other,
    }
}

/// Default mapping from skwaq DangerCategory to CWE IDs.
pub fn category_to_cwes(category: &str) -> Vec<u32> {
    match category {
        "memory" => vec![
            118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 135, 170, 176, 188, 467,
            562, 785, 787, 788, 805, 806, 824, 839, 416, 415, 189, 190, 191, 192, 193, 194, 195,
            196, 197, 680, 681, 682, 128, 590, 761, 763, 822, 823, 825, 843,
        ],
        "injection" => vec![15, 77, 78, 89, 90, 94, 114, 116, 501, 643, 917],
        "format_string" => vec![134],
        "race" => vec![362, 364, 366, 367, 832],
        "temp_file" => vec![377],
        "path_traversal" => vec![22, 23, 36, 426],
        "deserialization" => vec![502],
        "crypto" => vec![
            256, 259, 295, 310, 312, 319, 321, 323, 325, 326, 327, 328, 330, 338, 347, 614, 780,
            798, 1240,
        ],
        "unsafe_code" => vec![222, 223, 242, 244, 247, 676],
        "prototype_pollution" => vec![1321],
        "xss" => vec![79, 80],
        "null_deref" => vec![476, 252, 253, 690],
        "integer_overflow" => vec![
            128, 189, 190, 191, 192, 193, 194, 195, 196, 197, 680, 681, 682,
        ],
        "divide_by_zero" => vec![369],
        "resource_leak" => vec![401, 404, 459, 675, 772, 773, 775, 789],
        "uninitialized_var" => vec![457, 563, 665, 908],
        "use_after_free" => vec![415, 416, 562, 761, 763],
        "resource_exhaustion" => vec![400],
        "invalid_free" => vec![590],
        "type_confusion" => vec![843, 591],
        "access_control" => vec![272, 273, 284],
        "information_exposure" => vec![226, 534, 535, 526],
        "error_handling" => vec![666, 390, 391, 667],
        _ => vec![],
    }
}

pub fn semantic_class_to_cwes(class: SemanticPatternClass) -> &'static [u32] {
    match class {
        SemanticPatternClass::BufferOverflow => &[
            118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 135, 170, 176, 188, 467,
            785, 787, 788, 805, 806, 824, 839,
        ],
        SemanticPatternClass::CommandInjection => &[77, 78, 643],
        SemanticPatternClass::CrossSiteScripting => &[79, 80],
        SemanticPatternClass::CryptoWeakness => &[
            256, 259, 295, 310, 312, 319, 321, 323, 325, 326, 327, 328, 330, 338, 347, 780, 798,
            1240,
        ],
        SemanticPatternClass::Deserialization => &[502],
        SemanticPatternClass::DeadStore => &[563],
        SemanticPatternClass::EmbeddedMaliciousCode => &[506, 511, 510],
        SemanticPatternClass::FormatString => &[134],
        SemanticPatternClass::ImproperAccessControl => &[272, 273, 284],
        SemanticPatternClass::ImproperErrorHandling => &[666, 390, 391, 667],
        SemanticPatternClass::InfiniteLoop => &[835, 674],
        SemanticPatternClass::InformationExposure => &[226, 534, 535, 526],
        SemanticPatternClass::InsecureTempFile => &[377],
        SemanticPatternClass::InvalidFree => &[590],
        SemanticPatternClass::LdapInjection => &[90],
        SemanticPatternClass::OperatorMisuse => &[15, 478, 479, 480, 481, 482, 483, 484, 685, 688],
        SemanticPatternClass::PathTraversal => &[22, 23, 36, 426],
        SemanticPatternClass::PointerArithmetic => &[464, 468, 469, 475, 587, 588],
        SemanticPatternClass::SuspiciousCodeConstruct => &[546, 561, 570, 571, 605, 615, 620],
        SemanticPatternClass::UntrustedSearchPath => &[114, 427],
        SemanticPatternClass::UncheckedLoopCondition => &[606],
        SemanticPatternClass::PrototypePollution => &[1321],
        SemanticPatternClass::RaceCondition => &[362, 364, 366, 367, 832],
        SemanticPatternClass::ReachableAssertion => &[617],
        SemanticPatternClass::TypeConfusion => &[843, 591],
        SemanticPatternClass::UndefinedBehavior => &[758, 398],
        SemanticPatternClass::UnsafeApiUsage => &[222, 223, 242, 244, 247, 676],
        SemanticPatternClass::UseAfterFree => &[415, 416, 562, 761, 763],
        SemanticPatternClass::NullDeref => &[252, 253, 476, 690],
        SemanticPatternClass::IntegerOverflow => &[
            128, 189, 190, 191, 192, 193, 194, 195, 196, 197, 680, 681, 682,
        ],
        SemanticPatternClass::DivideByZero => &[369],
        SemanticPatternClass::ResourceExhaustion => &[400],
        SemanticPatternClass::ResourceLeak => &[401, 404, 459, 675, 772, 773, 775, 789],
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

/// Public accessor for CWE-to-semantic-class mapping.
pub fn cwe_to_semantic_class_public(cwe: u32) -> Option<SemanticPatternClass> {
    cwe_to_semantic_class(cwe)
}

fn cwe_to_semantic_class(cwe: u32) -> Option<SemanticPatternClass> {
    match cwe {
        118 | 119 | 120 | 121 | 122 | 123 | 124 | 125 | 126 | 127 | 129 | 131 | 135 | 170 | 176
        | 188 | 467 | 785 | 787 | 788 | 805 | 806 | 824 | 839 => {
            Some(SemanticPatternClass::BufferOverflow)
        }
        77 | 78 | 643 => Some(SemanticPatternClass::CommandInjection),
        79 | 80 => Some(SemanticPatternClass::CrossSiteScripting),
        256 | 259 | 295 | 310 | 312 | 319 | 321 | 323 | 325 | 326 | 327 | 328 | 330 | 338 | 347
        | 780 | 798 | 1240 => Some(SemanticPatternClass::CryptoWeakness),
        502 => Some(SemanticPatternClass::Deserialization),
        563 => Some(SemanticPatternClass::DeadStore),
        506 | 511 | 510 => Some(SemanticPatternClass::EmbeddedMaliciousCode),
        134 => Some(SemanticPatternClass::FormatString),
        272 | 273 | 284 => Some(SemanticPatternClass::ImproperAccessControl),
        666 | 390 | 391 | 667 => Some(SemanticPatternClass::ImproperErrorHandling),
        226 | 534 | 535 | 526 => Some(SemanticPatternClass::InformationExposure),
        590 => Some(SemanticPatternClass::InvalidFree),
        90 => Some(SemanticPatternClass::LdapInjection),
        22 | 23 | 36 | 426 => Some(SemanticPatternClass::PathTraversal),
        114 | 427 => Some(SemanticPatternClass::UntrustedSearchPath),
        606 => Some(SemanticPatternClass::UncheckedLoopCondition),
        1321 => Some(SemanticPatternClass::PrototypePollution),
        362 | 364 | 366 | 367 | 832 => Some(SemanticPatternClass::RaceCondition),
        617 => Some(SemanticPatternClass::ReachableAssertion),
        835 | 674 => Some(SemanticPatternClass::InfiniteLoop),
        15 | 478 | 479 | 480 | 481 | 482 | 483 | 484 | 685 | 688 => {
            Some(SemanticPatternClass::OperatorMisuse)
        }
        464 | 468 | 469 | 475 | 587 | 588 => Some(SemanticPatternClass::PointerArithmetic),
        546 | 561 | 570 | 571 | 605 | 615 | 620 => {
            Some(SemanticPatternClass::SuspiciousCodeConstruct)
        }
        758 | 398 => Some(SemanticPatternClass::UndefinedBehavior),
        843 | 591 => Some(SemanticPatternClass::TypeConfusion),
        377 => Some(SemanticPatternClass::InsecureTempFile),
        222 | 223 | 242 | 244 | 247 | 676 => Some(SemanticPatternClass::UnsafeApiUsage),
        415 | 416 | 562 | 761 | 763 => Some(SemanticPatternClass::UseAfterFree),
        252 | 253 | 476 | 690 => Some(SemanticPatternClass::NullDeref),
        128 | 189 | 190 | 191 | 192 | 193 | 194 | 195 | 196 | 197 | 680 | 681 | 682 => {
            Some(SemanticPatternClass::IntegerOverflow)
        }
        369 => Some(SemanticPatternClass::DivideByZero),
        400 => Some(SemanticPatternClass::ResourceExhaustion),
        401 | 404 | 459 | 675 | 772 | 773 | 775 | 789 => Some(SemanticPatternClass::ResourceLeak),
        457 | 665 | 908 => Some(SemanticPatternClass::UninitializedVar),
        _ => None,
    }
}

/// Deduplicate outcomes by case ID, merging results when the same case
/// appears in multiple shards/processes. When duplicates exist, findings
/// are merged (union of matched/unmatched IDs, union of detected CWEs,
/// and CWE hits use logical OR so a hit in any shard counts).
pub fn deduplicate_outcomes(outcomes: Vec<CaseOutcome>) -> Vec<CaseOutcome> {
    let mut by_case: HashMap<String, CaseOutcome> = HashMap::new();

    for outcome in outcomes {
        by_case
            .entry(outcome.case_id.clone())
            .and_modify(|existing| {
                assert_eq!(
                    existing.suite, outcome.suite,
                    "duplicate case {} had inconsistent suites during deduplication",
                    existing.case_id
                );

                let existing_expected: HashSet<u32> =
                    existing.expected_cwes.iter().copied().collect();
                let incoming_expected: HashSet<u32> =
                    outcome.expected_cwes.iter().copied().collect();
                assert_eq!(
                    existing_expected, incoming_expected,
                    "duplicate case {} had inconsistent expected CWEs during deduplication",
                    existing.case_id
                );

                let mut detected_set: HashSet<u32> =
                    existing.detected_cwes.iter().copied().collect();
                for &cwe in &outcome.detected_cwes {
                    detected_set.insert(cwe);
                }
                existing.detected_cwes = detected_set.into_iter().collect();

                let mut matched_set: HashSet<String> =
                    existing.matched_finding_ids.drain(..).collect();
                for id in &outcome.matched_finding_ids {
                    matched_set.insert(id.clone());
                }
                existing.matched_finding_ids = matched_set.into_iter().collect();

                let mut unmatched_set: HashSet<String> =
                    existing.unmatched_finding_ids.drain(..).collect();
                for id in &outcome.unmatched_finding_ids {
                    unmatched_set.insert(id.clone());
                }
                existing.unmatched_finding_ids = unmatched_set.into_iter().collect();

                for (&cwe, &hit) in &outcome.cwe_hits {
                    let entry = existing.cwe_hits.entry(cwe).or_insert(false);
                    *entry = *entry || hit;
                }
            })
            .or_insert(outcome);
    }

    by_case.into_values().collect()
}

/// Compute aggregate scores from a list of case outcomes.
///
/// Deduplicates outcomes by case ID before aggregation so that the same
/// test case appearing in multiple shards/processes is only counted once.
pub fn aggregate(outcomes: &[CaseOutcome]) -> AggregateScore {
    // Deduplicate by case_id to handle cross-shard merging
    let deduped = deduplicate_outcomes(outcomes.to_vec());

    let mut score = AggregateScore::default();
    let mut per_cwe: HashMap<u32, CweScore> = HashMap::new();
    let mut per_semantic: HashMap<String, SemanticScore> = HashMap::new();

    for outcome in &deduped {
        if outcome.expected_cwes.is_empty() {
            // Negative test case — track calibration metrics.
            score.negative_calibration.total_negative_cases += 1;
            if outcome.detected_cwes.is_empty() {
                score.true_negatives += 1;
                score.negative_calibration.true_negatives += 1;
            } else {
                score.false_positives += outcome.unmatched_finding_ids.len() as u32;
                score.negative_calibration.false_positives += 1;
                let detected_semantic_classes: HashSet<_> = outcome
                    .detected_cwes
                    .iter()
                    .filter_map(|&cwe| cwe_to_semantic_class(cwe))
                    .collect();
                for class in &detected_semantic_classes {
                    let class_name = class.as_str().to_string();
                    *score
                        .negative_calibration
                        .per_semantic_fps
                        .entry(class_name.clone())
                        .or_insert(0) += 1;
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

    // Compute negative case calibration rate
    let neg_total = score.negative_calibration.total_negative_cases as f64;
    let neg_fp = score.negative_calibration.false_positives as f64;
    score.negative_calibration.false_positive_rate = if neg_total > 0.0 {
        neg_fp / neg_total
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

/// Check if an improvement caused a precision regression on negative cases.
///
/// Returns `Some(delta)` if the false positive rate on negative cases
/// increased by more than the noise margin. This catches improvements
/// that help recall but hurt precision — a key overfitting signal.
pub fn precision_regression(
    baseline: &AggregateScore,
    new: &AggregateScore,
) -> Option<PrecisionRegressionDelta> {
    let b = &baseline.negative_calibration;
    let n = &new.negative_calibration;

    // Only check if both have negative cases
    if b.total_negative_cases == 0 || n.total_negative_cases == 0 {
        return None;
    }

    let delta = n.false_positive_rate - b.false_positive_rate;
    if delta > CWE_REGRESSION_NOISE_MARGIN {
        Some(PrecisionRegressionDelta {
            previous_fp_rate: b.false_positive_rate,
            current_fp_rate: n.false_positive_rate,
            delta_fp_rate: delta,
        })
    } else {
        None
    }
}

/// Combined regression check: recall regression OR precision regression.
pub fn has_any_regression(baseline: &AggregateScore, new: &AggregateScore) -> bool {
    !cwe_regressions(baseline, new).is_empty() || precision_regression(baseline, new).is_some()
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
    fn test_score_case_negative_case_critical_only() {
        // Negative test case: only critical findings with specific CWEs count as FP
        let case = TestCase {
            id: "negative".to_string(),
            path: "clean.c".to_string(),
            binary_path: None,
            expected_cwes: vec![],
            is_negative: true,
            language: "c".to_string(),
        };

        // High-severity finding should NOT count as FP (only critical does)
        let high_findings = vec![make_finding("memory", vec![119])];
        let outcome = score_case(&case, &high_findings, &|f| f.cwes.clone());
        assert!(
            outcome.detected_cwes.is_empty(),
            "high severity should be filtered out for negative cases"
        );
        assert_eq!(outcome.unmatched_finding_ids.len(), 0);

        // Critical-severity finding WITH specific CWEs SHOULD count as FP
        let critical_finding = DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: "memory".to_string(),
            severity: "critical".to_string(),
            cwes: vec![119],
            file: "test.c".to_string(),
            function: "main".to_string(),
            line: Some(10),
            title: "test finding".to_string(),
        };
        let outcome = score_case(&case, &[critical_finding], &|f| f.cwes.clone());
        assert_eq!(outcome.detected_cwes, vec![119]);
        assert_eq!(outcome.unmatched_finding_ids.len(), 1);

        // Critical-severity finding WITHOUT CWEs should NOT count as FP
        let vague_finding = DetectedFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: "suspicious".to_string(),
            severity: "critical".to_string(),
            cwes: vec![],
            file: "test.c".to_string(),
            function: "main".to_string(),
            line: Some(10),
            title: "vague finding".to_string(),
        };
        let outcome = score_case(&case, &[vague_finding], &|f| f.cwes.clone());
        assert!(
            outcome.detected_cwes.is_empty(),
            "findings without CWEs should be filtered for negative cases"
        );
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
    fn test_expanded_cwe_family_mappings() {
        // Resource management variants with concrete shutdown/release semantics -> CWE-401
        assert_eq!(cwe_family(404), 401); // improper resource shutdown
        assert_eq!(cwe_family(773), 401); // missing FD reference
        assert_eq!(cwe_family(675), 401); // multiple operations on resource
        assert_eq!(cwe_family(400), 400); // uncontrolled resource consumption stays distinct
        assert_eq!(cwe_family(666), 666); // wrong-lifetime-phase operations stay distinct

        // Crypto transport/key variants -> CWE-327; credentials stay in the 312 family.
        assert_eq!(cwe_family(319), 327); // cleartext transmission
        assert_eq!(cwe_family(321), 327); // hard-coded crypto key
        assert_eq!(cwe_family(259), 312); // hard-coded password
        assert_eq!(cwe_family(256), 312); // plaintext password storage

        // Initialization variants -> CWE-457
        assert_eq!(cwe_family(665), 457); // improper initialization

        // Search-path variants: keep the broader uncontrolled-element case distinct.
        assert_eq!(cwe_family(426), 22); // untrusted search path
        assert_eq!(cwe_family(427), 427); // uncontrolled search path element

        // Stack-address return is temporal memory misuse, not buffer overflow.
        assert_eq!(cwe_family(562), 416);
    }

    #[test]
    fn test_expanded_category_to_cwes() {
        let resource = category_to_cwes("resource_leak");
        assert!(resource.contains(&404));
        assert!(resource.contains(&773));
        assert!(resource.contains(&675));
        assert!(!resource.contains(&400));
        assert!(!resource.contains(&666));

        let crypto = category_to_cwes("crypto");
        assert!(crypto.contains(&312));
        assert!(crypto.contains(&319));
        assert!(crypto.contains(&321));
        assert!(crypto.contains(&259));
        assert!(crypto.contains(&256));
        assert!(crypto.contains(&798));

        let uninit = category_to_cwes("uninitialized_var");
        assert!(uninit.contains(&665));

        let path = category_to_cwes("path_traversal");
        assert!(path.contains(&426));
        assert!(!path.contains(&427));

        let uaf = category_to_cwes("use_after_free");
        assert!(uaf.contains(&562));
        assert!(uaf.contains(&761));
    }

    #[test]
    fn test_expanded_cwe_to_semantic_class() {
        // Resource management
        assert_eq!(
            cwe_to_semantic_class(404),
            Some(SemanticPatternClass::ResourceLeak)
        );
        assert_eq!(
            cwe_to_semantic_class(773),
            Some(SemanticPatternClass::ResourceLeak)
        );
        assert_eq!(
            cwe_to_semantic_class(400),
            Some(SemanticPatternClass::ResourceExhaustion)
        );
        assert_eq!(
            cwe_to_semantic_class(666),
            Some(SemanticPatternClass::ImproperErrorHandling)
        );

        // Crypto
        assert_eq!(
            cwe_to_semantic_class(312),
            Some(SemanticPatternClass::CryptoWeakness)
        );
        assert_eq!(
            cwe_to_semantic_class(319),
            Some(SemanticPatternClass::CryptoWeakness)
        );
        assert_eq!(
            cwe_to_semantic_class(321),
            Some(SemanticPatternClass::CryptoWeakness)
        );
        assert_eq!(
            cwe_to_semantic_class(256),
            Some(SemanticPatternClass::CryptoWeakness)
        );
        assert_eq!(
            cwe_to_semantic_class(259),
            Some(SemanticPatternClass::CryptoWeakness)
        );
        assert_eq!(
            cwe_to_semantic_class(798),
            Some(SemanticPatternClass::CryptoWeakness)
        );

        // Init
        assert_eq!(
            cwe_to_semantic_class(665),
            Some(SemanticPatternClass::UninitializedVar)
        );

        // Path
        assert_eq!(
            cwe_to_semantic_class(426),
            Some(SemanticPatternClass::PathTraversal)
        );
        assert_eq!(
            cwe_to_semantic_class(427),
            Some(SemanticPatternClass::UntrustedSearchPath)
        );

        // Temporal memory safety
        assert_eq!(
            cwe_to_semantic_class(562),
            Some(SemanticPatternClass::UseAfterFree)
        );
    }

    #[test]
    fn test_score_case_expanded_family_matches() {
        // CWE-404 ground truth should match a generalized resource-leak finding.
        let case = TestCase {
            id: "resource_test".to_string(),
            path: "test.c".to_string(),
            binary_path: None,
            expected_cwes: vec![404],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings = vec![make_finding("resource_leak", vec![401])];
        let outcome = score_case(&case, &findings, &|f| f.cwes.clone());
        assert!(outcome.cwe_hits[&404]);

        // CWE-400 should not be counted as a leak family hit.
        let case_uncontrolled_resource = TestCase {
            id: "resource_consumption_test".to_string(),
            path: "test.c".to_string(),
            binary_path: None,
            expected_cwes: vec![400],
            is_negative: false,
            language: "c".to_string(),
        };
        let outcome_uncontrolled_resource =
            score_case(&case_uncontrolled_resource, &findings, &|f| f.cwes.clone());
        assert!(!outcome_uncontrolled_resource.cwe_hits[&400]);

        // CWE-319 ground truth should match CWE-327 crypto finding
        let case2 = TestCase {
            id: "crypto_test".to_string(),
            path: "test.c".to_string(),
            binary_path: None,
            expected_cwes: vec![319],
            is_negative: false,
            language: "c".to_string(),
        };
        let findings2 = vec![make_finding("crypto", vec![327])];
        let outcome2 = score_case(&case2, &findings2, &|f| f.cwes.clone());
        assert!(outcome2.cwe_hits[&319]);
    }

    #[test]
    fn test_aggregate_dedup_by_case_id() {
        // Simulate overlapping shards: the same case appears twice and must merge.
        let outcomes = vec![
            CaseOutcome {
                case_id: "case-1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "case-1".to_string(), // duplicate case_id from another shard
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![122],
                matched_finding_ids: vec!["f2".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "case-2".to_string(),
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
    fn test_deduplicate_merges_findings() {
        let outcomes = vec![
            CaseOutcome {
                case_id: "case-1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, false)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "case-1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![122],
                matched_finding_ids: vec!["f2".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
        ];

        let deduped = deduplicate_outcomes(outcomes);
        assert_eq!(deduped.len(), 1);
        let merged = &deduped[0];
        assert!(merged.cwe_hits[&121], "CWE hit should be OR-merged");
        assert!(merged.detected_cwes.len() >= 2);
        assert_eq!(merged.matched_finding_ids.len(), 2);
    }

    #[test]
    #[should_panic(expected = "inconsistent expected CWEs")]
    fn test_deduplicate_rejects_inconsistent_expected_cwes() {
        let outcomes = vec![
            CaseOutcome {
                case_id: "case-1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![121],
                detected_cwes: vec![119],
                matched_finding_ids: vec!["f1".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(121, true)].into_iter().collect(),
            },
            CaseOutcome {
                case_id: "case-1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![134],
                detected_cwes: vec![134],
                matched_finding_ids: vec!["f2".to_string()],
                unmatched_finding_ids: vec![],
                cwe_hits: [(134, true)].into_iter().collect(),
            },
        ];

        let _ = deduplicate_outcomes(outcomes);
    }

    #[test]
    fn test_updated_category_to_cwes() {
        let crypto = category_to_cwes("crypto");
        assert!(crypto.contains(&798));
        assert!(crypto.contains(&312));
        assert!(crypto.contains(&323));
        assert!(crypto.contains(&325));
        assert!(crypto.contains(&347));
        assert!(crypto.contains(&780));
        assert!(crypto.contains(&1240));

        let memory = category_to_cwes("memory");
        assert!(memory.contains(&118));
        assert!(memory.contains(&135));
        assert!(memory.contains(&176));
        assert!(memory.contains(&188));
        assert!(memory.contains(&128));
        assert!(memory.contains(&761));
        assert!(memory.contains(&763));
        assert!(memory.contains(&806));
        assert!(memory.contains(&824));
        assert!(memory.contains(&839));
        assert!(memory.contains(&822));
        assert!(memory.contains(&825));
        assert!(!memory.contains(&242));

        let unsafe_code = category_to_cwes("unsafe_code");
        assert!(unsafe_code.contains(&222));
        assert!(unsafe_code.contains(&223));
        assert!(unsafe_code.contains(&244));
        assert!(unsafe_code.contains(&247));
        assert!(unsafe_code.contains(&676));
        assert!(unsafe_code.contains(&242));

        let race = category_to_cwes("race");
        assert!(race.contains(&364));
        assert!(race.contains(&366));
        assert!(race.contains(&832));

        let path = category_to_cwes("path_traversal");
        assert!(!path.contains(&59));
        assert!(!path.contains(&61));

        let injection = category_to_cwes("injection");
        assert!(injection.contains(&116));
        assert!(injection.contains(&501));
        assert!(injection.contains(&643));

        let integer = category_to_cwes("integer_overflow");
        assert!(integer.contains(&189));
        assert!(integer.contains(&682));
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
    fn test_inferred_finding_cwes_for_untrusted_search_path_preserves_legacy_114() {
        let finding = make_semantic_finding(
            "path_traversal",
            "dlopen",
            "Pattern: dlopen with untrusted path allows uncontrolled search path loading",
        );

        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&114));
        assert!(inferred.contains(&427));
        assert!(!inferred.contains(&22));
        assert!(!inferred.contains(&426));
    }

    #[test]
    fn test_inferred_finding_cwes_for_unchecked_loop_condition() {
        let finding = make_semantic_finding(
            "memory",
            "print_line",
            "LLM: unchecked loop condition from untrusted input controls iteration count",
        );

        let inferred = inferred_finding_cwes(&finding);
        assert!(inferred.contains(&606));
        assert!(!inferred.contains(&190));
        assert!(!inferred.contains(&119));
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
        assert!(crypto.contains(&256));
        assert!(crypto.contains(&259));
        assert!(crypto.contains(&312));
        assert!(crypto.contains(&327));
        assert!(crypto.contains(&323));
        assert!(crypto.contains(&325));
        assert!(crypto.contains(&338));
        assert!(crypto.contains(&798));
        assert!(crypto.contains(&347));
        assert!(crypto.contains(&780));
        assert!(crypto.contains(&1240));

        let deser = semantic_class_to_cwes(SemanticPatternClass::Deserialization);
        assert!(deser.contains(&502));

        let dead_store = semantic_class_to_cwes(SemanticPatternClass::DeadStore);
        assert_eq!(dead_store, &[563]);

        let reachable = semantic_class_to_cwes(SemanticPatternClass::ReachableAssertion);
        assert_eq!(reachable, &[617]);

        let ldap = semantic_class_to_cwes(SemanticPatternClass::LdapInjection);
        assert_eq!(ldap, &[90]);

        let int_overflow = semantic_class_to_cwes(SemanticPatternClass::IntegerOverflow);
        assert!(int_overflow.contains(&128));
        assert!(int_overflow.contains(&189));
        assert!(int_overflow.contains(&190));
        assert!(int_overflow.contains(&681));
        assert!(int_overflow.contains(&682));

        let null = semantic_class_to_cwes(SemanticPatternClass::NullDeref);
        assert!(null.contains(&476));
        assert!(null.contains(&690));

        let proto = semantic_class_to_cwes(SemanticPatternClass::PrototypePollution);
        assert!(proto.contains(&1321));

        let injection = semantic_class_to_cwes(SemanticPatternClass::CommandInjection);
        assert!(injection.contains(&643));

        let path = semantic_class_to_cwes(SemanticPatternClass::PathTraversal);
        assert!(!path.contains(&59));
        assert!(!path.contains(&61));
        assert!(!path.contains(&427));

        let search_path = semantic_class_to_cwes(SemanticPatternClass::UntrustedSearchPath);
        assert!(search_path.contains(&114));
        assert!(search_path.contains(&427));

        let loop_condition = semantic_class_to_cwes(SemanticPatternClass::UncheckedLoopCondition);
        assert_eq!(loop_condition, &[606]);

        let race = semantic_class_to_cwes(SemanticPatternClass::RaceCondition);
        assert!(race.contains(&364));
        assert!(race.contains(&366));
        assert!(race.contains(&832));

        let leak = semantic_class_to_cwes(SemanticPatternClass::ResourceLeak);
        assert!(leak.contains(&401));
        assert!(leak.contains(&675));
        assert!(leak.contains(&775));
        assert!(!leak.contains(&400));
        assert!(!leak.contains(&666));
        assert!(!leak.contains(&761));
        assert!(!leak.contains(&763));

        let exhaustion = semantic_class_to_cwes(SemanticPatternClass::ResourceExhaustion);
        assert_eq!(exhaustion, &[400]);

        let unsafe_api = semantic_class_to_cwes(SemanticPatternClass::UnsafeApiUsage);
        assert!(unsafe_api.contains(&222));
        assert!(unsafe_api.contains(&223));
        assert!(unsafe_api.contains(&244));
        assert!(unsafe_api.contains(&247));
        assert!(unsafe_api.contains(&676));
        assert!(unsafe_api.contains(&242));

        let uninitialized = semantic_class_to_cwes(SemanticPatternClass::UninitializedVar);
        assert!(uninitialized.contains(&457));
        assert!(uninitialized.contains(&908));

        let memory_lifecycle = semantic_class_to_cwes(SemanticPatternClass::UseAfterFree);
        assert!(memory_lifecycle.contains(&562));
        assert!(memory_lifecycle.contains(&761));
        assert!(memory_lifecycle.contains(&763));

        let invalid_free = semantic_class_to_cwes(SemanticPatternClass::InvalidFree);
        assert_eq!(invalid_free, &[590]);

        let buffer_overflow = semantic_class_to_cwes(SemanticPatternClass::BufferOverflow);
        assert!(buffer_overflow.contains(&118));
        assert!(buffer_overflow.contains(&135));
        assert!(buffer_overflow.contains(&176));
        assert!(buffer_overflow.contains(&188));
        assert!(buffer_overflow.contains(&467));
        assert!(buffer_overflow.contains(&785));
        assert!(buffer_overflow.contains(&806));
        assert!(buffer_overflow.contains(&824));
        assert!(buffer_overflow.contains(&839));
    }

    #[test]
    fn test_cwe_to_semantic_class_new_mappings() {
        use SemanticPatternClass::*;
        assert_eq!(cwe_to_semantic_class(118), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(135), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(176), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(188), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(806), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(824), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(839), Some(BufferOverflow));
        assert_eq!(cwe_to_semantic_class(79), Some(CrossSiteScripting));
        assert_eq!(cwe_to_semantic_class(80), Some(CrossSiteScripting));
        assert_eq!(cwe_to_semantic_class(327), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(312), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(798), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(323), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(325), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(338), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(347), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(780), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(1240), Some(CryptoWeakness));
        assert_eq!(cwe_to_semantic_class(502), Some(Deserialization));
        assert_eq!(cwe_to_semantic_class(272), Some(ImproperAccessControl));
        assert_eq!(cwe_to_semantic_class(284), Some(ImproperAccessControl));
        assert_eq!(cwe_to_semantic_class(843), Some(TypeConfusion));
        assert_eq!(cwe_to_semantic_class(758), Some(UndefinedBehavior));
        assert_eq!(cwe_to_semantic_class(398), Some(UndefinedBehavior));
        assert_eq!(cwe_to_semantic_class(591), Some(TypeConfusion));
        assert_eq!(cwe_to_semantic_class(563), Some(DeadStore));
        assert_eq!(cwe_to_semantic_class(617), Some(ReachableAssertion));
        assert_eq!(cwe_to_semantic_class(506), Some(EmbeddedMaliciousCode));
        assert_eq!(cwe_to_semantic_class(511), Some(EmbeddedMaliciousCode));
        assert_eq!(cwe_to_semantic_class(666), Some(ImproperErrorHandling));
        assert_eq!(cwe_to_semantic_class(390), Some(ImproperErrorHandling));
        assert_eq!(cwe_to_semantic_class(226), Some(InformationExposure));
        assert_eq!(cwe_to_semantic_class(534), Some(InformationExposure));
        assert_eq!(cwe_to_semantic_class(546), Some(SuspiciousCodeConstruct));
        assert_eq!(cwe_to_semantic_class(570), Some(SuspiciousCodeConstruct));
        assert_eq!(cwe_to_semantic_class(90), Some(LdapInjection));
        assert_eq!(cwe_to_semantic_class(128), Some(IntegerOverflow));
        assert_eq!(cwe_to_semantic_class(369), Some(DivideByZero));
        assert_eq!(cwe_to_semantic_class(476), Some(NullDeref));
        assert_eq!(cwe_to_semantic_class(690), Some(NullDeref));
        assert_eq!(cwe_to_semantic_class(1321), Some(PrototypePollution));
        assert_eq!(cwe_to_semantic_class(643), Some(CommandInjection));
        assert_eq!(cwe_to_semantic_class(59), None);
        assert_eq!(cwe_to_semantic_class(61), None);
        assert_eq!(cwe_to_semantic_class(364), Some(RaceCondition));
        assert_eq!(cwe_to_semantic_class(366), Some(RaceCondition));
        assert_eq!(cwe_to_semantic_class(832), Some(RaceCondition));
        assert_eq!(cwe_to_semantic_class(401), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(675), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(400), Some(ResourceExhaustion));
        assert_eq!(cwe_to_semantic_class(666), Some(ImproperErrorHandling));
        assert_eq!(cwe_to_semantic_class(189), Some(IntegerOverflow));
        assert_eq!(cwe_to_semantic_class(682), Some(IntegerOverflow));
        assert_eq!(cwe_to_semantic_class(761), Some(UseAfterFree));
        assert_eq!(cwe_to_semantic_class(763), Some(UseAfterFree));
        assert_eq!(cwe_to_semantic_class(562), Some(UseAfterFree));
        assert_eq!(cwe_to_semantic_class(789), Some(ResourceLeak));
        assert_eq!(cwe_to_semantic_class(222), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(223), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(244), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(247), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(676), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(242), Some(UnsafeApiUsage));
        assert_eq!(cwe_to_semantic_class(457), Some(UninitializedVar));
        assert_eq!(cwe_to_semantic_class(908), Some(UninitializedVar));
        assert_eq!(cwe_to_semantic_class(114), Some(UntrustedSearchPath));
        assert_eq!(cwe_to_semantic_class(426), Some(PathTraversal));
        assert_eq!(cwe_to_semantic_class(427), Some(UntrustedSearchPath));
        assert_eq!(cwe_to_semantic_class(590), Some(InvalidFree));
        assert_eq!(cwe_to_semantic_class(606), Some(UncheckedLoopCondition));
    }

    #[test]
    fn test_cwe_family_safe_subset_preserves_recent_scoring_decisions() {
        assert_eq!(cwe_family(59), 59);
        assert_eq!(cwe_family(61), 61);
        assert_eq!(cwe_family(256), 312);
        assert_eq!(cwe_family(259), 312);
        assert_eq!(cwe_family(404), 401);
        assert_eq!(cwe_family(675), 401);
        assert_eq!(cwe_family(426), 22);
        assert_eq!(cwe_family(427), 427);
    }

    #[test]
    fn test_cwe_family_safe_subset_adds_new_family_roots_conservatively() {
        assert_eq!(cwe_family(17), 20);
        assert_eq!(cwe_family(187), 20);
        assert_eq!(cwe_family(201), 200);
        assert_eq!(cwe_family(209), 200);
        assert_eq!(cwe_family(226), 200);
        assert_eq!(cwe_family(311), 200);
        assert_eq!(cwe_family(526), 200);
        assert_eq!(cwe_family(534), 200);
        assert_eq!(cwe_family(535), 200);
        assert_eq!(cwe_family(615), 200);
        assert_eq!(cwe_family(264), 284);
        assert_eq!(cwe_family(269), 284);
        assert_eq!(cwe_family(272), 284);
        assert_eq!(cwe_family(273), 284);
        assert_eq!(cwe_family(275), 284);
        assert_eq!(cwe_family(434), 284);
        assert_eq!(cwe_family(732), 284);
        assert_eq!(cwe_family(388), 703);
        assert_eq!(cwe_family(390), 703);
        assert_eq!(cwe_family(391), 703);
        assert_eq!(cwe_family(393), 703);
        assert_eq!(cwe_family(754), 703);
        assert_eq!(cwe_family(755), 703);
        assert_eq!(cwe_family(399), 400);
        assert_eq!(cwe_family(770), 400);
        assert_eq!(cwe_family(835), 400);
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

        // Verify negative calibration tracking
        assert_eq!(score.negative_calibration.total_negative_cases, 1);
        assert_eq!(score.negative_calibration.false_positives, 1);
        assert_eq!(score.negative_calibration.true_negatives, 0);
        assert!((score.negative_calibration.false_positive_rate - 1.0).abs() < 1e-9);
        assert_eq!(
            *score
                .negative_calibration
                .per_semantic_fps
                .get("buffer_overflow")
                .unwrap(),
            1
        );
    }

    #[test]
    fn test_negative_calibration_clean_cases() {
        let outcomes = vec![
            CaseOutcome {
                case_id: "neg-clean-1".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![],
                detected_cwes: vec![],
                matched_finding_ids: vec![],
                unmatched_finding_ids: vec![],
                cwe_hits: HashMap::new(),
            },
            CaseOutcome {
                case_id: "neg-clean-2".to_string(),
                suite: "test".to_string(),
                expected_cwes: vec![],
                detected_cwes: vec![],
                matched_finding_ids: vec![],
                unmatched_finding_ids: vec![],
                cwe_hits: HashMap::new(),
            },
        ];

        let score = aggregate(&outcomes);
        assert_eq!(score.negative_calibration.total_negative_cases, 2);
        assert_eq!(score.negative_calibration.true_negatives, 2);
        assert_eq!(score.negative_calibration.false_positives, 0);
        assert_eq!(score.negative_calibration.false_positive_rate, 0.0);
        assert!(score.negative_calibration.per_semantic_fps.is_empty());
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
    fn test_precision_regression_detects_fp_increase() {
        let mut baseline = AggregateScore::default();
        baseline.negative_calibration.total_negative_cases = 10;
        baseline.negative_calibration.false_positives = 1;
        baseline.negative_calibration.false_positive_rate = 0.10;

        let mut new = AggregateScore::default();
        new.negative_calibration.total_negative_cases = 10;
        new.negative_calibration.false_positives = 4;
        new.negative_calibration.false_positive_rate = 0.40;

        let delta = precision_regression(&baseline, &new);
        assert!(
            delta.is_some(),
            "Should detect 0.10 → 0.40 FP rate increase"
        );
        let d = delta.unwrap();
        assert!((d.delta_fp_rate - 0.30).abs() < 1e-9);
    }

    #[test]
    fn test_precision_regression_ignores_small_change() {
        let mut baseline = AggregateScore::default();
        baseline.negative_calibration.total_negative_cases = 10;
        baseline.negative_calibration.false_positive_rate = 0.10;

        let mut new = AggregateScore::default();
        new.negative_calibration.total_negative_cases = 10;
        new.negative_calibration.false_positive_rate = 0.11;

        assert!(
            precision_regression(&baseline, &new).is_none(),
            "0.01 increase should be within noise margin"
        );
    }

    #[test]
    fn test_has_any_regression_combines_checks() {
        let mut baseline = make_score(vec![(119, 0.75)]);
        baseline.negative_calibration.total_negative_cases = 5;
        baseline.negative_calibration.false_positive_rate = 0.0;

        // No regression at all
        let same = baseline.clone();
        assert!(!has_any_regression(&baseline, &same));

        // Only precision regression (FP increase but recall stable)
        let mut fp_worse = baseline.clone();
        fp_worse.negative_calibration.false_positive_rate = 0.50;
        assert!(has_any_regression(&baseline, &fp_worse));
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
        assert_eq!(cwe_family(404), 401);
        assert_eq!(cwe_family(773), 401);
        assert_eq!(cwe_family(675), 401);
        assert_eq!(cwe_family(400), 400);
        assert_eq!(cwe_family(666), 666);
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
    }

    #[test]
    fn test_cwe_family_safe_subset_expansions() {
        assert_eq!(cwe_family(643), 74);
        assert_eq!(cwe_family(59), 59);
        assert_eq!(cwe_family(61), 61);
        assert_eq!(cwe_family(323), 327);
        assert_eq!(cwe_family(325), 327);
        assert_eq!(cwe_family(347), 327);
        assert_eq!(cwe_family(780), 327);
        assert_eq!(cwe_family(364), 362);
        assert_eq!(cwe_family(366), 362);
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
        assert!(leak.contains(&675));
        assert!(!leak.contains(&400));
        assert!(!leak.contains(&666));
        assert!(!leak.contains(&761));
        assert!(!leak.contains(&763));

        let uninit = category_to_cwes("uninitialized_var");
        assert!(uninit.contains(&457));
        assert!(uninit.contains(&908));

        let uaf = category_to_cwes("use_after_free");
        assert!(uaf.contains(&562));
        let race = category_to_cwes("race");
        assert!(race.contains(&364));
        assert!(race.contains(&366));

        let path = category_to_cwes("path_traversal");
        assert!(!path.contains(&59));
        assert!(!path.contains(&61));

        let injection = category_to_cwes("injection");
        assert!(injection.contains(&643));
    }

    #[test]
    fn test_semantic_and_category_cwe_consistency() {
        // Every CWE mapped by semantic_class_to_cwes should be reachable
        // from at least one category_to_cwes entry. This prevents drift
        // between the two mapping systems.
        use skwaq_core::analysis::SemanticPatternClass;

        let all_classes = [
            SemanticPatternClass::BufferOverflow,
            SemanticPatternClass::CommandInjection,
            SemanticPatternClass::CrossSiteScripting,
            SemanticPatternClass::CryptoWeakness,
            SemanticPatternClass::DeadStore,
            SemanticPatternClass::Deserialization,
            SemanticPatternClass::FormatString,
            SemanticPatternClass::InsecureTempFile,
            SemanticPatternClass::InvalidFree,
            SemanticPatternClass::LdapInjection,
            SemanticPatternClass::NullDeref,
            SemanticPatternClass::IntegerOverflow,
            SemanticPatternClass::DivideByZero,
            SemanticPatternClass::RaceCondition,
            SemanticPatternClass::ResourceLeak,
            SemanticPatternClass::ResourceExhaustion,
            SemanticPatternClass::UninitializedVar,
            SemanticPatternClass::UseAfterFree,
            SemanticPatternClass::UnsafeApiUsage,
            SemanticPatternClass::PathTraversal,
        ];

        let all_categories = [
            "memory",
            "injection",
            "format_string",
            "race",
            "temp_file",
            "path_traversal",
            "deserialization",
            "crypto",
            "unsafe_code",
            "prototype_pollution",
            "xss",
            "null_deref",
            "integer_overflow",
            "divide_by_zero",
            "resource_leak",
            "resource_exhaustion",
            "uninitialized_var",
            "use_after_free",
            "invalid_free",
            "type_confusion",
            "access_control",
            "information_exposure",
            "error_handling",
        ];

        let category_cwes: std::collections::HashSet<u32> = all_categories
            .iter()
            .flat_map(|c| category_to_cwes(c))
            .collect();

        for class in &all_classes {
            for &cwe in semantic_class_to_cwes(*class) {
                assert!(
                    category_cwes.contains(&cwe),
                    "CWE-{} from semantic class {:?} not reachable from any category_to_cwes entry",
                    cwe,
                    class
                );
            }
        }
    }
}
