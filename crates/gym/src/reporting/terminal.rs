//! Rich terminal output for benchmark results.

use crate::history::{BenchmarkRun, CaseRegression};
use crate::scoring::{self, AggregateScore};

/// Print a summary of benchmark results.
pub fn print_summary(score: &AggregateScore, suite: &str) {
    println!("\n{}", "=".repeat(70));
    println!("  SKWAQ GYM RESULTS: {}", suite.to_uppercase());
    println!("{}", "=".repeat(70));
    println!();
    println!("  Precision:  {:.1}%", score.precision * 100.0);
    println!("  Recall:     {:.1}%", score.recall * 100.0);
    println!("  F1 Score:   {:.1}%", score.f1 * 100.0);
    println!();
    println!(
        "  TP: {}  FP: {}  FN: {}  TN: {}",
        score.true_positives, score.false_positives, score.false_negatives, score.true_negatives
    );
    println!();

    let mut cwes: Vec<_> = score.per_cwe.values().collect();
    cwes.sort_by(|a, b| {
        a.detection_rate
            .partial_cmp(&b.detection_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    println!(
        "  {:>8} {:>8} {:>8} {:>8} {:>10} {:>10}",
        "CWE", "Cases", "TP", "FN", "Detect%", "Prec%"
    );
    println!("  {}", "-".repeat(62));

    for cwe in &cwes {
        let detect_color = if cwe.detection_rate >= 0.8 {
            "\x1b[32m"
        } else if cwe.detection_rate >= 0.5 {
            "\x1b[33m"
        } else {
            "\x1b[31m"
        };
        println!(
            "  {:>8} {:>8} {:>8} {:>8} {}{:>9.1}%\x1b[0m {:>9.1}%",
            cwe.cwe_id,
            cwe.total_cases,
            cwe.true_positives,
            cwe.false_negatives,
            detect_color,
            cwe.detection_rate * 100.0,
            cwe.precision * 100.0
        );
    }
    println!();

    if !score.per_semantic.is_empty() {
        let mut semantics: Vec<_> = score.per_semantic.values().collect();
        semantics.sort_by(|a, b| {
            a.detection_rate
                .partial_cmp(&b.detection_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        println!(
            "  {:>22} {:>8} {:>8} {:>8} {:>10} {:>10}",
            "Semantic", "Cases", "TP", "FN", "Detect%", "Prec%"
        );
        println!("  {}", "-".repeat(86));

        for semantic in &semantics {
            let detect_color = if semantic.detection_rate >= 0.8 {
                "\x1b[32m"
            } else if semantic.detection_rate >= 0.5 {
                "\x1b[33m"
            } else {
                "\x1b[31m"
            };
            println!(
                "  {:>22} {:>8} {:>8} {:>8} {}{:>9.1}%\x1b[0m {:>9.1}%",
                semantic.class_name,
                semantic.total_cases,
                semantic.true_positives,
                semantic.false_negatives,
                detect_color,
                semantic.detection_rate * 100.0,
                semantic.precision * 100.0
            );
        }
        println!();
    }
}

/// Print a comparison between two runs.
pub fn print_comparison(
    previous: &BenchmarkRun,
    current: &BenchmarkRun,
    previous_score: &AggregateScore,
    current_score: &AggregateScore,
    case_regressions: &[CaseRegression],
) {
    print!(
        "{}",
        render_comparison(
            previous,
            current,
            previous_score,
            current_score,
            case_regressions,
        )
    );
}

fn render_comparison(
    previous: &BenchmarkRun,
    current: &BenchmarkRun,
    previous_score: &AggregateScore,
    current_score: &AggregateScore,
    case_regressions: &[CaseRegression],
) -> String {
    let mut output = String::new();
    output.push_str(&format!("\n{}\n", "=".repeat(70)));
    output.push_str("  IMPROVEMENT COMPARISON\n");
    output.push_str(&format!("{}\n\n", "=".repeat(70)));
    output.push_str(&format!("  Suite: {}\n", current.suite));
    output.push_str(&format!(
        "  Commits: {} -> {}\n\n",
        short_commit(&previous.skwaq_commit),
        short_commit(&current.skwaq_commit)
    ));

    let delta_f1 = current.f1 - previous.f1;
    let delta_p = current.precision - previous.precision;
    let delta_r = current.recall - previous.recall;

    output.push_str(&format!(
        "  {:>12} {:>10} {:>10} {:>10}\n",
        "", "Previous", "Current", "Delta"
    ));
    output.push_str(&format!("  {}\n", "-".repeat(46)));
    output.push_str(&format!(
        "  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%\n",
        "Precision",
        previous.precision * 100.0,
        current.precision * 100.0,
        delta_p * 100.0
    ));
    output.push_str(&format!(
        "  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%\n",
        "Recall",
        previous.recall * 100.0,
        current.recall * 100.0,
        delta_r * 100.0
    ));
    output.push_str(&format!(
        "  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%\n\n",
        "F1",
        previous.f1 * 100.0,
        current.f1 * 100.0,
        delta_f1 * 100.0
    ));

    if delta_f1 > 0.0 {
        output.push_str("  Overall: IMPROVED\n");
    } else if delta_f1 < 0.0 {
        output.push_str("  Overall: REGRESSED\n");
    } else {
        output.push_str("  Overall: No change\n");
    }

    let cwe_regressions = scoring::cwe_regressions(previous_score, current_score);
    output.push('\n');
    if cwe_regressions.is_empty() {
        output.push_str(&format!(
            "  No per-CWE detection regressions beyond the {:.1}% noise margin.\n",
            scoring::CWE_REGRESSION_NOISE_MARGIN * 100.0
        ));
    } else {
        output.push_str(&format!(
            "  Per-CWE detection regressions (> {:.1}% drop):\n",
            scoring::CWE_REGRESSION_NOISE_MARGIN * 100.0
        ));
        output.push_str(&format!(
            "  {:>8} {:>10} {:>10} {:>10}\n",
            "CWE", "Previous", "Current", "Delta"
        ));
        output.push_str(&format!("  {}\n", "-".repeat(46)));
        for regression in &cwe_regressions {
            output.push_str(&format!(
                "  {:>8} {:>9.1}% {:>9.1}% {:>+9.1}%\n",
                regression.cwe_id,
                regression.previous_detection_rate * 100.0,
                regression.current_detection_rate * 100.0,
                regression.delta_detection_rate * 100.0
            ));
        }
    }

    output.push('\n');
    if case_regressions.is_empty() {
        output.push_str("  No case regressions (TP -> FN).\n\n");
    } else {
        output.push_str("  Case regressions (TP -> FN):\n");
        for regression in case_regressions.iter().take(10) {
            output.push_str(&format!(
                "    - {} [{}] expected {:?}, baseline {:?}, current {:?}\n",
                regression.case_id,
                regression.suite,
                regression.expected_cwes,
                regression.baseline_detected,
                regression.new_detected
            ));
        }
        if case_regressions.len() > 10 {
            output.push_str(&format!(
                "    ... and {} more case regressions\n",
                case_regressions.len() - 10
            ));
        }
        output.push('\n');
    }

    output
}

fn short_commit(commit: &str) -> &str {
    &commit[..6.min(commit.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn run(
        id: &str,
        suite: &str,
        commit: &str,
        precision: f64,
        recall: f64,
        f1: f64,
    ) -> BenchmarkRun {
        BenchmarkRun {
            id: id.to_string(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: suite.to_string(),
            skwaq_commit: commit.to_string(),
            metadata: crate::history::RunMetadata::default(),
            precision,
            recall,
            f1,
            true_positives: 0,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 0,
        }
    }

    fn score(per_cwe: Vec<(u32, f64)>) -> AggregateScore {
        let mut per_cwe_map = HashMap::new();
        for (cwe_id, detection_rate) in per_cwe {
            per_cwe_map.insert(
                cwe_id,
                crate::scoring::CweScore {
                    cwe_id,
                    detection_rate,
                    ..Default::default()
                },
            );
        }
        AggregateScore {
            per_cwe: per_cwe_map,
            ..Default::default()
        }
    }

    #[test]
    fn render_comparison_surfaces_cwe_and_case_regressions() {
        let previous = run("run-a", "fixtures", "abcdef123456", 0.8, 0.8, 0.8);
        let current = run("run-b", "fixtures", "123456abcdef", 0.7, 0.6, 0.64);
        let previous_score = score(vec![(119, 0.80), (134, 0.60)]);
        let current_score = score(vec![(119, 0.75), (134, 0.40)]);
        let case_regressions = vec![CaseRegression {
            case_id: "overflow".to_string(),
            suite: "fixtures".to_string(),
            expected_cwes: vec![121],
            baseline_detected: vec![119],
            new_detected: vec![],
        }];

        let rendered = render_comparison(
            &previous,
            &current,
            &previous_score,
            &current_score,
            &case_regressions,
        );

        assert!(rendered.contains("Suite: fixtures"));
        assert!(rendered.contains("Per-CWE detection regressions"));
        assert!(rendered.contains("134"));
        assert!(rendered.contains("Case regressions (TP -> FN):"));
        assert!(rendered.contains("overflow [fixtures]"));
    }

    #[test]
    fn render_comparison_reports_when_no_regressions_exist() {
        let previous = run("run-a", "fixtures", "abcdef123456", 0.8, 0.8, 0.8);
        let current = run("run-b", "fixtures", "123456abcdef", 0.82, 0.81, 0.815);
        let previous_score = score(vec![(119, 0.80)]);
        let current_score = score(vec![(119, 0.79)]);

        let rendered = render_comparison(&previous, &current, &previous_score, &current_score, &[]);

        assert!(rendered.contains("No per-CWE detection regressions"));
        assert!(rendered.contains("No case regressions (TP -> FN)."));
    }
}
