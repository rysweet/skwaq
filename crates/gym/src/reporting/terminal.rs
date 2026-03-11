//! Rich terminal output for benchmark results.

use crate::history::BenchmarkRun;
use crate::scoring::AggregateScore;

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
}

/// Print a comparison between two runs.
pub fn print_comparison(previous: &BenchmarkRun, current: &BenchmarkRun) {
    println!("\n{}", "=".repeat(70));
    println!("  IMPROVEMENT COMPARISON");
    println!("{}", "=".repeat(70));
    println!();

    let delta_f1 = current.f1 - previous.f1;
    let delta_p = current.precision - previous.precision;
    let delta_r = current.recall - previous.recall;

    println!(
        "  {:>12} {:>10} {:>10} {:>10}",
        "", "Previous", "Current", "Delta"
    );
    println!("  {}", "-".repeat(46));
    println!(
        "  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%",
        "Precision",
        previous.precision * 100.0,
        current.precision * 100.0,
        delta_p * 100.0
    );
    println!(
        "  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%",
        "Recall",
        previous.recall * 100.0,
        current.recall * 100.0,
        delta_r * 100.0
    );
    println!(
        "  {:>12} {:>9.1}% {:>9.1}% {:>+9.1}%",
        "F1",
        previous.f1 * 100.0,
        current.f1 * 100.0,
        delta_f1 * 100.0
    );
    println!();

    if delta_f1 > 0.0 {
        println!("  Overall: IMPROVED");
    } else if delta_f1 < 0.0 {
        println!("  Overall: REGRESSED");
    } else {
        println!("  Overall: No change");
    }
    println!();
}
