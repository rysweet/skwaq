//! GitHub-compatible Markdown report generation.

use crate::scoring::AggregateScore;

pub fn generate(score: &AggregateScore, suite: &str, commit: &str) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Skwaq Gym Results: {}\n\n", suite));
    md.push_str(&format!("**Commit**: `{}`\n", commit));
    md.push_str(&format!(
        "**Date**: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));

    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Precision | {:.1}% |\n",
        score.precision * 100.0
    ));
    md.push_str(&format!("| Recall | {:.1}% |\n", score.recall * 100.0));
    md.push_str(&format!("| F1 Score | {:.1}% |\n", score.f1 * 100.0));
    md.push_str(&format!("| True Positives | {} |\n", score.true_positives));
    md.push_str(&format!(
        "| False Positives | {} |\n",
        score.false_positives
    ));
    md.push_str(&format!(
        "| False Negatives | {} |\n",
        score.false_negatives
    ));
    md.push_str(&format!(
        "| True Negatives | {} |\n\n",
        score.true_negatives
    ));

    md.push_str("## Per-CWE Detection Rates\n\n");
    md.push_str("| CWE | Cases | TP | FN | Detection % | Precision % |\n");
    md.push_str("|-----|-------|----|----|-------------|-------------|\n");

    let mut cwes: Vec<_> = score.per_cwe.values().collect();
    cwes.sort_by(|a, b| {
        a.detection_rate
            .partial_cmp(&b.detection_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for cwe in &cwes {
        let emoji = if cwe.detection_rate >= 0.8 {
            "+"
        } else if cwe.detection_rate >= 0.5 {
            "~"
        } else {
            "-"
        };
        md.push_str(&format!(
            "| CWE-{} {} | {} | {} | {} | {:.1}% | {:.1}% |\n",
            cwe.cwe_id,
            emoji,
            cwe.total_cases,
            cwe.true_positives,
            cwe.false_negatives,
            cwe.detection_rate * 100.0,
            cwe.precision * 100.0
        ));
    }

    md.push_str("\n\n_Legend: + >80% detection, ~ 50-80%, - <50%_\n");
    md
}
