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

    md.push_str("\n## Per-Semantic Detection Rates\n\n");
    if score.per_semantic.is_empty() {
        md.push_str("_No semantic-class metrics available._\n");
        return md;
    }

    md.push_str("| Semantic class | Cases | TP | FN | Detection % | Precision % |\n");
    md.push_str("|----------------|-------|----|----|-------------|-------------|\n");

    let mut semantics: Vec<_> = score.per_semantic.values().collect();
    semantics.sort_by(|a, b| {
        a.detection_rate
            .partial_cmp(&b.detection_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for semantic in &semantics {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {:.1}% | {:.1}% |\n",
            semantic.class_name,
            semantic.total_cases,
            semantic.true_positives,
            semantic.false_negatives,
            semantic.detection_rate * 100.0,
            semantic.precision * 100.0
        ));
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::{AggregateScore, SemanticScore};

    #[test]
    fn test_generate_includes_semantic_section() {
        let mut score = AggregateScore::default();
        score.per_semantic.insert(
            "buffer_overflow".to_string(),
            SemanticScore {
                class_name: "buffer_overflow".to_string(),
                total_cases: 2,
                true_positives: 1,
                false_positives: 0,
                false_negatives: 1,
                detection_rate: 0.5,
                precision: 1.0,
            },
        );

        let markdown = generate(&score, "fixtures", "abc123");
        assert!(markdown.contains("## Per-Semantic Detection Rates"));
        assert!(markdown.contains("buffer_overflow"));
    }
}
