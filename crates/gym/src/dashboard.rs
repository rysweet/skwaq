//! Dashboard: generates mermaid charts and updates the GitHub issue.
//!
//! Called after each eval/improve cycle to keep the master issue
//! up-to-date with the latest scores and trajectory.

use crate::history::HistoryDb;
use std::collections::HashMap;

/// Generate mermaid xychart blocks from the run history.
pub fn generate_charts(db: &HistoryDb) -> anyhow::Result<String> {
    let runs = db.recent_runs(100)?;
    if runs.is_empty() {
        return Ok("_No benchmark runs yet._".to_string());
    }

    // Group runs by suite, ordered by time
    let mut by_suite: HashMap<String, Vec<(String, f64)>> = HashMap::new();
    for run in runs.iter().rev() {
        // Use short commit as label
        let label = if run.skwaq_commit.len() >= 6 {
            run.skwaq_commit[..6].to_string()
        } else {
            run.skwaq_commit.clone()
        };
        by_suite
            .entry(run.suite.clone())
            .or_default()
            .push((label, run.f1 * 100.0));
    }

    let mut charts = String::new();
    charts.push_str("### Score Trajectory Charts\n\n");

    // Per-suite trajectory charts
    for suite in ["fixtures", "juliet", "owasp", "cyberseceval", "cgc"] {
        if let Some(data) = by_suite.get(suite) {
            // Deduplicate: keep the latest score per commit
            let mut deduped: Vec<(String, f64)> = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for (label, f1) in data {
                if seen.insert(label.clone()) {
                    deduped.push((label.clone(), *f1));
                } else {
                    // Update to latest value for this commit
                    if let Some(entry) = deduped.iter_mut().find(|(l, _)| l == label) {
                        entry.1 = *f1;
                    }
                }
            }

            // Only show chart if we have 2+ data points
            if deduped.len() >= 2 {
                // Take last 10 data points max
                let recent: Vec<_> = deduped.iter().rev().take(10).rev().cloned().collect();
                let labels: Vec<String> =
                    recent.iter().map(|(l, _)| format!("\"{}\"", l)).collect();
                let values: Vec<String> = recent.iter().map(|(_, f)| format!("{:.0}", f)).collect();

                let max_y = recent
                    .iter()
                    .map(|(_, f)| *f)
                    .fold(0.0f64, f64::max)
                    .max(10.0);
                let y_max = ((max_y / 10.0).ceil() * 10.0) as u32;

                charts.push_str(&format!(
                    "```mermaid\nxychart-beta\n    title \"{} F1 Score Trajectory\"\n    x-axis [{}]\n    y-axis \"F1 (%)\" 0 --> {}\n    bar [{}]\n    line [{}]\n```\n\n",
                    suite_display_name(suite),
                    labels.join(", "),
                    y_max,
                    values.join(", "),
                    values.join(", "),
                ));
            }
        }
    }

    // Summary chart: latest score per suite
    let mut latest_scores: Vec<(&str, f64)> = Vec::new();
    for suite in ["fixtures", "juliet", "owasp", "cyberseceval", "cgc"] {
        if let Some(data) = by_suite.get(suite) {
            if let Some((_, f1)) = data.last() {
                latest_scores.push((suite, *f1));
            }
        }
    }

    if !latest_scores.is_empty() {
        let labels: Vec<String> = latest_scores
            .iter()
            .map(|(s, _)| format!("\"{}\"", suite_display_name(s)))
            .collect();
        let values: Vec<String> = latest_scores
            .iter()
            .map(|(_, f)| format!("{:.0}", f))
            .collect();

        charts.push_str(&format!(
            "```mermaid\nxychart-beta\n    title \"All Benchmarks - Current F1 Scores\"\n    x-axis [{}]\n    y-axis \"F1 (%)\" 0 --> 100\n    bar [{}]\n```\n\n",
            labels.join(", "),
            values.join(", "),
        ));
    }

    charts.push_str(
        "> Full interactive charts: [rysweet.github.io/skwaq](https://rysweet.github.io/skwaq/)\n",
    );

    Ok(charts)
}

/// Generate a scores table for the issue body.
pub fn generate_scores_table(db: &HistoryDb) -> anyhow::Result<String> {
    let runs = db.recent_runs(100)?;

    // Get latest run per suite
    let mut latest: HashMap<String, (f64, f64, f64, u32)> = HashMap::new();
    for run in &runs {
        latest
            .entry(run.suite.clone())
            .or_insert((run.precision, run.recall, run.f1, 0));
    }

    let mut table = String::new();
    table.push_str(
        "| Benchmark | F1 | Precision | Recall |\n|-----------|-----|-----------|--------|\n",
    );

    for suite in ["fixtures", "juliet", "owasp", "cyberseceval", "cgc"] {
        if let Some((p, r, f1, _)) = latest.get(suite) {
            table.push_str(&format!(
                "| **{}** | {:.1}% | {:.1}% | {:.1}% |\n",
                suite_display_name(suite),
                f1 * 100.0,
                p * 100.0,
                r * 100.0,
            ));
        }
    }

    Ok(table)
}

/// Generate JSON for eval release artifacts.
pub fn generate_eval_json(db: &HistoryDb) -> anyhow::Result<String> {
    let runs = db.recent_runs(100)?;

    let mut latest: HashMap<String, serde_json::Value> = HashMap::new();
    for run in &runs {
        latest.entry(run.suite.clone()).or_insert_with(|| {
            serde_json::json!({
                "f1": run.f1,
                "precision": run.precision,
                "recall": run.recall,
                "true_positives": run.true_positives,
                "false_positives": run.false_positives,
                "false_negatives": run.false_negatives,
                "true_negatives": run.true_negatives,
            })
        });
    }

    let result = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "benchmarks": latest,
    });

    Ok(serde_json::to_string_pretty(&result)?)
}

fn suite_display_name(suite: &str) -> &str {
    match suite {
        "fixtures" => "Fixtures",
        "juliet" => "Juliet",
        "owasp" => "OWASP",
        "cyberseceval" => "CyberSecEval",
        "cgc" => "CGC",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{BenchmarkRun, HistoryDb};
    use chrono::Utc;

    #[test]
    fn test_generate_charts_with_data() {
        let db = HistoryDb::in_memory().unwrap();

        // Add some runs
        let id1 = db.start_run("fixtures", "abc123").unwrap();
        db.finish_run(&BenchmarkRun {
            id: id1,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "fixtures".to_string(),
            skwaq_commit: "abc123".to_string(),
            precision: 0.67,
            recall: 0.40,
            f1: 0.50,
            true_positives: 2,
            false_positives: 1,
            false_negatives: 3,
            true_negatives: 0,
        })
        .unwrap();

        let id2 = db.start_run("fixtures", "def456").unwrap();
        db.finish_run(&BenchmarkRun {
            id: id2,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            suite: "fixtures".to_string(),
            skwaq_commit: "def456".to_string(),
            precision: 1.0,
            recall: 0.87,
            f1: 0.93,
            true_positives: 13,
            false_positives: 0,
            false_negatives: 2,
            true_negatives: 0,
        })
        .unwrap();

        let charts = generate_charts(&db).unwrap();
        assert!(
            charts.contains("xychart-beta"),
            "Should contain mermaid chart"
        );
        assert!(charts.contains("Fixtures"), "Should contain suite name");

        let table = generate_scores_table(&db).unwrap();
        assert!(
            table.contains("Fixtures"),
            "Table should contain suite name"
        );

        let json = generate_eval_json(&db).unwrap();
        assert!(json.contains("fixtures"), "JSON should contain suite");
    }

    #[test]
    fn test_generate_charts_empty() {
        let db = HistoryDb::in_memory().unwrap();
        let charts = generate_charts(&db).unwrap();
        assert!(
            charts.contains("No benchmark runs"),
            "Should handle empty DB"
        );
    }
}
