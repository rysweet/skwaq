//! Machine-readable JSON report generation.

use crate::scoring::AggregateScore;
use serde::Serialize;

#[derive(Serialize)]
pub struct JsonReport {
    pub suite: String,
    pub timestamp: String,
    pub skwaq_commit: String,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
    pub per_cwe: Vec<JsonCweResult>,
}

#[derive(Serialize)]
pub struct JsonCweResult {
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

pub fn generate(score: &AggregateScore, suite: &str, commit: &str) -> String {
    let report = JsonReport {
        suite: suite.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        skwaq_commit: commit.to_string(),
        precision: score.precision,
        recall: score.recall,
        f1: score.f1,
        true_positives: score.true_positives,
        false_positives: score.false_positives,
        false_negatives: score.false_negatives,
        true_negatives: score.true_negatives,
        per_cwe: score
            .per_cwe
            .values()
            .map(|c| JsonCweResult {
                cwe_id: c.cwe_id,
                total_cases: c.total_cases,
                true_positives: c.true_positives,
                false_positives: c.false_positives,
                false_negatives: c.false_negatives,
                detection_rate: c.detection_rate,
                precision: c.precision,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&report).unwrap_or_default()
}
