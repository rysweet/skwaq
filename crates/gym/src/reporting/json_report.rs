//! Machine-readable JSON report generation.

use crate::history::RunMetadata;
use crate::scoring::AggregateScore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonReport {
    pub suite: String,
    pub timestamp: String,
    pub skwaq_commit: String,
    pub metadata: RunMetadata,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
    pub per_cwe: Vec<JsonCweResult>,
    #[serde(default)]
    pub per_semantic: Vec<JsonSemanticResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonCweResult {
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonSemanticResult {
    pub class_name: String,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

pub fn generate(
    score: &AggregateScore,
    suite: &str,
    commit: &str,
    metadata: &RunMetadata,
) -> anyhow::Result<String> {
    let mut per_cwe: Vec<_> = score.per_cwe.values().collect();
    per_cwe.sort_by_key(|c| c.cwe_id);

    let mut per_semantic: Vec<_> = score.per_semantic.values().collect();
    per_semantic.sort_by(|a, b| a.class_name.cmp(&b.class_name));

    let report = JsonReport {
        suite: suite.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        skwaq_commit: commit.to_string(),
        metadata: metadata.clone(),
        precision: score.precision,
        recall: score.recall,
        f1: score.f1,
        true_positives: score.true_positives,
        false_positives: score.false_positives,
        false_negatives: score.false_negatives,
        true_negatives: score.true_negatives,
        per_cwe: per_cwe
            .into_iter()
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
        per_semantic: per_semantic
            .into_iter()
            .map(|s| JsonSemanticResult {
                class_name: s.class_name.clone(),
                total_cases: s.total_cases,
                true_positives: s.true_positives,
                false_positives: s.false_positives,
                false_negatives: s.false_negatives,
                detection_rate: s.detection_rate,
                precision: s.precision,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&report).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::{AggregateScore, SemanticScore};

    #[test]
    fn test_generate_includes_semantic_metrics() {
        let mut score = AggregateScore::default();
        score.per_semantic.insert(
            "buffer_overflow".to_string(),
            SemanticScore {
                class_name: "buffer_overflow".to_string(),
                total_cases: 1,
                true_positives: 1,
                false_positives: 0,
                false_negatives: 0,
                detection_rate: 1.0,
                precision: 1.0,
            },
        );

        let json = generate(&score, "fixtures", "abc123", &RunMetadata::default()).unwrap();
        let report: JsonReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.per_semantic.len(), 1);
        assert_eq!(report.per_semantic[0].class_name, "buffer_overflow");
    }

    #[test]
    fn test_old_json_without_per_semantic_still_parses() {
        let json = r#"{
          "suite": "fixtures",
          "timestamp": "2026-01-01T00:00:00Z",
          "skwaq_commit": "abc123",
          "metadata": {
            "llm_backend": "",
            "llm_model": "",
            "run_mode": "",
            "binary_mode": false,
            "git_dirty": false,
            "concurrency": 1,
            "skip": 0,
            "max_cases": null
          },
          "precision": 1.0,
          "recall": 1.0,
          "f1": 1.0,
          "true_positives": 1,
          "false_positives": 0,
          "false_negatives": 0,
          "true_negatives": 0,
          "per_cwe": []
        }"#;

        let report: JsonReport = serde_json::from_str(json).unwrap();
        assert!(report.per_semantic.is_empty());
    }

    #[test]
    fn test_generate_sorts_semantic_metrics_by_class_name() {
        let mut score = AggregateScore::default();
        score.per_semantic.insert(
            "zeta".to_string(),
            SemanticScore {
                class_name: "zeta".to_string(),
                total_cases: 1,
                true_positives: 1,
                false_positives: 0,
                false_negatives: 0,
                detection_rate: 1.0,
                precision: 1.0,
            },
        );
        score.per_semantic.insert(
            "alpha".to_string(),
            SemanticScore {
                class_name: "alpha".to_string(),
                total_cases: 1,
                true_positives: 1,
                false_positives: 0,
                false_negatives: 0,
                detection_rate: 1.0,
                precision: 1.0,
            },
        );

        let json = generate(&score, "fixtures", "abc123", &RunMetadata::default()).unwrap();
        let report: JsonReport = serde_json::from_str(&json).unwrap();
        let names: Vec<_> = report
            .per_semantic
            .into_iter()
            .map(|entry| entry.class_name)
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }
}
