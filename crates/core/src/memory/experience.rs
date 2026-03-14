//! Experience data model for agent memory.

use serde::{Deserialize, Serialize};

/// The type of experience an agent recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExperienceType {
    /// A successful analysis outcome (true positive finding, correct classification).
    Success,
    /// A failed analysis outcome (false positive, missed vulnerability).
    Failure,
    /// A recognized recurring pattern across analyses.
    Pattern,
    /// A generalized insight or lesson learned.
    Insight,
}

impl ExperienceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Pattern => "pattern",
            Self::Insight => "insight",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "pattern" => Some(Self::Pattern),
            "insight" => Some(Self::Insight),
            _ => None,
        }
    }
}

/// A single unit of agent memory.
///
/// Experiences are investigation-independent: they capture generalized lessons
/// that help agents across different targets and benchmark runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experience {
    /// Unique identifier (auto-generated on insert).
    pub id: String,
    /// Which agent created this experience.
    pub agent: String,
    /// What type of experience this is.
    pub experience_type: ExperienceType,
    /// The situation or context that led to this experience.
    /// Should be generalized (no target-specific paths/addresses).
    pub context: String,
    /// What the agent learned or observed.
    pub outcome: String,
    /// Confidence in this experience (0.0–1.0). Decays over time.
    pub confidence: f64,
    /// Tags for categorization and filtering.
    pub tags: Vec<String>,
    /// ISO 8601 timestamp of when this was recorded.
    pub created_at: String,
    /// Number of times this experience has been recalled by an agent.
    pub recall_count: u32,
}

impl Experience {
    /// Compute a relevance score for this experience against a query.
    ///
    /// Uses keyword overlap between the query and the experience's context
    /// and outcome, weighted by confidence and type.
    pub fn relevance_to(&self, query: &str) -> f64 {
        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower
            .split_whitespace()
            .filter(|w| w.len() > 2)
            .collect();

        if query_words.is_empty() {
            return 0.0;
        }

        let text = format!("{} {} {}", self.context, self.outcome, self.tags.join(" "));
        let text_lower = text.to_lowercase();

        let matches = query_words
            .iter()
            .filter(|w| text_lower.contains(**w))
            .count();

        let keyword_score = matches as f64 / query_words.len() as f64;

        // Type weight: patterns and insights are more valuable than raw successes/failures
        let type_weight = match self.experience_type {
            ExperienceType::Pattern => 1.5,
            ExperienceType::Insight => 1.3,
            ExperienceType::Success => 1.0,
            ExperienceType::Failure => 1.1, // failures are slightly more informative
        };

        keyword_score * self.confidence * type_weight
    }
}
