//! Pattern detection: recognizes recurring patterns from agent experiences.
//!
//! When the same type of discovery appears multiple times across different
//! investigations, the pattern detector promotes it to a high-confidence
//! generalized pattern. This is the key anti-overfitting mechanism: only
//! patterns that recur across diverse targets become durable memories.

use super::experience::ExperienceType;
use super::store::MemoryStore;

/// Minimum number of similar experiences before a pattern is recognized.
const PATTERN_THRESHOLD: usize = 3;

/// Maximum confidence for auto-detected patterns (capped to prevent overfit).
const MAX_PATTERN_CONFIDENCE: f64 = 0.95;

/// Minimum generalization score (0.0–1.0) for an experience to be stored
/// at full confidence. Below this threshold, the experience is flagged as
/// likely benchmark-specific overfitting.
const MIN_GENERALIZATION_SCORE: f64 = 0.5;

/// Detects and promotes recurring patterns from agent experiences.
pub struct PatternDetector<'a> {
    store: &'a MemoryStore,
}

impl<'a> PatternDetector<'a> {
    pub fn new(store: &'a MemoryStore) -> Self {
        Self { store }
    }

    /// Scan an agent's experiences for recurring patterns and promote them.
    ///
    /// Looks for clusters of SUCCESS experiences with overlapping tags.
    /// When a cluster reaches `PATTERN_THRESHOLD`, creates a PATTERN experience
    /// summarizing the generalized lesson.
    ///
    /// Returns the number of new patterns detected.
    pub fn detect_patterns(&self, agent: &str) -> anyhow::Result<u32> {
        let successes = self
            .store
            .recall_recent(agent, 500, Some(ExperienceType::Success))?;

        if successes.len() < PATTERN_THRESHOLD {
            return Ok(0);
        }

        // Group by overlapping tags
        let mut tag_groups: std::collections::HashMap<String, Vec<&super::experience::Experience>> =
            std::collections::HashMap::new();

        for exp in &successes {
            for tag in &exp.tags {
                tag_groups.entry(tag.clone()).or_default().push(exp);
            }
        }

        let existing_patterns =
            self.store
                .recall_recent(agent, 1000, Some(ExperienceType::Pattern))?;

        let mut new_patterns = 0u32;

        for (tag, group) in &tag_groups {
            if group.len() < PATTERN_THRESHOLD {
                continue;
            }

            // Check if we already have a pattern for this tag
            let already_exists = existing_patterns.iter().any(|p| p.tags.contains(tag));

            if already_exists {
                continue;
            }

            // Build a generalized pattern from the cluster
            let confidence = compute_pattern_confidence(group.len());
            let context = format!(
                "Recurring pattern across {} analyses involving '{}'",
                group.len(),
                tag
            );
            let outcome = generalize_outcomes(group);

            self.store.store(
                agent,
                ExperienceType::Pattern,
                &context,
                &outcome,
                confidence,
                &[tag.as_str()],
            )?;

            new_patterns += 1;
        }

        Ok(new_patterns)
    }

    /// Check if a new experience overlaps significantly with existing patterns.
    ///
    /// Returns true if the experience is likely benchmark-specific and should
    /// have its confidence reduced. This is the generalization filter.
    pub fn is_likely_overfit(
        &self,
        agent: &str,
        context: &str,
        tags: &[&str],
    ) -> anyhow::Result<bool> {
        // Heuristics for overfitting:
        // 1. Context contains specific addresses (0x...) — too target-specific
        if context.contains("0x") && context.len() < 100 {
            return Ok(true);
        }

        // 2. Context contains specific file paths
        if context.contains('/') && context.matches('/').count() > 2 {
            return Ok(true);
        }

        // 3. Context contains benchmark-specific identifiers (CGC challenge names,
        //    specific binary names, test case IDs)
        if generalization_score(context) < MIN_GENERALIZATION_SCORE {
            return Ok(true);
        }

        // 4. Too many experiences with the same tags from the same agent
        //    (suggests the agent is memorizing a specific benchmark's patterns)
        for tag in tags {
            let count: u32 = self
                .store
                .recall_recent(agent, 100, Some(ExperienceType::Success))?
                .iter()
                .filter(|e| e.tags.iter().any(|t| t == *tag))
                .count() as u32;

            if count > 20 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Compute confidence for a pattern based on how many times it was observed.
fn compute_pattern_confidence(occurrences: usize) -> f64 {
    let base = 0.5 + (occurrences as f64 * 0.1);
    base.min(MAX_PATTERN_CONFIDENCE)
}

/// Score how generalized a context string is (0.0 = very specific, 1.0 = fully general).
///
/// Penalizes benchmark-specific identifiers: hex addresses, specific file paths,
/// CGC challenge names, test case IDs, and other target-specific tokens.
fn generalization_score(context: &str) -> f64 {
    let words: Vec<&str> = context.split_whitespace().collect();
    if words.is_empty() {
        return 0.0;
    }

    let mut penalties = 0.0_f64;
    let total = words.len() as f64;

    for word in &words {
        let w = word.to_lowercase();
        let is_hex_addr = w.starts_with("0x") && w.len() > 4;
        let is_benchmark_id =
            w.contains('_') && w.chars().filter(|c| c.is_ascii_digit()).count() > 3;
        let is_abs_path = w.starts_with('/') && w.matches('/').count() > 1;
        let is_decompiler_name = (w.starts_with("fun_") || w.starts_with("sub_")) && w.len() > 4;

        if is_hex_addr || is_benchmark_id || is_abs_path {
            penalties += 2.0;
        } else if is_decompiler_name {
            penalties += 1.5;
        }
    }

    (1.0 - (penalties / total)).max(0.0)
}

/// Strip benchmark-specific details from a context string.
///
/// Removes hex addresses, absolute paths, CGC/benchmark identifiers, and
/// decompiler-generated names, replacing them with generic placeholders.
/// Keeps the text readable and useful as a generalized lesson.
pub fn strip_benchmark_specifics(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for word in text.split_whitespace() {
        let w = word.to_lowercase();
        let replacement = if w.starts_with("0x") && w.len() > 4 {
            "<addr>"
        } else if w.starts_with('/') && w.matches('/').count() > 1 {
            "<path>"
        } else if w.contains('_') && w.chars().filter(|c| c.is_ascii_digit()).count() > 3 {
            "<id>"
        } else if (w.starts_with("fun_") || w.starts_with("sub_")) && w.len() > 4 {
            "<func>"
        } else {
            word
        };

        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(replacement);
    }
    result
}

/// Generalize the outcomes of a group of experiences into a single description.
fn generalize_outcomes(group: &[&super::experience::Experience]) -> String {
    if group.is_empty() {
        return String::new();
    }

    // Take the first few outcomes as representative examples
    let examples: Vec<&str> = group.iter().take(3).map(|e| e.outcome.as_str()).collect();

    format!(
        "Observed {} times. Examples: {}",
        group.len(),
        examples.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_patterns_below_threshold() {
        let store = MemoryStore::in_memory().unwrap();
        store
            .store(
                "agent",
                ExperienceType::Success,
                "ctx",
                "out",
                0.8,
                &["tag1"],
            )
            .unwrap();

        let detector = PatternDetector::new(&store);
        let new = detector.detect_patterns("agent").unwrap();
        assert_eq!(new, 0);
    }

    #[test]
    fn test_detect_patterns_above_threshold() {
        let store = MemoryStore::in_memory().unwrap();

        for i in 0..5 {
            store
                .store(
                    "agent",
                    ExperienceType::Success,
                    &format!("buffer overflow case {i}"),
                    &format!("CWE-120 found in function_{i}"),
                    0.8,
                    &["buffer-overflow"],
                )
                .unwrap();
        }

        let detector = PatternDetector::new(&store);
        let new = detector.detect_patterns("agent").unwrap();
        assert_eq!(new, 1);

        // Verify pattern was created
        let patterns = store
            .recall_recent("agent", 10, Some(ExperienceType::Pattern))
            .unwrap();
        assert_eq!(patterns.len(), 1);
        assert!(patterns[0].context.contains("buffer-overflow"));
    }

    #[test]
    fn test_is_likely_overfit_address() {
        let store = MemoryStore::in_memory().unwrap();
        let detector = PatternDetector::new(&store);

        assert!(detector
            .is_likely_overfit("agent", "overflow at 0x401234", &[])
            .unwrap());
    }

    #[test]
    fn test_is_likely_overfit_path() {
        let store = MemoryStore::in_memory().unwrap();
        let detector = PatternDetector::new(&store);

        assert!(detector
            .is_likely_overfit("agent", "found in /home/user/project/src/main.c", &[])
            .unwrap());
    }

    #[test]
    fn test_not_overfit_general_context() {
        let store = MemoryStore::in_memory().unwrap();
        let detector = PatternDetector::new(&store);

        assert!(!detector
            .is_likely_overfit(
                "agent",
                "strcpy called with unsanitized network input leads to buffer overflow",
                &["buffer-overflow"],
            )
            .unwrap());
    }

    #[test]
    fn test_pattern_confidence_scaling() {
        assert!(compute_pattern_confidence(3) < compute_pattern_confidence(10));
        assert!(compute_pattern_confidence(100) <= MAX_PATTERN_CONFIDENCE);
    }

    #[test]
    fn test_generalization_score_general_context() {
        let score = generalization_score(
            "strcpy called with unsanitized network input leads to buffer overflow",
        );
        assert!(
            score >= MIN_GENERALIZATION_SCORE,
            "General context should pass: {score}"
        );
    }

    #[test]
    fn test_generalization_score_specific_addresses() {
        let score = generalization_score("overflow at 0x401234 in 0x402000 called from 0x403000");
        assert!(
            score < MIN_GENERALIZATION_SCORE,
            "Address-heavy context should fail: {score}"
        );
    }

    #[test]
    fn test_generalization_score_benchmark_ids() {
        let score = generalization_score("CADET_00001 test case cb_12345 showed buffer overflow");
        assert!(
            score < MIN_GENERALIZATION_SCORE,
            "Benchmark ID context should fail: {score}"
        );
    }

    #[test]
    fn test_generalization_score_mixed() {
        // Mostly general with one specific token — should still pass
        let score = generalization_score(
            "buffer overflow via unchecked memcpy with user controlled length parameter in network parsing code",
        );
        assert!(
            score >= MIN_GENERALIZATION_SCORE,
            "Mostly general context should pass: {score}"
        );
    }
}
