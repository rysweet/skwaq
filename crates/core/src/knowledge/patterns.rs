//! Known vulnerability patterns used for matching against analysis findings.
//!
//! `VulnerabilityPatterns` holds a catalogue of common vulnerability
//! signatures (buffer overflows, format strings, use-after-free, etc.)
//! that can be matched against graph query results.

/// A single vulnerability pattern definition.
#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub cwe_ids: Vec<String>,
    pub indicators: Vec<String>,
}

/// Catalogue of known vulnerability patterns.
pub struct VulnerabilityPatterns {
    patterns: Vec<VulnerabilityPattern>,
}

impl VulnerabilityPatterns {
    /// Create a new empty pattern catalogue.
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Return all patterns whose indicators overlap with `terms`.
    pub fn match_indicators(&self, terms: &[&str]) -> Vec<&VulnerabilityPattern> {
        self.patterns
            .iter()
            .filter(|p| {
                p.indicators
                    .iter()
                    .any(|ind| terms.iter().any(|t| ind.contains(t)))
            })
            .collect()
    }
}

impl Default for VulnerabilityPatterns {
    fn default() -> Self {
        Self::new()
    }
}
