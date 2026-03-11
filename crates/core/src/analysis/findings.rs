//! Finding model with status tracking across analysis cycles.
//!
//! Findings are the core output of multi-cycle analysis. Each finding
//! tracks its lifecycle: discovered in one cycle, then confirmed,
//! challenged, or invalidated by subsequent cycles.

use serde::{Deserialize, Serialize};

/// Status of a finding as it progresses through analysis cycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    /// Just discovered in the current cycle.
    New,
    /// Validated by a subsequent cycle.
    Confirmed,
    /// Another perspective disagrees with this finding.
    Challenged,
    /// Proven to be a false positive.
    Invalidated,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Confirmed => write!(f, "confirmed"),
            Self::Challenged => write!(f, "challenged"),
            Self::Invalidated => write!(f, "invalidated"),
        }
    }
}

impl FindingStatus {
    /// Parse a status string back into the enum.
    pub fn parse(s: &str) -> Self {
        match s {
            "confirmed" => Self::Confirmed,
            "challenged" => Self::Challenged,
            "invalidated" => Self::Invalidated,
            _ => Self::New,
        }
    }
}

/// Location of a finding within the analyzed binary or source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocation {
    /// File or binary path.
    pub file: String,
    /// Function name where the finding occurs.
    pub function: String,
    /// Source line number, if available.
    pub line: Option<u32>,
    /// Binary address, if available.
    pub address: Option<String>,
}

/// A single analysis finding with lifecycle tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: String,
    /// Short title describing the issue.
    pub title: String,
    /// Detailed description of the finding.
    pub description: String,
    /// Severity level (critical, high, medium, low).
    pub severity: String,
    /// Category of the finding (memory, injection, format_string, etc.).
    pub category: String,
    /// Where in the code the finding was detected.
    pub location: FindingLocation,
    /// Supporting evidence for this finding.
    pub evidence: Vec<String>,
    /// Current status in the analysis lifecycle.
    pub status: FindingStatus,
    /// Cycle number when this finding was first discovered.
    pub cycle_discovered: u32,
    /// Cycle number when this finding was last updated.
    pub cycle_last_updated: u32,
}

/// An update to an existing finding from a subsequent cycle.
#[derive(Debug, Clone)]
pub struct FindingUpdate {
    /// ID of the finding being updated.
    pub finding_id: String,
    /// New status for the finding.
    pub new_status: FindingStatus,
    /// Reason for the status change.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_status_display() {
        assert_eq!(FindingStatus::New.to_string(), "new");
        assert_eq!(FindingStatus::Confirmed.to_string(), "confirmed");
        assert_eq!(FindingStatus::Challenged.to_string(), "challenged");
        assert_eq!(FindingStatus::Invalidated.to_string(), "invalidated");
    }

    #[test]
    fn test_finding_status_from_str() {
        assert_eq!(FindingStatus::parse("confirmed"), FindingStatus::Confirmed);
        assert_eq!(
            FindingStatus::parse("challenged"),
            FindingStatus::Challenged
        );
        assert_eq!(
            FindingStatus::parse("invalidated"),
            FindingStatus::Invalidated
        );
        assert_eq!(FindingStatus::parse("new"), FindingStatus::New);
        assert_eq!(FindingStatus::parse("unknown"), FindingStatus::New);
    }

    #[test]
    fn test_finding_creation() {
        let finding = Finding {
            id: "f1".to_string(),
            title: "Dangerous strcpy".to_string(),
            description: "Use of strcpy without bounds checking".to_string(),
            severity: "critical".to_string(),
            category: "memory".to_string(),
            location: FindingLocation {
                file: "test.bin".to_string(),
                function: "process_input".to_string(),
                line: None,
                address: Some("0x401000".to_string()),
            },
            evidence: vec!["strcpy called with user input".to_string()],
            status: FindingStatus::New,
            cycle_discovered: 1,
            cycle_last_updated: 1,
        };
        assert_eq!(finding.status, FindingStatus::New);
        assert_eq!(finding.cycle_discovered, 1);
    }
}
