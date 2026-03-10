//! CWE (Common Weakness Enumeration) database.
//!
//! `CweDatabase` loads CWE definitions and provides search capabilities
//! for mapping detected vulnerabilities to their CWE identifiers.

use serde::{Deserialize, Serialize};

/// An individual CWE entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweEntry {
    pub cwe_id: String,
    pub name: String,
    pub description: String,
}

/// In-memory CWE lookup database.
pub struct CweDatabase {
    entries: Vec<CweEntry>,
}

impl CweDatabase {
    /// Load CWE definitions from a JSON file or embedded data.
    pub fn load(_path: &str) -> anyhow::Result<Self> {
        todo!("CWE database loading not yet implemented")
    }

    /// Create an empty database (useful for tests).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Search for CWE entries matching a keyword.
    pub fn search(&self, keyword: &str) -> Vec<&CweEntry> {
        let kw = keyword.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.name.to_lowercase().contains(&kw)
                    || e.description.to_lowercase().contains(&kw)
                    || e.cwe_id.contains(&kw)
            })
            .collect()
    }
}
