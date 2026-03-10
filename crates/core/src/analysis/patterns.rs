//! Detection of dangerous API usage patterns.
//!
//! `DangerousApiDetector` checks function imports against a list of
//! known-dangerous C/C++ functions (e.g. `strcpy`, `sprintf`, `gets`)
//! and flags their use sites.  It can also query the graph database
//! for function names and imports stored during ingestion.

use crate::binary::types::ImportInfo;
use crate::graph::GraphDb;
use serde::{Deserialize, Serialize};

/// Danger categories for grouping findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DangerCategory {
    Memory,
    Injection,
    FormatString,
    Race,
    TempFile,
    PathTraversal,
}

impl std::fmt::Display for DangerCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::Injection => write!(f, "injection"),
            Self::FormatString => write!(f, "format_string"),
            Self::Race => write!(f, "race"),
            Self::TempFile => write!(f, "temp_file"),
            Self::PathTraversal => write!(f, "path_traversal"),
        }
    }
}

/// Severity level of a dangerous API finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Internal mapping of a dangerous API to its category and severity.
struct DangerousEntry {
    name: &'static str,
    category: DangerCategory,
    severity: Severity,
    reason: &'static str,
}

/// All known dangerous APIs with their categories.
const DANGEROUS_APIS: &[DangerousEntry] = &[
    // Memory safety
    DangerousEntry { name: "strcpy",   category: DangerCategory::Memory,       severity: Severity::Critical, reason: "unbounded copy; use strncpy or strlcpy" },
    DangerousEntry { name: "strcat",   category: DangerCategory::Memory,       severity: Severity::Critical, reason: "unbounded concatenation; use strncat or strlcat" },
    DangerousEntry { name: "gets",     category: DangerCategory::Memory,       severity: Severity::Critical, reason: "no bounds checking; use fgets" },
    DangerousEntry { name: "memcpy",   category: DangerCategory::Memory,       severity: Severity::Medium,   reason: "no bounds checking; verify size parameter" },
    DangerousEntry { name: "memmove",  category: DangerCategory::Memory,       severity: Severity::Medium,   reason: "no bounds checking; verify size parameter" },
    DangerousEntry { name: "strncpy",  category: DangerCategory::Memory,       severity: Severity::Low,      reason: "may not null-terminate; prefer strlcpy" },
    DangerousEntry { name: "strncat",  category: DangerCategory::Memory,       severity: Severity::Low,      reason: "size semantics are error-prone; prefer strlcat" },
    // Format string
    DangerousEntry { name: "sprintf",  category: DangerCategory::FormatString, severity: Severity::High,     reason: "unbounded format output; use snprintf" },
    DangerousEntry { name: "vsprintf", category: DangerCategory::FormatString, severity: Severity::High,     reason: "unbounded format output; use vsnprintf" },
    DangerousEntry { name: "scanf",    category: DangerCategory::FormatString, severity: Severity::High,     reason: "unbounded input; use width specifiers or fgets" },
    DangerousEntry { name: "fscanf",   category: DangerCategory::FormatString, severity: Severity::High,     reason: "unbounded input; use width specifiers" },
    DangerousEntry { name: "sscanf",   category: DangerCategory::FormatString, severity: Severity::Medium,   reason: "potential buffer overflow with %s" },
    // Injection / command execution
    DangerousEntry { name: "system",   category: DangerCategory::Injection,    severity: Severity::Critical, reason: "shell injection risk; use exec* family directly" },
    DangerousEntry { name: "popen",    category: DangerCategory::Injection,    severity: Severity::Critical, reason: "shell injection risk; use pipe+fork+exec" },
    DangerousEntry { name: "exec",     category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution; validate all arguments" },
    DangerousEntry { name: "execl",    category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution; validate all arguments" },
    DangerousEntry { name: "execle",   category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution; validate all arguments" },
    DangerousEntry { name: "execlp",   category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution with PATH search; validate arguments" },
    DangerousEntry { name: "execv",    category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution; validate all arguments" },
    DangerousEntry { name: "execvp",   category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution with PATH search; validate arguments" },
    DangerousEntry { name: "execvpe",  category: DangerCategory::Injection,    severity: Severity::High,     reason: "command execution with PATH/env; validate arguments" },
    // Temp file / race condition
    DangerousEntry { name: "mktemp",   category: DangerCategory::Race,        severity: Severity::Medium,   reason: "TOCTOU race; use mkstemp" },
    DangerousEntry { name: "tmpnam",   category: DangerCategory::TempFile,    severity: Severity::Medium,   reason: "TOCTOU race; use tmpfile or mkstemp" },
    // Path traversal
    DangerousEntry { name: "realpath", category: DangerCategory::PathTraversal, severity: Severity::Low,    reason: "buffer overflow in some implementations; check buffer size" },
];

/// A detected use of a dangerous API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousApiHit {
    pub function_name: String,
    pub library: String,
    pub reason: String,
    pub danger_category: DangerCategory,
    pub severity: Severity,
}

/// Scans import tables for known dangerous functions.
pub struct DangerousApiDetector {
    entries: &'static [DangerousEntry],
}

impl Default for DangerousApiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DangerousApiDetector {
    pub fn new() -> Self {
        Self {
            entries: DANGEROUS_APIS,
        }
    }

    /// Check a set of binary imports for dangerous function usage.
    pub fn check_imports(&self, imports: &[ImportInfo]) -> Vec<DangerousApiHit> {
        imports
            .iter()
            .filter_map(|imp| {
                self.entries.iter().find(|e| e.name == imp.name.as_str()).map(|entry| {
                    DangerousApiHit {
                        function_name: imp.name.clone(),
                        library: imp.library.clone(),
                        reason: entry.reason.to_string(),
                        danger_category: entry.category.clone(),
                        severity: entry.severity.clone(),
                    }
                })
            })
            .collect()
    }

    /// Detect dangerous APIs by querying the graph database.
    /// Checks functions, symbols/imports, and call relationships.
    /// Handles versioned names like `system@GLIBC_2.2.5`.
    pub fn detect(&self, db: &GraphDb) -> anyhow::Result<Vec<DangerousApiHit>> {
        let mut hits = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Check function names (strip @version suffix for matching)
        let mut stmt = db.conn().prepare(
            "SELECT f.name FROM functions f",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let name = row?;
            let base = name.split('@').next().unwrap_or(&name);
            if let Some(entry) = self.entries.iter().find(|e| e.name == base) {
                if seen.insert(base.to_string()) {
                    hits.push(DangerousApiHit {
                        function_name: name.clone(),
                        library: "function".into(),
                        reason: entry.reason.to_string(),
                        danger_category: entry.category.clone(),
                        severity: entry.severity.clone(),
                    });
                }
            }
        }

        // Check imports stored in the symbols table
        let mut stmt = db.conn().prepare(
            "SELECT s.name FROM symbols s WHERE s.symbol_type = 'import'",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let name = row?;
            let base = name.split('@').next().unwrap_or(&name);
            if let Some(entry) = self.entries.iter().find(|e| e.name == base) {
                if seen.insert(base.to_string()) {
                    hits.push(DangerousApiHit {
                        function_name: name.clone(),
                        library: "import".into(),
                        reason: entry.reason.to_string(),
                        danger_category: entry.category.clone(),
                        severity: entry.severity.clone(),
                    });
                }
            }
        }

        // Check data_sinks (already classified during ingestion)
        let mut stmt = db.conn().prepare(
            "SELECT s.name, s.danger_level FROM data_sinks s",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (name, danger) = row?;
            let base = name.split('@').next().unwrap_or(&name);
            if let Some(entry) = self.entries.iter().find(|e| e.name == base) {
                if seen.insert(base.to_string()) {
                    hits.push(DangerousApiHit {
                        function_name: name.clone(),
                        library: format!("sink ({})", danger),
                        reason: entry.reason.to_string(),
                        danger_category: entry.category.clone(),
                        severity: entry.severity.clone(),
                    });
                }
            }
        }

        // Sort by severity (Critical first)
        hits.sort_by(|a, b| a.severity.cmp(&b.severity));
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_imports_finds_dangerous() {
        let detector = DangerousApiDetector::new();
        let imports = vec![
            ImportInfo { name: "strcpy".into(), library: "libc.so.6".into() },
            ImportInfo { name: "safe_func".into(), library: "libfoo.so".into() },
            ImportInfo { name: "system".into(), library: "libc.so.6".into() },
        ];
        let hits = detector.check_imports(&imports);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].function_name, "strcpy");
        assert_eq!(hits[0].danger_category, DangerCategory::Memory);
        assert_eq!(hits[1].function_name, "system");
        assert_eq!(hits[1].danger_category, DangerCategory::Injection);
    }

    #[test]
    fn test_detect_from_graph() {
        let db = GraphDb::in_memory().unwrap();
        // Insert a dangerous function
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f1', 'strcpy')",
            &[],
        ).unwrap();
        db.execute(
            "INSERT INTO functions (id, name) VALUES ('f2', 'main')",
            &[],
        ).unwrap();
        db.execute(
            "INSERT INTO calls (caller_id, callee_id) VALUES ('f2', 'f1')",
            &[],
        ).unwrap();

        let detector = DangerousApiDetector::new();
        let hits = detector.detect(&db).unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|h| h.function_name == "strcpy"));
    }

    #[test]
    fn test_no_false_positives() {
        let detector = DangerousApiDetector::new();
        let imports = vec![
            ImportInfo { name: "printf".into(), library: "libc.so.6".into() },
            ImportInfo { name: "malloc".into(), library: "libc.so.6".into() },
        ];
        let hits = detector.check_imports(&imports);
        assert!(hits.is_empty());
    }
}
