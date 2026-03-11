//! Binary-level dangerous API detection.
//!
//! `DangerousApiDetector` checks function imports against a list of
//! known-dangerous C/C++ functions and flags their use sites.

use super::patterns::{DangerousApiHit, DangerousEntry, DANGEROUS_APIS};
use crate::binary::types::ImportInfo;
use crate::graph::GraphDb;

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
                        file: String::new(),
                        line: 0,
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
                        file: String::new(),
                        line: 0,
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
                        file: String::new(),
                        line: 0,
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
                        file: String::new(),
                        line: 0,
                    });
                }
            }
        }

        // Sort by severity (Critical first)
        hits.sort_by(|a, b| a.severity.cmp(&b.severity));
        Ok(hits)
    }

    /// Detect dangerous patterns in a source file.
    ///
    /// Reads the file, detects its language, then scans for language-specific
    /// dangerous patterns using regex matching.
    pub fn detect_in_source(
        &self,
        source_path: &std::path::Path,
        language: &str,
    ) -> anyhow::Result<Vec<DangerousApiHit>> {
        let content = std::fs::read_to_string(source_path)
            .map_err(|e| anyhow::anyhow!("Cannot read {}: {}", source_path.display(), e))?;

        self.detect_in_source_content(&content, language, &source_path.display().to_string())
    }

    /// Detect dangerous patterns in source content already in memory.
    pub fn detect_in_source_content(
        &self,
        content: &str,
        language: &str,
        file_path: &str,
    ) -> anyhow::Result<Vec<DangerousApiHit>> {
        super::patterns_source::detect_in_source_content(content, language, file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::patterns::DangerCategory;

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
