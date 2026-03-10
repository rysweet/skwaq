//! Detection of dangerous API usage patterns.
//!
//! `DangerousApiDetector` checks function imports against a list of
//! known-dangerous C/C++ functions (e.g. `strcpy`, `sprintf`, `gets`)
//! and flags their use sites.

use crate::binary::types::ImportInfo;

/// List of C standard library functions considered dangerous.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "sprintf",
    "vsprintf",
    "gets",
    "scanf",
    "fscanf",
    "sscanf",
    "system",
    "popen",
    "exec",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execvp",
    "execvpe",
    "mktemp",
    "tmpnam",
    "realpath",
];

/// A detected use of a dangerous API.
#[derive(Debug, Clone)]
pub struct DangerousApiHit {
    pub function_name: String,
    pub library: String,
    pub reason: String,
}

/// Scans import tables for known dangerous functions.
pub struct DangerousApiDetector {
    dangerous: Vec<&'static str>,
}

impl Default for DangerousApiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DangerousApiDetector {
    pub fn new() -> Self {
        Self {
            dangerous: DANGEROUS_FUNCTIONS.to_vec(),
        }
    }

    /// Check a set of binary imports for dangerous function usage.
    pub fn check_imports(&self, imports: &[ImportInfo]) -> Vec<DangerousApiHit> {
        imports
            .iter()
            .filter_map(|imp| {
                if self.dangerous.contains(&imp.name.as_str()) {
                    Some(DangerousApiHit {
                        function_name: imp.name.clone(),
                        library: imp.library.clone(),
                        reason: format!(
                            "'{}' is a dangerous function; consider a safer alternative",
                            imp.name
                        ),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}
