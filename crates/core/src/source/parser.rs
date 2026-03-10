//! Source code parsing using tree-sitter.
//!
//! Provides AST extraction for supported languages (C, C++, Rust, Python, etc.)
//! so that function boundaries, call sites, and data flows can be fed into the
//! graph database.

use std::path::Path;

/// Parsed representation of a single source file.
#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub path: String,
    pub language: String,
    pub functions: Vec<ParsedFunction>,
}

/// A function extracted from source code.
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub calls: Vec<String>,
}

/// Parse a source file and extract functions and call sites.
///
/// Uses tree-sitter under the hood (to be wired up).
pub fn parse_file(_path: &Path) -> anyhow::Result<ParsedFile> {
    Err(anyhow::anyhow!("tree-sitter source parsing not yet implemented"))
}

/// Detect the programming language from a file extension.
pub fn detect_language(path: &Path) -> Option<&'static str> {
    match path.extension()?.to_str()? {
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" => Some("cpp"),
        "rs" => Some("rust"),
        "py" => Some("python"),
        "js" | "ts" => Some("javascript"),
        "go" => Some("go"),
        "java" => Some("java"),
        _ => None,
    }
}
