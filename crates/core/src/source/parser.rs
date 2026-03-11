//! Source code parsing using regex-based extraction.
//!
//! Provides function/method extraction, call-site detection, import discovery,
//! and string-literal extraction for popular languages: Python, JavaScript/TypeScript,
//! Go, Rust, Java, C, and C++.  Tree-sitter can be swapped in later for higher
//! fidelity; the API surface stays the same.

use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed representation of a single source file.
#[derive(Debug, Clone)]
pub struct ParsedSource {
    pub path: String,
    pub language: String,
    pub functions: Vec<ExtractedFunction>,
    pub calls: Vec<ExtractedCall>,
    pub imports: Vec<String>,
    pub string_literals: Vec<ExtractedString>,
}

/// A function/method extracted from source code.
#[derive(Debug, Clone)]
pub struct ExtractedFunction {
    pub name: String,
    pub line: usize,
    pub signature: String,
}

/// A function call extracted from source code.
#[derive(Debug, Clone)]
pub struct ExtractedCall {
    pub name: String,
    pub line: usize,
    /// The full call expression (e.g. `os.system("ls")`)
    pub expression: String,
}

/// A string literal found in source code.
#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub line: usize,
}

// ---------------------------------------------------------------------------
// Backward-compatible aliases (used by mod.rs re-exports)
// ---------------------------------------------------------------------------

/// Alias kept for backward compatibility with existing callers.
pub type ParsedFile = ParsedSource;

/// Alias kept for backward compatibility with existing callers.
pub type ParsedFunction = ExtractedFunction;

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

/// Detect the programming language from a file extension.
pub fn detect_language(path: &Path) -> Option<&'static str> {
    match path.extension()?.to_str()? {
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" => Some("cpp"),
        "rs" => Some("rust"),
        "py" | "pyw" => Some("python"),
        "js" | "mjs" | "cjs" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        "java" => Some("java"),
        _ => None,
    }
}

/// List of recognized source file extensions.
pub const SOURCE_EXTENSIONS: &[&str] = &[
    "py", "pyw", "js", "mjs", "cjs", "ts", "tsx", "go", "rs", "java", "c", "h", "cpp", "cc", "cxx",
    "hpp", "hh",
];

/// Return `true` when the path has a recognized source extension.
pub fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| SOURCE_EXTENSIONS.contains(&ext))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Parse a source file and extract functions, calls, imports, and strings.
pub fn parse_file(path: &Path) -> anyhow::Result<ParsedSource> {
    let language = detect_language(path)
        .ok_or_else(|| anyhow::anyhow!("Unsupported language for {:?}", path))?;

    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;

    parse_source(&content, language, &path.display().to_string())
}

/// Parse source content already in memory.
pub fn parse_source(content: &str, language: &str, path: &str) -> anyhow::Result<ParsedSource> {
    let functions = extract_functions(content, language);
    let calls = extract_calls(content, language);
    let imports = extract_imports(content, language);
    let string_literals = extract_strings(content);

    Ok(ParsedSource {
        path: path.to_string(),
        language: language.to_string(),
        functions,
        calls,
        imports,
        string_literals,
    })
}

// ---------------------------------------------------------------------------
// Function extraction per language
// ---------------------------------------------------------------------------

fn extract_functions(content: &str, language: &str) -> Vec<ExtractedFunction> {
    let patterns: Vec<Regex> = match language {
        "python" => vec![
            Regex::new(r"(?m)^\s*def\s+(\w+)\s*\(").expect("compile-time regex"),
            Regex::new(r"(?m)^\s*async\s+def\s+(\w+)\s*\(").expect("compile-time regex"),
        ],
        "javascript" | "typescript" => vec![
            Regex::new(r"(?m)\bfunction\s+(\w+)\s*\(").expect("compile-time regex"),
            Regex::new(r"(?m)(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(")
                .expect("compile-time regex"),
            Regex::new(r"(?m)(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function")
                .expect("compile-time regex"),
            Regex::new(r"(?m)^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{").expect("compile-time regex"),
        ],
        "go" => {
            vec![Regex::new(r"(?m)^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(").expect("compile-time regex")]
        }
        "rust" => {
            vec![Regex::new(r"(?m)(?:pub\s+)?(?:async\s+)?fn\s+(\w+)").expect("compile-time regex")]
        }
        "java" => {
            vec![
                Regex::new(r"(?m)(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(")
                    .expect("compile-time regex"),
            ]
        }
        "c" | "cpp" => vec![
            // Return type + name + paren – rough but effective for common patterns.
            Regex::new(r"(?m)^[\w*\s]+\s+(\w+)\s*\([^;]*\)\s*\{").expect("compile-time regex"),
        ],
        _ => vec![],
    };

    let mut result = Vec::new();
    let mut seen = HashSet::new();

    for pat in &patterns {
        for m in pat.captures_iter(content) {
            let name = m.get(1).expect("compile-time regex").as_str().to_string();
            let byte_offset = m.get(0).expect("compile-time regex").start();
            let line = content[..byte_offset].matches('\n').count() + 1;
            let sig = m
                .get(0)
                .expect("compile-time regex")
                .as_str()
                .trim()
                .to_string();

            if seen.insert((name.clone(), line)) {
                result.push(ExtractedFunction {
                    name,
                    line,
                    signature: sig,
                });
            }
        }
    }

    result.sort_by_key(|f| f.line);
    result
}

// ---------------------------------------------------------------------------
// Call-site extraction per language
// ---------------------------------------------------------------------------

fn extract_calls(content: &str, language: &str) -> Vec<ExtractedCall> {
    // Generic call pattern: word followed by `(`.
    // Excludes language keywords via a post-filter.
    let call_re = Regex::new(r"(?m)([\w.]+)\s*\(").expect("compile-time regex");

    let keywords: HashSet<&str> = match language {
        "python" => [
            "def", "class", "if", "elif", "while", "for", "with", "async", "await", "return",
            "import", "from", "except", "assert",
        ]
        .iter()
        .copied()
        .collect(),
        "javascript" | "typescript" => [
            "function",
            "if",
            "else",
            "while",
            "for",
            "switch",
            "case",
            "catch",
            "return",
            "typeof",
            "instanceof",
            "new",
            "class",
            "import",
            "from",
            "const",
            "let",
            "var",
        ]
        .iter()
        .copied()
        .collect(),
        "go" => [
            "func",
            "if",
            "else",
            "for",
            "switch",
            "case",
            "select",
            "return",
            "go",
            "defer",
            "range",
            "type",
            "struct",
            "interface",
        ]
        .iter()
        .copied()
        .collect(),
        "rust" => [
            "fn", "if", "else", "while", "for", "loop", "match", "return", "let", "mut", "pub",
            "mod", "use", "struct", "enum", "impl", "trait", "type", "where", "async", "await",
            "unsafe",
        ]
        .iter()
        .copied()
        .collect(),
        "java" => [
            "if",
            "else",
            "while",
            "for",
            "switch",
            "case",
            "catch",
            "return",
            "class",
            "interface",
            "new",
            "import",
            "package",
            "throw",
            "throws",
            "instanceof",
        ]
        .iter()
        .copied()
        .collect(),
        "c" | "cpp" => [
            "if",
            "else",
            "while",
            "for",
            "switch",
            "case",
            "return",
            "sizeof",
            "typeof",
            "struct",
            "union",
            "enum",
            "class",
            "template",
            "namespace",
        ]
        .iter()
        .copied()
        .collect(),
        _ => HashSet::new(),
    };

    let mut result = Vec::new();

    for m in call_re.captures_iter(content) {
        let full = m.get(1).expect("compile-time regex").as_str();
        // Last segment after any `.` chains.
        let leaf = full.rsplit('.').next().unwrap_or(full);
        if keywords.contains(leaf) {
            continue;
        }
        let byte_offset = m.get(0).expect("compile-time regex").start();
        let line = content[..byte_offset].matches('\n').count() + 1;
        let expression = m
            .get(0)
            .expect("compile-time regex")
            .as_str()
            .trim()
            .to_string();

        result.push(ExtractedCall {
            name: full.to_string(),
            line,
            expression,
        });
    }

    result
}

// ---------------------------------------------------------------------------
// Import extraction per language
// ---------------------------------------------------------------------------

fn extract_imports(content: &str, language: &str) -> Vec<String> {
    let patterns: Vec<Regex> = match language {
        "python" => vec![
            Regex::new(r"(?m)^\s*import\s+([\w.]+)").expect("compile-time regex"),
            Regex::new(r"(?m)^\s*from\s+([\w.]+)\s+import").expect("compile-time regex"),
        ],
        "javascript" | "typescript" => vec![
            Regex::new(r#"(?m)(?:import|require)\s*\(?['"]([^'"]+)['"]\)?"#)
                .expect("compile-time regex"),
            Regex::new(r#"(?m)import\s+.*\s+from\s+['"]([^'"]+)['"]"#).expect("compile-time regex"),
        ],
        "go" => vec![
            Regex::new(r#"(?m)import\s+"([^"]+)""#).expect("compile-time regex"),
            Regex::new(r#"(?m)\s+"([^"]+)""#).expect("compile-time regex"), // inside import block
        ],
        "rust" => vec![
            Regex::new(r"(?m)^\s*use\s+([\w:]+)").expect("compile-time regex"),
            Regex::new(r"(?m)^\s*extern\s+crate\s+(\w+)").expect("compile-time regex"),
        ],
        "java" => vec![Regex::new(r"(?m)^\s*import\s+([\w.]+);").expect("compile-time regex")],
        "c" | "cpp" => {
            vec![Regex::new(r#"(?m)^\s*#\s*include\s+[<"]([^>"]+)[>"]"#)
                .expect("compile-time regex")]
        }
        _ => vec![],
    };

    let mut result = Vec::new();
    let mut seen = HashSet::new();

    for pat in &patterns {
        for m in pat.captures_iter(content) {
            let imp = m.get(1).expect("compile-time regex").as_str().to_string();
            if seen.insert(imp.clone()) {
                result.push(imp);
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// String literal extraction (language-agnostic)
// ---------------------------------------------------------------------------

fn extract_strings(content: &str) -> Vec<ExtractedString> {
    // Matches double-quoted and single-quoted strings (non-greedy).
    // Does not handle multi-line strings or escaped quotes perfectly,
    // but catches the common cases.
    let re =
        Regex::new(r#"(?m)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"#).expect("compile-time regex");

    let mut result = Vec::new();
    for m in re.captures_iter(content) {
        let raw = m.get(1).expect("compile-time regex").as_str();
        // Strip quotes.
        if raw.len() >= 2 {
            let value = &raw[1..raw.len() - 1];
            // Skip tiny strings.
            if value.len() < 3 {
                continue;
            }
            let byte_offset = m.get(0).expect("compile-time regex").start();
            let line = content[..byte_offset].matches('\n').count() + 1;
            result.push(ExtractedString {
                value: value.to_string(),
                line,
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language_python() {
        assert_eq!(detect_language(Path::new("app.py")), Some("python"));
    }

    #[test]
    fn test_detect_language_rust() {
        assert_eq!(detect_language(Path::new("main.rs")), Some("rust"));
    }

    #[test]
    fn test_detect_language_js() {
        assert_eq!(detect_language(Path::new("index.js")), Some("javascript"));
    }

    #[test]
    fn test_detect_language_ts() {
        assert_eq!(detect_language(Path::new("app.ts")), Some("typescript"));
    }

    #[test]
    fn test_detect_language_go() {
        assert_eq!(detect_language(Path::new("main.go")), Some("go"));
    }

    #[test]
    fn test_detect_language_java() {
        assert_eq!(detect_language(Path::new("Main.java")), Some("java"));
    }

    #[test]
    fn test_detect_language_unknown() {
        assert_eq!(detect_language(Path::new("data.csv")), None);
    }

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("foo.py")));
        assert!(is_source_file(Path::new("bar.rs")));
        assert!(!is_source_file(Path::new("readme.md")));
    }

    #[test]
    fn test_parse_python() {
        let src = r#"
import os
from subprocess import call

def handler(request):
    name = request.args.get("name")
    os.system("echo " + name)
    eval(name)

async def helper():
    pass
"#;
        let parsed = parse_source(src, "python", "app.py").expect("compile-time regex");
        assert_eq!(parsed.language, "python");
        assert!(parsed.functions.len() >= 2);
        assert!(parsed.functions.iter().any(|f| f.name == "handler"));
        assert!(parsed.functions.iter().any(|f| f.name == "helper"));

        assert!(parsed.imports.iter().any(|i| i == "os"));
        assert!(parsed.imports.iter().any(|i| i == "subprocess"));

        assert!(parsed.calls.iter().any(|c| c.name == "os.system"));
        assert!(parsed.calls.iter().any(|c| c.name == "eval"));
    }

    #[test]
    fn test_parse_javascript() {
        let src = r#"
const express = require('express');

function handleRequest(req, res) {
    const input = req.params.id;
    eval(input);
    res.send(document.write(input));
}

const helper = (x) => {
    return x + 1;
};
"#;
        let parsed = parse_source(src, "javascript", "app.js").expect("compile-time regex");
        assert!(parsed.functions.iter().any(|f| f.name == "handleRequest"));
        assert!(parsed.calls.iter().any(|c| c.name == "eval"));
    }

    #[test]
    fn test_parse_rust() {
        let src = r#"
use std::process::Command;

pub fn run_cmd(input: &str) {
    let output = Command::new(input)
        .output()
        .expect("compile-time regex");
}

fn helper() -> bool {
    true
}
"#;
        let parsed = parse_source(src, "rust", "main.rs").expect("compile-time regex");
        assert!(parsed.functions.iter().any(|f| f.name == "run_cmd"));
        assert!(parsed.functions.iter().any(|f| f.name == "helper"));
        assert!(parsed.imports.iter().any(|i| i.contains("std")));
    }

    #[test]
    fn test_parse_go() {
        let src = r#"
package main

import "os/exec"

func RunCommand(input string) {
    exec.Command(input).Run()
}
"#;
        let parsed = parse_source(src, "go", "main.go").expect("compile-time regex");
        assert!(parsed.functions.iter().any(|f| f.name == "RunCommand"));
        assert!(parsed.imports.iter().any(|i| i == "os/exec"));
    }

    #[test]
    fn test_parse_java() {
        let src = r#"
import java.lang.Runtime;

public class Vuln {
    public void execute(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}
"#;
        let parsed = parse_source(src, "java", "Vuln.java").expect("compile-time regex");
        assert!(parsed.functions.iter().any(|f| f.name == "execute"));
        assert!(parsed.imports.iter().any(|i| i.contains("Runtime")));
    }

    #[test]
    fn test_extract_strings() {
        let src = r#"
let msg = "hello world";
let other = 'single quotes here';
let tiny = "ab";
"#;
        let strings = extract_strings(src);
        assert!(strings.iter().any(|s| s.value == "hello world"));
        assert!(strings.iter().any(|s| s.value == "single quotes here"));
        // "ab" is too short (< 3 chars), should be filtered.
        assert!(!strings.iter().any(|s| s.value == "ab"));
    }
}
