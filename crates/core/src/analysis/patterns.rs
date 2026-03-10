//! Detection of dangerous API usage patterns.
//!
//! `DangerousApiDetector` checks function imports against a list of
//! known-dangerous C/C++ functions (e.g. `strcpy`, `sprintf`, `gets`)
//! and flags their use sites.  It also scans source code in any supported
//! language for language-specific dangerous patterns (eval, command injection,
//! deserialization, etc.).

use crate::binary::types::ImportInfo;
use crate::graph::GraphDb;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Danger categories for grouping findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DangerCategory {
    Memory,
    Injection,
    FormatString,
    Race,
    TempFile,
    PathTraversal,
    Deserialization,
    Crypto,
    UnsafeCode,
    PrototypePollution,
    Xss,
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
            Self::Deserialization => write!(f, "deserialization"),
            Self::Crypto => write!(f, "crypto"),
            Self::UnsafeCode => write!(f, "unsafe_code"),
            Self::PrototypePollution => write!(f, "prototype_pollution"),
            Self::Xss => write!(f, "xss"),
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

/// All known dangerous C/C++ APIs with their categories.
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
    /// Source file where the hit was found (empty for binary-level detections).
    #[serde(default)]
    pub file: String,
    /// Line number in source file (0 for binary-level detections).
    #[serde(default)]
    pub line: usize,
}

// ---------------------------------------------------------------------------
// Language-specific dangerous patterns for source analysis
// ---------------------------------------------------------------------------

struct SourcePattern {
    regex: &'static str,
    category: DangerCategory,
    severity: Severity,
    reason: &'static str,
}

fn python_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern { regex: r"\beval\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "eval() executes arbitrary code; use ast.literal_eval() for data" },
        SourcePattern { regex: r"\bexec\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "exec() executes arbitrary code; avoid or sandbox" },
        SourcePattern { regex: r"\bos\.system\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "os.system() passes commands to shell; use subprocess with shell=False" },
        SourcePattern { regex: r"\bsubprocess\.call\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "subprocess.call may use shell; ensure shell=False and validate inputs" },
        SourcePattern { regex: r"\bsubprocess\.Popen\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "Popen may use shell; ensure shell=False and validate inputs" },
        SourcePattern { regex: r"\bpickle\.loads?\s*\(", category: DangerCategory::Deserialization, severity: Severity::Critical, reason: "pickle deserialization executes arbitrary code; use json or safe alternatives" },
        SourcePattern { regex: r"\byaml\.load\s*\(", category: DangerCategory::Deserialization, severity: Severity::High, reason: "yaml.load is unsafe; use yaml.safe_load" },
        SourcePattern { regex: r"\b__import__\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "__import__() can load arbitrary modules; validate input" },
        SourcePattern { regex: r"\bshelve\.open\s*\(", category: DangerCategory::Deserialization, severity: Severity::High, reason: "shelve uses pickle internally; avoid with untrusted data" },
        SourcePattern { regex: r"\bmarshall\.loads?\s*\(", category: DangerCategory::Deserialization, severity: Severity::High, reason: "marshal deserialization can execute code; use json" },
        SourcePattern { regex: r"\bcursor\.execute\s*\([^)]*%", category: DangerCategory::Injection, severity: Severity::Critical, reason: "SQL injection via string formatting; use parameterized queries" },
        SourcePattern { regex: r#"\bcursor\.execute\s*\([^)]*\+\s*"#, category: DangerCategory::Injection, severity: Severity::Critical, reason: "SQL injection via string concatenation; use parameterized queries" },
    ]
}

fn javascript_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern { regex: r"\beval\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "eval() executes arbitrary code; avoid entirely" },
        SourcePattern { regex: r"\.innerHTML\s*=", category: DangerCategory::Xss, severity: Severity::High, reason: "innerHTML can execute scripts; use textContent or sanitize" },
        SourcePattern { regex: r"\bdocument\.write\s*\(", category: DangerCategory::Xss, severity: Severity::High, reason: "document.write can inject scripts; use DOM API" },
        SourcePattern { regex: r"\bchild_process\.exec\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "child_process.exec uses shell; use execFile or spawn" },
        SourcePattern { regex: r"\bnew\s+Function\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "new Function() is eval-equivalent; avoid" },
        SourcePattern { regex: r#"\bsetTimeout\s*\(\s*['""]"#, category: DangerCategory::Injection, severity: Severity::High, reason: "setTimeout with string arg is eval-equivalent; pass a function reference" },
        SourcePattern { regex: r#"\bsetInterval\s*\(\s*['""]"#, category: DangerCategory::Injection, severity: Severity::High, reason: "setInterval with string arg is eval-equivalent; pass a function reference" },
        SourcePattern { regex: r"__proto__", category: DangerCategory::PrototypePollution, severity: Severity::High, reason: "prototype pollution via __proto__; validate or freeze prototypes" },
        SourcePattern { regex: r"\bconstructor\s*\[", category: DangerCategory::PrototypePollution, severity: Severity::High, reason: "prototype pollution via constructor; sanitize keys" },
    ]
}

fn go_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern { regex: r"\bexec\.Command\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "exec.Command runs external processes; validate arguments" },
        SourcePattern { regex: r"\btemplate\.HTML\s*\(", category: DangerCategory::Xss, severity: Severity::High, reason: "template.HTML bypasses escaping; sanitize input" },
        SourcePattern { regex: r#"\bsql\.Query\s*\([^)]*\+"#, category: DangerCategory::Injection, severity: Severity::Critical, reason: "SQL injection via concatenation; use parameterized queries" },
        SourcePattern { regex: r#"\bdb\.Exec\s*\([^)]*\+"#, category: DangerCategory::Injection, severity: Severity::Critical, reason: "SQL injection via concatenation; use parameterized queries" },
        SourcePattern { regex: r"\bhttp\.ListenAndServe\s*\(", category: DangerCategory::Crypto, severity: Severity::Medium, reason: "HTTP without TLS; use ListenAndServeTLS for production" },
    ]
}

fn rust_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern { regex: r"\bunsafe\s*\{", category: DangerCategory::UnsafeCode, severity: Severity::High, reason: "unsafe block bypasses Rust safety guarantees; minimize and audit" },
        SourcePattern { regex: r"\bCommand::new\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "Command::new runs external processes; validate arguments" },
        SourcePattern { regex: r"\.unwrap\s*\(\s*\)", category: DangerCategory::Memory, severity: Severity::Low, reason: ".unwrap() panics on error; consider .expect() or proper error handling" },
        SourcePattern { regex: r"\*\s*\w+\s+as\s+\*", category: DangerCategory::Memory, severity: Severity::High, reason: "raw pointer cast; ensure safety invariants" },
        SourcePattern { regex: r"std::mem::transmute", category: DangerCategory::Memory, severity: Severity::Critical, reason: "transmute bypasses type safety; use safe alternatives" },
    ]
}

fn java_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern { regex: r"\bRuntime\.getRuntime\(\)\.exec\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "Runtime.exec runs OS commands; validate all arguments" },
        SourcePattern { regex: r"\bProcessBuilder\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "ProcessBuilder runs OS commands; validate arguments" },
        SourcePattern { regex: r"\bStatement\.execute\s*\(", category: DangerCategory::Injection, severity: Severity::High, reason: "Statement.execute may be vulnerable to SQL injection; use PreparedStatement" },
        SourcePattern { regex: r"\bObjectInputStream\b", category: DangerCategory::Deserialization, severity: Severity::Critical, reason: "Java deserialization can execute code; use allowlists or safe formats" },
        SourcePattern { regex: r"\bJNDI\b|\bInitialContext\b", category: DangerCategory::Injection, severity: Severity::Critical, reason: "JNDI lookup can lead to remote code execution (Log4Shell class); validate inputs" },
        SourcePattern { regex: r"\bScriptEngine\b.*\beval\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "ScriptEngine.eval executes arbitrary code; avoid with untrusted input" },
    ]
}

fn c_cpp_patterns() -> &'static [SourcePattern] {
    &[
        SourcePattern { regex: r"\bstrcpy\s*\(", category: DangerCategory::Memory, severity: Severity::Critical, reason: "strcpy has no bounds checking; use strncpy or strlcpy" },
        SourcePattern { regex: r"\bsprintf\s*\(", category: DangerCategory::FormatString, severity: Severity::High, reason: "sprintf has no bounds checking; use snprintf" },
        SourcePattern { regex: r"\bgets\s*\(", category: DangerCategory::Memory, severity: Severity::Critical, reason: "gets has no bounds checking; use fgets" },
        SourcePattern { regex: r"\bsystem\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "system() passes to shell; use exec* family" },
        SourcePattern { regex: r"\bstrcat\s*\(", category: DangerCategory::Memory, severity: Severity::Critical, reason: "strcat has no bounds checking; use strncat or strlcat" },
        SourcePattern { regex: r"\bscanf\s*\(", category: DangerCategory::FormatString, severity: Severity::High, reason: "scanf with %s has no bounds; use width specifiers" },
        SourcePattern { regex: r"\bpopen\s*\(", category: DangerCategory::Injection, severity: Severity::Critical, reason: "popen passes to shell; use pipe+fork+exec" },
    ]
}

fn get_patterns_for_language(language: &str) -> &'static [SourcePattern] {
    match language {
        "python" => python_patterns(),
        "javascript" | "typescript" => javascript_patterns(),
        "go" => go_patterns(),
        "rust" => rust_patterns(),
        "java" => java_patterns(),
        "c" | "cpp" => c_cpp_patterns(),
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

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
        source_path: &Path,
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
        let patterns = get_patterns_for_language(language);
        let mut hits = Vec::new();

        for pat in patterns {
            let re = Regex::new(pat.regex)
                .map_err(|e| anyhow::anyhow!("Bad pattern {}: {}", pat.regex, e))?;

            for m in re.find_iter(content) {
                let byte_offset = m.start();
                let line = content[..byte_offset].matches('\n').count() + 1;
                let matched_text = m.as_str().trim().to_string();

                hits.push(DangerousApiHit {
                    function_name: matched_text,
                    library: format!("source:{}", language),
                    reason: pat.reason.to_string(),
                    danger_category: pat.category.clone(),
                    severity: pat.severity.clone(),
                    file: file_path.to_string(),
                    line,
                });
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

    #[test]
    fn test_detect_python_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
import os
user_input = input()
os.system("echo " + user_input)
eval(user_input)
pickle.loads(data)
"#;
        let hits = detector.detect_in_source_content(src, "python", "app.py").unwrap();
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Injection));
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Deserialization));
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_detect_javascript_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
const input = req.params.id;
eval(input);
document.innerHTML = input;
child_process.exec("ls " + input);
new Function(input);
"#;
        let hits = detector.detect_in_source_content(src, "javascript", "app.js").unwrap();
        assert!(hits.iter().any(|h| h.function_name.contains("eval")));
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Xss));
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_detect_rust_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
fn run(input: &str) {
    unsafe {
        let ptr = input.as_ptr();
    }
    Command::new(input).output().unwrap();
}
"#;
        let hits = detector.detect_in_source_content(src, "rust", "main.rs").unwrap();
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::UnsafeCode));
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Injection));
    }

    #[test]
    fn test_detect_go_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
func run(input string) {
    exec.Command(input).Run()
    template.HTML(input)
}
"#;
        let hits = detector.detect_in_source_content(src, "go", "main.go").unwrap();
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Injection));
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Xss));
    }

    #[test]
    fn test_detect_java_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
import java.io.ObjectInputStream;
Runtime.getRuntime().exec(cmd);
ObjectInputStream ois = new ObjectInputStream(in);
"#;
        let hits = detector.detect_in_source_content(src, "java", "Vuln.java").unwrap();
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Injection));
        assert!(hits.iter().any(|h| h.danger_category == DangerCategory::Deserialization));
    }

    #[test]
    fn test_detect_c_dangerous() {
        let detector = DangerousApiDetector::new();
        let src = r#"
void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
    sprintf(buf, "%s", input);
    system(input);
}
"#;
        let hits = detector.detect_in_source_content(src, "c", "vuln.c").unwrap();
        assert!(hits.iter().any(|h| h.function_name.contains("strcpy")));
        assert!(hits.iter().any(|h| h.function_name.contains("system")));
        assert!(hits.len() >= 3);
    }

    #[test]
    fn test_detect_source_no_false_positives() {
        let detector = DangerousApiDetector::new();
        let src = r#"
def safe_function():
    print("hello")
    x = 1 + 2
    return x
"#;
        let hits = detector.detect_in_source_content(src, "python", "safe.py").unwrap();
        assert!(hits.is_empty());
    }
}
