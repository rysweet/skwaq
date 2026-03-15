//! Semantic pattern-class detection for aligning findings across analysis layers.
//!
//! These classes are intentionally benchmark-agnostic. They represent stable
//! vulnerability concepts that can be inferred from syntactic hits, graph-based
//! findings, or LLM-produced finding text without hard-coding benchmark names.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A stable semantic class for a vulnerability pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticPatternClass {
    BufferOverflow,
    CommandInjection,
    FormatString,
    InsecureTempFile,
    PathTraversal,
    RaceCondition,
    UseAfterFree,
}

impl SemanticPatternClass {
    /// Stable identifier suitable for logs, prompts, and deduplication keys.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BufferOverflow => "buffer_overflow",
            Self::CommandInjection => "command_injection",
            Self::FormatString => "format_string",
            Self::InsecureTempFile => "insecure_temp_file",
            Self::PathTraversal => "path_traversal",
            Self::RaceCondition => "race_condition",
            Self::UseAfterFree => "use_after_free",
        }
    }
}

/// Stateless classifier for inferring semantic pattern classes from findings.
#[derive(Debug, Default, Clone, Copy)]
pub struct SemanticPatternClassifier;

impl SemanticPatternClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify a finding from its coarse category plus any title/function hints.
    pub fn classify(
        &self,
        category: &str,
        title: &str,
        function_name: &str,
    ) -> BTreeSet<SemanticPatternClass> {
        let category = normalize_text(category);
        let title = normalize_text(title);
        let function_name = normalize_symbol(function_name);
        let mut classes = BTreeSet::new();

        if is_buffer_overflow(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::BufferOverflow);
        }
        if is_command_injection(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::CommandInjection);
        }
        if is_format_string(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::FormatString);
        }
        if is_path_traversal(&category, &title) {
            classes.insert(SemanticPatternClass::PathTraversal);
        }
        if is_use_after_free(&title) {
            classes.insert(SemanticPatternClass::UseAfterFree);
        }
        if is_race_condition(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::RaceCondition);
        }
        if is_insecure_temp_file(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::InsecureTempFile);
        }

        classes
    }
}

/// Extract the best-effort function hint embedded in a finding title.
pub fn extract_function_from_title(title: &str) -> String {
    let Some((_, rest)) = title.split_once(": ") else {
        return String::new();
    };

    let head = rest.split(" (").next().unwrap_or(rest).trim();
    if let Some((_, sink)) = head.rsplit_once("->") {
        return sink.trim().to_string();
    }

    head.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Extract a best-effort source line hint from titles like `... (file.c:42)`.
pub fn extract_line_from_title(title: &str) -> Option<u32> {
    let (_, suffix) = title.rsplit_once(':')?;
    let digits = suffix.strip_suffix(')')?.trim();
    digits.parse().ok()
}

fn normalize_text(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn normalize_symbol(input: &str) -> String {
    input
        .split('@')
        .next()
        .unwrap_or(input)
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .to_ascii_lowercase()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn is_function(function_name: &str, names: &[&str]) -> bool {
    names.contains(&function_name)
}

fn is_buffer_overflow(category: &str, title: &str, function_name: &str) -> bool {
    const BUFFER_APIS: &[&str] = &[
        "strcpy", "strcat", "gets", "memcpy", "memmove", "strncpy", "strncat",
    ];
    const BUFFER_TERMS: &[&str] = &[
        "buffer overflow",
        "stack overflow",
        "heap overflow",
        "out-of-bounds",
        "out of bounds",
        "out-of-bounds write",
        "out-of-bounds read",
    ];

    is_function(function_name, BUFFER_APIS)
        || (category == "memory" && contains_any(title, BUFFER_TERMS))
        || contains_any(title, BUFFER_TERMS)
}

fn is_command_injection(_category: &str, title: &str, function_name: &str) -> bool {
    const COMMAND_APIS: &[&str] = &[
        "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execvp", "execvpe",
    ];
    const COMMAND_TERMS: &[&str] = &[
        "command injection",
        "shell injection",
        "os command injection",
        "command execution",
    ];

    is_function(function_name, COMMAND_APIS) || contains_any(title, COMMAND_TERMS)
}

fn is_format_string(category: &str, title: &str, function_name: &str) -> bool {
    const FORMAT_APIS: &[&str] = &["sprintf", "vsprintf", "scanf", "fscanf", "sscanf"];
    const FORMAT_TERMS: &[&str] = &["format string", "uncontrolled format string"];

    category == "format_string"
        || is_function(function_name, FORMAT_APIS)
        || contains_any(title, FORMAT_TERMS)
}

fn is_path_traversal(category: &str, title: &str) -> bool {
    category == "path_traversal"
        || contains_any(
            title,
            &["path traversal", "directory traversal", "zip slip"],
        )
}

fn is_use_after_free(title: &str) -> bool {
    contains_any(title, &["use-after-free", "use after free", "uaf"])
}

fn is_race_condition(category: &str, title: &str, function_name: &str) -> bool {
    category == "race"
        || is_function(function_name, &["access"])
        || contains_any(title, &["race condition", "toctou", "time-of-check"])
}

fn is_insecure_temp_file(category: &str, title: &str, function_name: &str) -> bool {
    category == "temp_file"
        || is_function(function_name, &["mktemp", "tmpnam"])
        || contains_any(
            title,
            &["temporary file", "temp file", "insecure temporary file"],
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_buffer_overflow_from_api_name() {
        let classes =
            SemanticPatternClassifier::new().classify("memory", "Dangerous API: strcpy", "strcpy");

        assert!(classes.contains(&SemanticPatternClass::BufferOverflow));
    }

    #[test]
    fn classifies_buffer_overflow_from_semantic_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: stack buffer overflow in copy_input",
            "copy_input",
        );

        assert!(classes.contains(&SemanticPatternClass::BufferOverflow));
    }

    #[test]
    fn does_not_overclassify_generic_memory_findings() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: suspicious memory corruption risk",
            "parse_packet",
        );

        assert!(classes.is_empty());
    }

    #[test]
    fn classifies_use_after_free_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: use-after-free in cleanup",
            "cleanup",
        );

        assert!(classes.contains(&SemanticPatternClass::UseAfterFree));
    }

    #[test]
    fn classifies_command_injection_from_exec_symbols() {
        let classes = SemanticPatternClassifier::new().classify(
            "command",
            "Agent: suspicious execv",
            "execv",
        );

        assert!(classes.contains(&SemanticPatternClass::CommandInjection));
    }

    #[test]
    fn classifies_tempfile_from_mktemp_without_race_overlap() {
        let classes = SemanticPatternClassifier::new().classify(
            "temp_file",
            "Pattern: insecure temporary file via mktemp",
            "mktemp",
        );

        assert!(classes.contains(&SemanticPatternClass::InsecureTempFile));
        assert!(!classes.contains(&SemanticPatternClass::RaceCondition));
    }

    #[test]
    fn classifies_race_from_access_symbol() {
        let classes = SemanticPatternClassifier::new().classify(
            "race",
            "Pattern: time-of-check race via access",
            "access",
        );

        assert!(classes.contains(&SemanticPatternClass::RaceCondition));
    }

    #[test]
    fn extracts_function_from_pattern_title() {
        assert_eq!(
            extract_function_from_title("Dangerous pattern: strcpy (foo.c:10)"),
            "strcpy"
        );
    }

    #[test]
    fn extracts_sink_function_from_flow_title() {
        assert_eq!(
            extract_function_from_title("Unsanitized flow: recv -> strcpy"),
            "strcpy"
        );
    }

    #[test]
    fn extracts_line_from_pattern_title() {
        assert_eq!(
            extract_line_from_title("Dangerous pattern: strcpy (foo.c:10)"),
            Some(10)
        );
    }
}
