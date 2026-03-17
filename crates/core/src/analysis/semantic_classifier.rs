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
    CrossSiteScripting,
    CryptoWeakness,
    Deserialization,
    FormatString,
    InsecureTempFile,
    PathTraversal,
    PrototypePollution,
    RaceCondition,
    UnsafeApiUsage,
    UseAfterFree,
    NullDeref,
    IntegerOverflow,
    DivideByZero,
    ResourceLeak,
    UninitializedVar,
}

impl SemanticPatternClass {
    /// Stable identifier suitable for logs, prompts, and deduplication keys.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BufferOverflow => "buffer_overflow",
            Self::CommandInjection => "command_injection",
            Self::CrossSiteScripting => "cross_site_scripting",
            Self::CryptoWeakness => "crypto_weakness",
            Self::Deserialization => "deserialization",
            Self::FormatString => "format_string",
            Self::InsecureTempFile => "insecure_temp_file",
            Self::PathTraversal => "path_traversal",
            Self::PrototypePollution => "prototype_pollution",
            Self::RaceCondition => "race_condition",
            Self::UnsafeApiUsage => "unsafe_api_usage",
            Self::UseAfterFree => "use_after_free",
            Self::NullDeref => "null_deref",
            Self::IntegerOverflow => "integer_overflow",
            Self::DivideByZero => "divide_by_zero",
            Self::ResourceLeak => "resource_leak",
            Self::UninitializedVar => "uninitialized_var",
        }
    }

    /// Coarse semantic cluster for routing closely related findings.
    pub fn confidence_cluster(&self) -> &'static str {
        match self {
            Self::BufferOverflow => "memory_bounds",
            Self::UseAfterFree => "memory_lifecycle",
            Self::NullDeref => "memory_allocation",
            Self::CommandInjection | Self::Deserialization => "code_execution",
            Self::CrossSiteScripting | Self::PrototypePollution => "web_data_flow",
            Self::InsecureTempFile | Self::PathTraversal | Self::RaceCondition => {
                "filesystem_safety"
            }
            Self::IntegerOverflow | Self::DivideByZero => "arithmetic_safety",
            Self::ResourceLeak => "resource_management",
            Self::UninitializedVar => "initialization_safety",
            Self::FormatString => "format_string",
            Self::CryptoWeakness => "crypto",
            Self::UnsafeApiUsage => "unsafe_api",
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
        if is_cross_site_scripting(&category, &title) {
            classes.insert(SemanticPatternClass::CrossSiteScripting);
        }
        if is_crypto_weakness(&category, &title) {
            classes.insert(SemanticPatternClass::CryptoWeakness);
        }
        if is_deserialization(&category, &title) {
            classes.insert(SemanticPatternClass::Deserialization);
        }
        if is_format_string(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::FormatString);
        }
        if is_path_traversal(&category, &title) {
            classes.insert(SemanticPatternClass::PathTraversal);
        }
        if is_prototype_pollution(&category, &title) {
            classes.insert(SemanticPatternClass::PrototypePollution);
        }
        if is_use_after_free(&title) {
            classes.insert(SemanticPatternClass::UseAfterFree);
        }
        if is_race_condition(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::RaceCondition);
        }
        if is_unsafe_api_usage(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::UnsafeApiUsage);
        }
        if is_insecure_temp_file(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::InsecureTempFile);
        }
        if is_null_deref(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::NullDeref);
        }
        if is_integer_overflow(&category, &title) {
            classes.insert(SemanticPatternClass::IntegerOverflow);
        }
        if is_divide_by_zero(&category, &title) {
            classes.insert(SemanticPatternClass::DivideByZero);
        }
        if is_resource_leak(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::ResourceLeak);
        }
        if is_uninitialized_var(&category, &title) {
            classes.insert(SemanticPatternClass::UninitializedVar);
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
        // Wide-string equivalents (wchar_t)
        "wcscpy", "wcscat", "wmemcpy", "wmemmove", "wcsncpy", "wcsncat", "swprintf",
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

fn is_cross_site_scripting(category: &str, title: &str) -> bool {
    category == "xss"
        || contains_any(
            title,
            &[
                "cross-site scripting",
                "cross site scripting",
                "xss",
                "innerhtml",
                "document.write",
            ],
        )
}

fn is_crypto_weakness(category: &str, title: &str) -> bool {
    category == "crypto"
        || contains_any(
            title,
            &[
                "weak crypto",
                "weak hash",
                "weak cipher",
                "insecure random",
                "broken crypto",
                "md5",
                "sha1",
                "des ",
                "rc4",
                "weak key",
                "insufficient key",
            ],
        )
}

fn is_deserialization(category: &str, title: &str) -> bool {
    category == "deserialization"
        || contains_any(
            title,
            &[
                "deserialization",
                "deserialisation",
                "unsafe unmarshall",
                "pickle.load",
                "yaml.load",
                "objectinputstream",
                "readobject",
            ],
        )
}

fn is_prototype_pollution(category: &str, title: &str) -> bool {
    category == "prototype_pollution"
        || contains_any(
            title,
            &["prototype pollution", "__proto__", "constructor.prototype"],
        )
}

fn is_unsafe_api_usage(category: &str, title: &str, function_name: &str) -> bool {
    category == "unsafe_code"
        || is_function(function_name, &["transmute", "setuid", "setgid"])
        || contains_any(
            title,
            &[
                "dangerous function",
                "potentially dangerous",
                "unsafe api",
                "deprecated api",
                "banned function",
            ],
        )
}

fn is_null_deref(category: &str, title: &str, function_name: &str) -> bool {
    category == "null_deref"
        || contains_any(
            title,
            &[
                "null dereference",
                "null pointer",
                "null deref",
                "nullptr",
                "null check",
                "unchecked return",
            ],
        )
        || (contains_any(title, &["malloc", "calloc", "realloc"])
            && contains_any(title, &["null", "check", "unchecked"]))
        || is_function(function_name, &["malloc", "calloc", "realloc"])
            && contains_any(title, &["null", "unchecked"])
}

fn is_integer_overflow(category: &str, title: &str) -> bool {
    category == "integer_overflow"
        || contains_any(
            title,
            &[
                "integer overflow",
                "integer underflow",
                "integer wrap",
                "int overflow",
                "numeric overflow",
                "arithmetic overflow",
                "truncation",
                "integer coercion",
            ],
        )
}

fn is_divide_by_zero(category: &str, title: &str) -> bool {
    category == "divide_by_zero"
        || contains_any(
            title,
            &[
                "divide by zero",
                "division by zero",
                "divide-by-zero",
                "div by zero",
                "modulo by zero",
                "zero divisor",
            ],
        )
}

fn is_resource_leak(category: &str, title: &str, function_name: &str) -> bool {
    const RESOURCE_APIS: &[&str] = &[
        "fopen", "open", "socket", "accept", "dup", "dup2", "pipe", "creat",
    ];

    category == "resource_leak"
        || contains_any(
            title,
            &[
                "resource leak",
                "memory leak",
                "file descriptor leak",
                "handle leak",
                "fd leak",
                "unclosed",
                "not freed",
                "not closed",
            ],
        )
        || (is_function(function_name, RESOURCE_APIS)
            && contains_any(title, &["leak", "unclosed", "not closed"]))
}

fn is_uninitialized_var(category: &str, title: &str) -> bool {
    category == "uninitialized_var"
        || contains_any(
            title,
            &[
                "uninitialized",
                "uninitialised",
                "not initialized",
                "use of uninitialized",
                "indeterminate value",
            ],
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
    fn confidence_clusters_split_memory_classes() {
        assert_eq!(
            SemanticPatternClass::BufferOverflow.confidence_cluster(),
            "memory_bounds"
        );
        assert_eq!(
            SemanticPatternClass::NullDeref.confidence_cluster(),
            "memory_allocation"
        );
        assert_eq!(
            SemanticPatternClass::UseAfterFree.confidence_cluster(),
            "memory_lifecycle"
        );
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
    fn classifies_xss_from_category() {
        let classes = SemanticPatternClassifier::new().classify("xss", "XSS via innerHTML", "");
        assert!(classes.contains(&SemanticPatternClass::CrossSiteScripting));
    }

    #[test]
    fn classifies_xss_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "injection",
            "LLM: cross-site scripting in render_page",
            "render_page",
        );
        assert!(classes.contains(&SemanticPatternClass::CrossSiteScripting));
    }

    #[test]
    fn classifies_crypto_from_category() {
        let classes =
            SemanticPatternClassifier::new().classify("crypto", "Weak hash: MD5", "md5_init");
        assert!(classes.contains(&SemanticPatternClass::CryptoWeakness));
    }

    #[test]
    fn classifies_crypto_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "security",
            "LLM: weak cipher DES used for encryption",
            "encrypt",
        );
        assert!(classes.contains(&SemanticPatternClass::CryptoWeakness));
    }

    #[test]
    fn classifies_deserialization_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "deserialization",
            "Unsafe pickle.loads",
            "load_data",
        );
        assert!(classes.contains(&SemanticPatternClass::Deserialization));
    }

    #[test]
    fn classifies_deserialization_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "injection",
            "LLM: insecure deserialization via ObjectInputStream",
            "readObject",
        );
        assert!(classes.contains(&SemanticPatternClass::Deserialization));
    }

    #[test]
    fn classifies_prototype_pollution_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "prototype_pollution",
            "Prototype pollution via merge",
            "deep_merge",
        );
        assert!(classes.contains(&SemanticPatternClass::PrototypePollution));
    }

    #[test]
    fn classifies_prototype_pollution_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "injection",
            "LLM: __proto__ manipulation in merge",
            "merge",
        );
        assert!(classes.contains(&SemanticPatternClass::PrototypePollution));
    }

    #[test]
    fn classifies_unsafe_api_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "unsafe_code",
            "Dangerous function: transmute",
            "transmute",
        );
        assert!(classes.contains(&SemanticPatternClass::UnsafeApiUsage));
    }

    #[test]
    fn classifies_unsafe_api_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: potentially dangerous function usage",
            "custom_alloc",
        );
        assert!(classes.contains(&SemanticPatternClass::UnsafeApiUsage));
    }

    #[test]
    fn does_not_overclassify_generic_injection_into_xss() {
        let classes = SemanticPatternClassifier::new().classify(
            "injection",
            "LLM: SQL injection in query builder",
            "execute_query",
        );
        assert!(!classes.contains(&SemanticPatternClass::CrossSiteScripting));
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

    #[test]
    fn classifies_null_deref_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "null_deref",
            "Pattern: pointer dereference",
            "parse",
        );
        assert!(classes.contains(&SemanticPatternClass::NullDeref));
    }

    #[test]
    fn classifies_null_deref_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: null pointer dereference in parse_input",
            "parse_input",
        );
        assert!(classes.contains(&SemanticPatternClass::NullDeref));
    }

    #[test]
    fn classifies_integer_overflow_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "integer_overflow",
            "Pattern: increment without check",
            "counter",
        );
        assert!(classes.contains(&SemanticPatternClass::IntegerOverflow));
    }

    #[test]
    fn classifies_integer_overflow_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "arithmetic",
            "LLM: integer overflow in size calculation",
            "calc_size",
        );
        assert!(classes.contains(&SemanticPatternClass::IntegerOverflow));
    }

    #[test]
    fn classifies_divide_by_zero_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "divide_by_zero",
            "Pattern: division without check",
            "compute",
        );
        assert!(classes.contains(&SemanticPatternClass::DivideByZero));
    }

    #[test]
    fn classifies_divide_by_zero_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "arithmetic",
            "LLM: division by zero in normalize",
            "normalize",
        );
        assert!(classes.contains(&SemanticPatternClass::DivideByZero));
    }

    #[test]
    fn classifies_resource_leak_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "resource_leak",
            "Pattern: file opened",
            "init",
        );
        assert!(classes.contains(&SemanticPatternClass::ResourceLeak));
    }

    #[test]
    fn classifies_resource_leak_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "io",
            "LLM: resource leak — file descriptor not closed",
            "open_file",
        );
        assert!(classes.contains(&SemanticPatternClass::ResourceLeak));
    }

    #[test]
    fn classifies_uninitialized_var_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "uninitialized_var",
            "Pattern: variable declared without init",
            "process",
        );
        assert!(classes.contains(&SemanticPatternClass::UninitializedVar));
    }

    #[test]
    fn classifies_uninitialized_var_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: use of uninitialized variable in loop",
            "loop_body",
        );
        assert!(classes.contains(&SemanticPatternClass::UninitializedVar));
    }

    #[test]
    fn classifies_buffer_overflow_from_wide_string_apis() {
        let classifier = SemanticPatternClassifier::new();

        for api in &[
            "wcscpy", "wcscat", "wmemcpy", "wmemmove", "wcsncpy", "wcsncat", "swprintf",
        ] {
            let classes = classifier.classify(
                "memory",
                &format!("Dangerous pattern: {} (test.c:10)", api),
                api,
            );
            assert!(
                classes.contains(&SemanticPatternClass::BufferOverflow),
                "Expected BufferOverflow for wide-string API '{}', got {:?}",
                api,
                classes
            );
        }
    }

    #[test]
    fn wide_string_apis_do_not_misclassify() {
        let classifier = SemanticPatternClassifier::new();

        let classes = classifier.classify("memory", "Dangerous pattern: wcscpy", "wcscpy");
        assert!(classes.contains(&SemanticPatternClass::BufferOverflow));
        assert!(!classes.contains(&SemanticPatternClass::CommandInjection));
        assert!(!classes.contains(&SemanticPatternClass::FormatString));
    }
}
