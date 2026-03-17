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
    DeadStore,
    Deserialization,
    EmbeddedMaliciousCode,
    FormatString,
    ImproperAccessControl,
    ImproperErrorHandling,
    InfiniteLoop,
    InformationExposure,
    InsecureTempFile,
    InvalidFree,
    LdapInjection,
    OperatorMisuse,
    PathTraversal,
    PointerArithmetic,
    SuspiciousCodeConstruct,
    TypeConfusion,
    UntrustedSearchPath,
    UncheckedLoopCondition,
    PrototypePollution,
    RaceCondition,
    ReachableAssertion,
    UndefinedBehavior,
    UnsafeApiUsage,
    UseAfterFree,
    NullDeref,
    IntegerOverflow,
    DivideByZero,
    ResourceExhaustion,
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
            Self::DeadStore => "dead_store",
            Self::Deserialization => "deserialization",
            Self::EmbeddedMaliciousCode => "embedded_malicious_code",
            Self::FormatString => "format_string",
            Self::ImproperAccessControl => "improper_access_control",
            Self::ImproperErrorHandling => "improper_error_handling",
            Self::InfiniteLoop => "infinite_loop",
            Self::InformationExposure => "information_exposure",
            Self::InsecureTempFile => "insecure_temp_file",
            Self::InvalidFree => "invalid_free",
            Self::LdapInjection => "ldap_injection",
            Self::OperatorMisuse => "operator_misuse",
            Self::PathTraversal => "path_traversal",
            Self::PointerArithmetic => "pointer_arithmetic",
            Self::SuspiciousCodeConstruct => "suspicious_code_construct",
            Self::TypeConfusion => "type_confusion",
            Self::UntrustedSearchPath => "untrusted_search_path",
            Self::UncheckedLoopCondition => "unchecked_loop_condition",
            Self::PrototypePollution => "prototype_pollution",
            Self::RaceCondition => "race_condition",
            Self::ReachableAssertion => "reachable_assertion",
            Self::UndefinedBehavior => "undefined_behavior",
            Self::UnsafeApiUsage => "unsafe_api_usage",
            Self::UseAfterFree => "use_after_free",
            Self::NullDeref => "null_deref",
            Self::IntegerOverflow => "integer_overflow",
            Self::DivideByZero => "divide_by_zero",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::ResourceLeak => "resource_leak",
            Self::UninitializedVar => "uninitialized_var",
        }
    }

    /// Coarse semantic cluster for routing closely related findings.
    pub fn confidence_cluster(&self) -> &'static str {
        match self {
            Self::BufferOverflow | Self::PointerArithmetic => "memory_bounds",
            Self::UseAfterFree | Self::InvalidFree | Self::TypeConfusion => "memory_lifecycle",
            Self::NullDeref => "memory_allocation",
            Self::CommandInjection
            | Self::Deserialization
            | Self::LdapInjection
            | Self::EmbeddedMaliciousCode => "code_execution",
            Self::CrossSiteScripting | Self::PrototypePollution => "web_data_flow",
            Self::InsecureTempFile
            | Self::PathTraversal
            | Self::UntrustedSearchPath
            | Self::RaceCondition => "filesystem_safety",
            Self::UncheckedLoopCondition
            | Self::IntegerOverflow
            | Self::DivideByZero
            | Self::ReachableAssertion
            | Self::InfiniteLoop => "arithmetic_safety",
            Self::ResourceExhaustion | Self::ResourceLeak | Self::ImproperErrorHandling => {
                "resource_management"
            }
            Self::UninitializedVar
            | Self::DeadStore
            | Self::SuspiciousCodeConstruct
            | Self::OperatorMisuse => "initialization_safety",
            Self::FormatString => "format_string",
            Self::CryptoWeakness | Self::InformationExposure => "crypto",
            Self::UnsafeApiUsage | Self::ImproperAccessControl | Self::UndefinedBehavior => {
                "unsafe_api"
            }
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
        if is_dead_store(&category, &title) {
            classes.insert(SemanticPatternClass::DeadStore);
        }
        if is_deserialization(&category, &title) {
            classes.insert(SemanticPatternClass::Deserialization);
        }
        if is_embedded_malicious_code(&category, &title) {
            classes.insert(SemanticPatternClass::EmbeddedMaliciousCode);
        }
        if is_format_string(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::FormatString);
        }
        if is_improper_access_control(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::ImproperAccessControl);
        }
        if is_improper_error_handling(&category, &title) {
            classes.insert(SemanticPatternClass::ImproperErrorHandling);
        }
        if is_information_exposure(&category, &title) {
            classes.insert(SemanticPatternClass::InformationExposure);
        }
        if is_path_traversal(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::PathTraversal);
        }
        if is_untrusted_search_path(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::UntrustedSearchPath);
        }
        if is_unchecked_loop_condition(&category, &title) {
            classes.insert(SemanticPatternClass::UncheckedLoopCondition);
        }
        if is_prototype_pollution(&category, &title) {
            classes.insert(SemanticPatternClass::PrototypePollution);
        }
        if is_use_after_free(&category, &title) {
            classes.insert(SemanticPatternClass::UseAfterFree);
        }
        if is_type_confusion(&category, &title) {
            classes.insert(SemanticPatternClass::TypeConfusion);
        }
        if is_suspicious_code_construct(&category, &title) {
            classes.insert(SemanticPatternClass::SuspiciousCodeConstruct);
        }
        if is_operator_misuse(&category, &title) {
            classes.insert(SemanticPatternClass::OperatorMisuse);
        }
        if is_pointer_arithmetic(&category, &title) {
            classes.insert(SemanticPatternClass::PointerArithmetic);
        }
        if is_race_condition(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::RaceCondition);
        }
        if is_reachable_assertion(&category, &title) {
            classes.insert(SemanticPatternClass::ReachableAssertion);
        }
        if is_undefined_behavior(&category, &title) {
            classes.insert(SemanticPatternClass::UndefinedBehavior);
        }
        if is_unsafe_api_usage(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::UnsafeApiUsage);
        }
        if is_insecure_temp_file(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::InsecureTempFile);
        }
        if is_invalid_free(&category, &title) {
            classes.insert(SemanticPatternClass::InvalidFree);
        }
        if is_ldap_injection(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::LdapInjection);
        }
        if is_null_deref(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::NullDeref);
        }
        if is_integer_overflow(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::IntegerOverflow);
        }
        if is_infinite_loop(&category, &title) {
            classes.insert(SemanticPatternClass::InfiniteLoop);
        }
        if is_divide_by_zero(&category, &title) {
            classes.insert(SemanticPatternClass::DivideByZero);
        }
        if is_resource_leak(&category, &title, &function_name) {
            classes.insert(SemanticPatternClass::ResourceLeak);
        }
        if is_resource_exhaustion(&category, &title) {
            classes.insert(SemanticPatternClass::ResourceExhaustion);
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
    const FORMAT_APIS: &[&str] = &[
        "sprintf",
        "vsprintf",
        "printf",
        "fprintf",
        "vprintf",
        "vfprintf",
        "snprintf",
        "vsnprintf",
        "scanf",
        "fscanf",
        "sscanf",
    ];
    const FORMAT_TERMS: &[&str] = &["format string", "uncontrolled format string"];

    category == "format_string"
        || is_function(function_name, FORMAT_APIS)
        || contains_any(title, FORMAT_TERMS)
}

fn is_improper_access_control(category: &str, title: &str, function_name: &str) -> bool {
    const PRIVILEGE_APIS: &[&str] = &[
        "setuid",
        "seteuid",
        "setreuid",
        "setgid",
        "setegid",
        "setregid",
        "createprocessasuser",
    ];
    const ACCESS_TERMS: &[&str] = &[
        "privilege violation",
        "least privilege",
        "improper access control",
        "improper authorization",
        "privilege escalation",
        "missing authorization",
        "access control",
        "permission check",
    ];

    category == "access_control"
        || category == "privilege"
        || is_function(function_name, PRIVILEGE_APIS)
        || contains_any(title, ACCESS_TERMS)
}

fn is_path_traversal(category: &str, title: &str, function_name: &str) -> bool {
    !is_untrusted_search_path(category, title, function_name)
        && (category == "path_traversal"
            || contains_any(
                title,
                &["path traversal", "directory traversal", "zip slip"],
            ))
}

fn is_untrusted_search_path(category: &str, title: &str, function_name: &str) -> bool {
    const SEARCH_PATH_APIS: &[&str] = &["dlopen", "loadlibrary", "loadlibraryex"];
    const SEARCH_PATH_TERMS: &[&str] = &[
        "untrusted search path",
        "uncontrolled search path",
        "library path",
        "shared library",
        "dll search path",
        "loadlibrary",
        "dlopen",
    ];

    is_function(function_name, SEARCH_PATH_APIS)
        || (category == "path_traversal" && contains_any(title, SEARCH_PATH_TERMS))
}

fn is_use_after_free(category: &str, title: &str) -> bool {
    category == "use_after_free"
        || contains_any(title, &["use-after-free", "use after free", "uaf"])
}

fn is_type_confusion(category: &str, title: &str) -> bool {
    category == "type_confusion"
        || contains_any(
            title,
            &[
                "type confusion",
                "type mismatch",
                "type error",
                "wrong type",
                "incorrect type",
                "cast to wrong type",
                "improper type",
            ],
        )
}

fn is_unchecked_loop_condition(category: &str, title: &str) -> bool {
    const LOOP_CONDITION_TERMS: &[&str] = &[
        "unchecked loop condition",
        "untrusted loop condition",
        "unchecked loop bound",
        "unchecked loop bounds",
        "untrusted loop bound",
        "untrusted loop bounds",
        "loop condition from untrusted input",
        "untrusted iteration count",
        "unbounded iteration count",
    ];

    category == "unchecked_loop_condition" || contains_any(title, LOOP_CONDITION_TERMS)
}

fn is_race_condition(category: &str, title: &str, function_name: &str) -> bool {
    category == "race"
        || is_function(function_name, &["access"])
        || contains_any(title, &["race condition", "toctou", "time-of-check"])
}

fn is_reachable_assertion(category: &str, title: &str) -> bool {
    category == "reachable_assertion"
        || contains_any(
            title,
            &[
                "reachable assertion",
                "reachable assert",
                "assertion failure",
                "assertion reachable",
                "abort reachable",
                "assert reachable from untrusted input",
            ],
        )
}

fn is_undefined_behavior(category: &str, title: &str) -> bool {
    category == "undefined_behavior"
        || category == "poor_code_quality"
        || contains_any(
            title,
            &[
                "undefined behavior",
                "unspecified behavior",
                "implementation-defined",
                "implementation defined",
                "poor code quality",
                "code quality indicator",
                "reliance on undefined",
            ],
        )
}

fn is_insecure_temp_file(category: &str, title: &str, function_name: &str) -> bool {
    category == "temp_file"
        || is_function(function_name, &["mktemp", "tmpnam"])
        || contains_any(
            title,
            &["temporary file", "temp file", "insecure temporary file"],
        )
}

fn is_invalid_free(category: &str, title: &str) -> bool {
    category == "invalid_free"
        || contains_any(
            title,
            &[
                "free of memory not on the heap",
                "free memory not on heap",
                "invalid free",
                "free non-heap",
                "free stack memory",
                "free of pointer not on the heap",
                "free of non-heap memory",
                "freeing stack",
                "freeing non-heap",
                "free on stack",
            ],
        )
}

fn is_ldap_injection(category: &str, title: &str, function_name: &str) -> bool {
    const LDAP_APIS: &[&str] = &["ldap_search", "ldap_search_s", "ldap_search_ext_s"];
    const LDAP_TERMS: &[&str] = &[
        "ldap injection",
        "ldap query injection",
        "ldap filter injection",
        "unsanitized ldap",
        "ldap search injection",
    ];

    category == "ldap_injection"
        || is_function(function_name, LDAP_APIS)
        || contains_any(title, LDAP_TERMS)
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

fn is_dead_store(category: &str, title: &str) -> bool {
    category == "dead_store"
        || category == "unused_variable"
        || contains_any(
            title,
            &[
                "dead store",
                "unused variable",
                "unused assignment",
                "assignment to variable without use",
                "value assigned is never used",
                "value written is never read",
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

fn is_integer_overflow(category: &str, title: &str, function_name: &str) -> bool {
    const OVERFLOW_APIS: &[&str] = &["atoi", "atol", "atoll", "atof"];

    category == "integer_overflow"
        || is_function(function_name, OVERFLOW_APIS)
        || (category == "memory" && is_function(function_name, OVERFLOW_APIS))
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
                "atoi",
                "atol",
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

fn is_resource_exhaustion(category: &str, title: &str) -> bool {
    category == "resource_exhaustion"
        || contains_any(
            title,
            &[
                "resource exhaustion",
                "resource consumption",
                "uncontrolled resource",
                "denial of service",
                "excessive allocation",
                "excessive iteration",
                "excessive memory",
                "excessive cpu",
                "algorithmic complexity",
                "billion laughs",
                "zip bomb",
                "decompression bomb",
            ],
        )
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

fn is_embedded_malicious_code(category: &str, title: &str) -> bool {
    category == "malicious_code"
        || category == "trojan"
        || category == "backdoor"
        || contains_any(
            title,
            &[
                "trojan",
                "backdoor",
                "malicious code",
                "embedded malicious",
                "logic bomb",
                "hidden functionality",
                "covert channel",
            ],
        )
}

fn is_improper_error_handling(category: &str, title: &str) -> bool {
    category == "error_handling"
        || contains_any(
            title,
            &[
                "empty catch",
                "unchecked error",
                "improper error handling",
                "missing error check",
                "error condition",
                "improper locking",
                "improper check for unusual",
            ],
        )
}

fn is_information_exposure(category: &str, title: &str) -> bool {
    category == "information_exposure"
        || category == "sensitive_data"
        || contains_any(
            title,
            &[
                "information exposure",
                "sensitive data in log",
                "sensitive data in debug",
                "debug information",
                "environment variable exposure",
                "sensitive information in environment",
                "password in log",
                "credential in log",
            ],
        )
}

fn is_suspicious_code_construct(category: &str, title: &str) -> bool {
    category == "suspicious_comment"
        || category == "dead_code"
        || contains_any(
            title,
            &[
                "suspicious comment",
                "dead code",
                "unreachable code",
                "always true",
                "always false",
                "expression is always",
                "code never executed",
                "obsolete code",
            ],
        )
}

fn is_infinite_loop(category: &str, title: &str) -> bool {
    category == "infinite_loop"
        || contains_any(
            title,
            &[
                "infinite loop",
                "infinite recursion",
                "uncontrolled recursion",
                "excessive recursion",
                "missing break",
            ],
        )
}

fn is_operator_misuse(category: &str, title: &str) -> bool {
    category == "operator_misuse"
        || contains_any(
            title,
            &[
                "wrong operator",
                "operator precedence",
                "use of wrong operator",
                "assignment instead of comparison",
                "missing break in switch",
                "missing default in switch",
                "incorrect block delimitation",
                "function call with wrong number",
                "function call with incorrect argument",
            ],
        )
}

fn is_pointer_arithmetic(category: &str, title: &str) -> bool {
    category == "pointer_arithmetic"
        || contains_any(
            title,
            &[
                "pointer scaling",
                "pointer subtraction",
                "wrong pointer",
                "non-structure pointer",
                "child of non-structure",
                "addition to pointer",
                "access child of non-structure",
                "fixed address",
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
    fn classifies_use_after_free_from_category() {
        let classes = SemanticPatternClassifier::new().classify(
            "use_after_free",
            "Dangerous API: free",
            "free",
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
        assert_eq!(
            SemanticPatternClass::UntrustedSearchPath.confidence_cluster(),
            "filesystem_safety"
        );
        assert_eq!(
            SemanticPatternClass::UncheckedLoopCondition.confidence_cluster(),
            "arithmetic_safety"
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
    fn classifies_untrusted_search_path_without_generic_path_overlap() {
        let classes = SemanticPatternClassifier::new().classify(
            "path_traversal",
            "Pattern: dlopen with untrusted path allows uncontrolled search path loading",
            "dlopen",
        );

        assert!(classes.contains(&SemanticPatternClass::UntrustedSearchPath));
        assert!(!classes.contains(&SemanticPatternClass::PathTraversal));
    }

    #[test]
    fn classifies_unchecked_loop_condition_from_title() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: unchecked loop condition from untrusted input controls iteration count",
            "print_line",
        );

        assert!(classes.contains(&SemanticPatternClass::UncheckedLoopCondition));
    }

    #[test]
    fn keeps_generic_path_traversal_distinct_from_search_path() {
        let classes = SemanticPatternClassifier::new().classify(
            "path_traversal",
            "LLM: directory traversal in archive extraction",
            "extract_archive",
        );

        assert!(classes.contains(&SemanticPatternClass::PathTraversal));
        assert!(!classes.contains(&SemanticPatternClass::UntrustedSearchPath));
    }

    #[test]
    fn does_not_classify_generic_loop_mentions_as_unchecked_loop_condition() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: manual byte-by-byte loop without proof of overflow",
            "copy_bytes",
        );

        assert!(!classes.contains(&SemanticPatternClass::UncheckedLoopCondition));
    }

    #[test]
    fn does_not_classify_unrelated_library_path_titles_as_search_path() {
        let classes = SemanticPatternClassifier::new().classify(
            "memory",
            "LLM: buffer overflow in library path parser",
            "strcpy",
        );

        assert!(classes.contains(&SemanticPatternClass::BufferOverflow));
        assert!(!classes.contains(&SemanticPatternClass::UntrustedSearchPath));
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

    #[test]
    fn classifies_printf_family_as_format_string() {
        let classifier = SemanticPatternClassifier::new();
        for api in &[
            "printf",
            "fprintf",
            "vprintf",
            "vfprintf",
            "snprintf",
            "vsnprintf",
        ] {
            let classes =
                classifier.classify("format_string", &format!("Dangerous pattern: {api}"), api);
            assert!(
                classes.contains(&SemanticPatternClass::FormatString),
                "{api} should classify as FormatString"
            );
        }
    }

    #[test]
    fn classifies_invalid_free_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "memory",
            "free of memory not on the heap in process_data",
            "free",
        );
        assert!(classes.contains(&SemanticPatternClass::InvalidFree));
    }

    #[test]
    fn classifies_invalid_free_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("invalid_free", "Dangerous pattern: free", "free");
        assert!(classes.contains(&SemanticPatternClass::InvalidFree));
    }

    #[test]
    fn invalid_free_does_not_trigger_on_use_after_free() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("memory", "use-after-free in handler", "handler");
        assert!(classes.contains(&SemanticPatternClass::UseAfterFree));
        assert!(!classes.contains(&SemanticPatternClass::InvalidFree));
    }

    #[test]
    fn invalid_free_clusters_with_memory_lifecycle() {
        assert_eq!(
            SemanticPatternClass::InvalidFree.confidence_cluster(),
            "memory_lifecycle"
        );
    }

    #[test]
    fn classifies_ldap_injection_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "injection",
            "ldap injection in search_users",
            "search_users",
        );
        assert!(classes.contains(&SemanticPatternClass::LdapInjection));
    }

    #[test]
    fn classifies_ldap_injection_from_api() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "injection",
            "Dangerous pattern: ldap_search_s",
            "ldap_search_s",
        );
        assert!(classes.contains(&SemanticPatternClass::LdapInjection));
    }

    #[test]
    fn classifies_ldap_injection_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("ldap_injection", "unsanitized user input", "query");
        assert!(classes.contains(&SemanticPatternClass::LdapInjection));
    }

    #[test]
    fn ldap_injection_does_not_trigger_on_command_injection() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("injection", "command injection in run", "system");
        assert!(classes.contains(&SemanticPatternClass::CommandInjection));
        assert!(!classes.contains(&SemanticPatternClass::LdapInjection));
    }

    #[test]
    fn ldap_injection_clusters_with_code_execution() {
        assert_eq!(
            SemanticPatternClass::LdapInjection.confidence_cluster(),
            "code_execution"
        );
    }

    #[test]
    fn classifies_resource_exhaustion_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "memory",
            "resource exhaustion via unbounded allocation",
            "malloc",
        );
        assert!(classes.contains(&SemanticPatternClass::ResourceExhaustion));
    }

    #[test]
    fn classifies_resource_exhaustion_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "resource_exhaustion",
            "Dangerous pattern: connect loop",
            "connect",
        );
        assert!(classes.contains(&SemanticPatternClass::ResourceExhaustion));
    }

    #[test]
    fn resource_exhaustion_does_not_trigger_on_resource_leak() {
        let classifier = SemanticPatternClassifier::new();
        let classes =
            classifier.classify("resource_leak", "file descriptor leak in handler", "open");
        assert!(classes.contains(&SemanticPatternClass::ResourceLeak));
        assert!(!classes.contains(&SemanticPatternClass::ResourceExhaustion));
    }

    #[test]
    fn resource_exhaustion_clusters_with_resource_management() {
        assert_eq!(
            SemanticPatternClass::ResourceExhaustion.confidence_cluster(),
            "resource_management"
        );
    }

    #[test]
    fn classifies_dead_store_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "code_quality",
            "dead store: value assigned is never used",
            "foo",
        );
        assert!(classes.contains(&SemanticPatternClass::DeadStore));
    }

    #[test]
    fn classifies_dead_store_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("unused_variable", "unused global value", "global_var");
        assert!(classes.contains(&SemanticPatternClass::DeadStore));
    }

    #[test]
    fn dead_store_clusters_with_initialization_safety() {
        assert_eq!(
            SemanticPatternClass::DeadStore.confidence_cluster(),
            "initialization_safety"
        );
    }

    #[test]
    fn classifies_reachable_assertion_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "robustness",
            "reachable assertion in input handler",
            "assert",
        );
        assert!(classes.contains(&SemanticPatternClass::ReachableAssertion));
    }

    #[test]
    fn classifies_reachable_assertion_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes =
            classifier.classify("reachable_assertion", "Dangerous pattern: assert", "assert");
        assert!(classes.contains(&SemanticPatternClass::ReachableAssertion));
    }

    #[test]
    fn reachable_assertion_clusters_with_arithmetic_safety() {
        assert_eq!(
            SemanticPatternClass::ReachableAssertion.confidence_cluster(),
            "arithmetic_safety"
        );
    }

    #[test]
    fn classifies_access_control_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "security",
            "privilege violation in createprocessasuser call",
            "createprocessasuser",
        );
        assert!(classes.contains(&SemanticPatternClass::ImproperAccessControl));
    }

    #[test]
    fn classifies_access_control_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("access_control", "missing permission check", "handler");
        assert!(classes.contains(&SemanticPatternClass::ImproperAccessControl));
    }

    #[test]
    fn access_control_clusters_with_unsafe_api() {
        assert_eq!(
            SemanticPatternClass::ImproperAccessControl.confidence_cluster(),
            "unsafe_api"
        );
    }

    #[test]
    fn classifies_type_confusion_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "memory",
            "type confusion in xmlValidateOneNamespace",
            "xmlValidateOneNamespace",
        );
        assert!(classes.contains(&SemanticPatternClass::TypeConfusion));
    }

    #[test]
    fn classifies_type_confusion_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("type_confusion", "cast to wrong type", "process");
        assert!(classes.contains(&SemanticPatternClass::TypeConfusion));
    }

    #[test]
    fn type_confusion_clusters_with_memory_lifecycle() {
        assert_eq!(
            SemanticPatternClass::TypeConfusion.confidence_cluster(),
            "memory_lifecycle"
        );
    }

    #[test]
    fn classifies_undefined_behavior_from_title() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "code_quality",
            "reliance on undefined behavior in pointer arithmetic",
            "ptr_add",
        );
        assert!(classes.contains(&SemanticPatternClass::UndefinedBehavior));
    }

    #[test]
    fn classifies_undefined_behavior_from_category() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "poor_code_quality",
            "suspicious arithmetic operation",
            "add",
        );
        assert!(classes.contains(&SemanticPatternClass::UndefinedBehavior));
    }

    #[test]
    fn undefined_behavior_clusters_with_unsafe_api() {
        assert_eq!(
            SemanticPatternClass::UndefinedBehavior.confidence_cluster(),
            "unsafe_api"
        );
    }

    #[test]
    fn classifies_embedded_malicious_code() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("security", "trojan horse in network handler", "send");
        assert!(classes.contains(&SemanticPatternClass::EmbeddedMaliciousCode));
    }

    #[test]
    fn classifies_improper_error_handling() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("error_handling", "empty catch block", "catch");
        assert!(classes.contains(&SemanticPatternClass::ImproperErrorHandling));
    }

    #[test]
    fn classifies_information_exposure() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("security", "sensitive data in log output", "log");
        assert!(classes.contains(&SemanticPatternClass::InformationExposure));
    }

    #[test]
    fn classifies_suspicious_code_construct() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("code_quality", "expression is always true", "check");
        assert!(classes.contains(&SemanticPatternClass::SuspiciousCodeConstruct));
    }

    #[test]
    fn new_classes_cluster_correctly() {
        assert_eq!(
            SemanticPatternClass::EmbeddedMaliciousCode.confidence_cluster(),
            "code_execution"
        );
        assert_eq!(
            SemanticPatternClass::ImproperErrorHandling.confidence_cluster(),
            "resource_management"
        );
        assert_eq!(
            SemanticPatternClass::InformationExposure.confidence_cluster(),
            "crypto"
        );
        assert_eq!(
            SemanticPatternClass::SuspiciousCodeConstruct.confidence_cluster(),
            "initialization_safety"
        );
    }

    #[test]
    fn classifies_infinite_loop() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("robustness", "infinite loop in parser", "parse");
        assert!(classes.contains(&SemanticPatternClass::InfiniteLoop));
    }

    #[test]
    fn classifies_operator_misuse() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "code_quality",
            "use of wrong operator in comparison",
            "compare",
        );
        assert!(classes.contains(&SemanticPatternClass::OperatorMisuse));
    }

    #[test]
    fn classifies_pointer_arithmetic() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify(
            "memory",
            "wrong pointer scaling in array access",
            "array_get",
        );
        assert!(classes.contains(&SemanticPatternClass::PointerArithmetic));
    }

    #[test]
    fn new_sweep_classes_cluster_correctly() {
        assert_eq!(
            SemanticPatternClass::InfiniteLoop.confidence_cluster(),
            "arithmetic_safety"
        );
        assert_eq!(
            SemanticPatternClass::OperatorMisuse.confidence_cluster(),
            "initialization_safety"
        );
        assert_eq!(
            SemanticPatternClass::PointerArithmetic.confidence_cluster(),
            "memory_bounds"
        );
    }

    #[test]
    fn classifies_atoi_as_integer_overflow() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("memory", "Dangerous API: atoi", "atoi");
        assert!(
            classes.contains(&SemanticPatternClass::IntegerOverflow),
            "atoi should classify as IntegerOverflow, got {:?}",
            classes
        );
    }

    #[test]
    fn classifies_atol_as_integer_overflow() {
        let classifier = SemanticPatternClassifier::new();
        let classes = classifier.classify("memory", "Dangerous API: atol", "atol");
        assert!(classes.contains(&SemanticPatternClass::IntegerOverflow));
    }
}
