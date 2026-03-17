//! Detection of dangerous API usage patterns.
//!
//! Shared types used by both binary-level and source-level detectors.
//! The actual detection logic is split across:
//! - `patterns_binary`: binary import scanning and graph DB detection
//! - `patterns_source`: language-specific source code pattern matching

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
    Deserialization,
    Crypto,
    UnsafeCode,
    PrototypePollution,
    Xss,
    NullDeref,
    IntegerOverflow,
    DivideByZero,
    ResourceLeak,
    ResourceExhaustion,
    UninitializedVar,
    UseAfterFree,
    InvalidFree,
    TypeConfusion,
    AccessControl,
    InformationExposure,
    ErrorHandling,
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
            Self::NullDeref => write!(f, "null_deref"),
            Self::IntegerOverflow => write!(f, "integer_overflow"),
            Self::DivideByZero => write!(f, "divide_by_zero"),
            Self::ResourceLeak => write!(f, "resource_leak"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::UninitializedVar => write!(f, "uninitialized_var"),
            Self::UseAfterFree => write!(f, "use_after_free"),
            Self::InvalidFree => write!(f, "invalid_free"),
            Self::TypeConfusion => write!(f, "type_confusion"),
            Self::AccessControl => write!(f, "access_control"),
            Self::InformationExposure => write!(f, "information_exposure"),
            Self::ErrorHandling => write!(f, "error_handling"),
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
pub(crate) struct DangerousEntry {
    pub name: &'static str,
    pub category: DangerCategory,
    pub severity: Severity,
    pub reason: &'static str,
}

/// All known dangerous C/C++ APIs with their categories.
pub(crate) const DANGEROUS_APIS: &[DangerousEntry] = &[
    // Memory safety
    DangerousEntry {
        name: "strcpy",
        category: DangerCategory::Memory,
        severity: Severity::Critical,
        reason: "unbounded copy; use strncpy or strlcpy",
    },
    DangerousEntry {
        name: "strcat",
        category: DangerCategory::Memory,
        severity: Severity::Critical,
        reason: "unbounded concatenation; use strncat or strlcat",
    },
    DangerousEntry {
        name: "gets",
        category: DangerCategory::Memory,
        severity: Severity::Critical,
        reason: "no bounds checking; use fgets",
    },
    DangerousEntry {
        name: "memcpy",
        category: DangerCategory::Memory,
        severity: Severity::Medium,
        reason: "no bounds checking; verify size parameter",
    },
    DangerousEntry {
        name: "memmove",
        category: DangerCategory::Memory,
        severity: Severity::Medium,
        reason: "no bounds checking; verify size parameter",
    },
    DangerousEntry {
        name: "strncpy",
        category: DangerCategory::Memory,
        severity: Severity::Low,
        reason: "may not null-terminate; prefer strlcpy",
    },
    DangerousEntry {
        name: "strncat",
        category: DangerCategory::Memory,
        severity: Severity::Low,
        reason: "size semantics are error-prone; prefer strlcat",
    },
    // Wide-string memory safety (wchar_t equivalents)
    DangerousEntry {
        name: "wcscpy",
        category: DangerCategory::Memory,
        severity: Severity::Critical,
        reason: "unbounded wide-string copy; use wcsncpy or wcslcpy",
    },
    DangerousEntry {
        name: "wcscat",
        category: DangerCategory::Memory,
        severity: Severity::Critical,
        reason: "unbounded wide-string concatenation; use wcsncat or wcslcat",
    },
    DangerousEntry {
        name: "wmemcpy",
        category: DangerCategory::Memory,
        severity: Severity::Medium,
        reason: "no bounds checking on wide chars; verify size parameter",
    },
    DangerousEntry {
        name: "wmemmove",
        category: DangerCategory::Memory,
        severity: Severity::Medium,
        reason: "no bounds checking on wide chars; verify size parameter",
    },
    DangerousEntry {
        name: "wcsncpy",
        category: DangerCategory::Memory,
        severity: Severity::Low,
        reason: "may not null-terminate wide string; prefer wcslcpy",
    },
    DangerousEntry {
        name: "wcsncat",
        category: DangerCategory::Memory,
        severity: Severity::Low,
        reason: "size semantics are error-prone for wide strings; prefer wcslcat",
    },
    DangerousEntry {
        name: "swprintf",
        category: DangerCategory::Memory,
        severity: Severity::Medium,
        reason: "wide-string format output; verify buffer size parameter",
    },
    // Format string
    DangerousEntry {
        name: "sprintf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "unbounded format output; use snprintf",
    },
    DangerousEntry {
        name: "vsprintf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "unbounded format output; use vsnprintf",
    },
    DangerousEntry {
        name: "printf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "format string vulnerability if format is user-controlled; use printf(\"%s\", var)",
    },
    DangerousEntry {
        name: "fprintf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason:
            "format string vulnerability if format is user-controlled; use fprintf(f, \"%s\", var)",
    },
    DangerousEntry {
        name: "vprintf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "variadic format always uses variable format string; validate format origin",
    },
    DangerousEntry {
        name: "vfprintf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "variadic format always uses variable format string; validate format origin",
    },
    DangerousEntry {
        name: "snprintf",
        category: DangerCategory::FormatString,
        severity: Severity::Medium,
        reason: "bounded output but format string vulnerability if format is user-controlled",
    },
    DangerousEntry {
        name: "vsnprintf",
        category: DangerCategory::FormatString,
        severity: Severity::Medium,
        reason: "bounded variadic format; validate format string origin",
    },
    DangerousEntry {
        name: "scanf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "unbounded input; use width specifiers or fgets",
    },
    DangerousEntry {
        name: "fscanf",
        category: DangerCategory::FormatString,
        severity: Severity::High,
        reason: "unbounded input; use width specifiers",
    },
    DangerousEntry {
        name: "sscanf",
        category: DangerCategory::FormatString,
        severity: Severity::Medium,
        reason: "potential buffer overflow with %s",
    },
    // Injection / command execution
    DangerousEntry {
        name: "system",
        category: DangerCategory::Injection,
        severity: Severity::Critical,
        reason: "shell injection risk; use exec* family directly",
    },
    DangerousEntry {
        name: "popen",
        category: DangerCategory::Injection,
        severity: Severity::Critical,
        reason: "shell injection risk; use pipe+fork+exec",
    },
    DangerousEntry {
        name: "exec",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution; validate all arguments",
    },
    DangerousEntry {
        name: "execl",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution; validate all arguments",
    },
    DangerousEntry {
        name: "execle",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution; validate all arguments",
    },
    DangerousEntry {
        name: "execlp",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution with PATH search; validate arguments",
    },
    DangerousEntry {
        name: "execv",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution; validate all arguments",
    },
    DangerousEntry {
        name: "execvp",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution with PATH search; validate arguments",
    },
    DangerousEntry {
        name: "execvpe",
        category: DangerCategory::Injection,
        severity: Severity::High,
        reason: "command execution with PATH/env; validate arguments",
    },
    // Temp file / race condition
    DangerousEntry {
        name: "mktemp",
        category: DangerCategory::Race,
        severity: Severity::Medium,
        reason: "TOCTOU race; use mkstemp",
    },
    DangerousEntry {
        name: "tmpnam",
        category: DangerCategory::TempFile,
        severity: Severity::Medium,
        reason: "TOCTOU race; use tmpfile or mkstemp",
    },
    DangerousEntry {
        name: "access",
        category: DangerCategory::Race,
        severity: Severity::Medium,
        reason: "TOCTOU race between access() check and subsequent open(); use fstat on open fd",
    },
    // Path traversal
    DangerousEntry {
        name: "realpath",
        category: DangerCategory::PathTraversal,
        severity: Severity::Low,
        reason: "buffer overflow in some implementations; check buffer size",
    },
    // Null dereference (CWE-476/690) — allocation APIs that can return NULL
    DangerousEntry {
        name: "malloc",
        category: DangerCategory::NullDeref,
        severity: Severity::Medium,
        reason: "returns NULL on failure; check return value before use",
    },
    DangerousEntry {
        name: "calloc",
        category: DangerCategory::NullDeref,
        severity: Severity::Medium,
        reason: "returns NULL on failure; check return value before use",
    },
    DangerousEntry {
        name: "realloc",
        category: DangerCategory::NullDeref,
        severity: Severity::Medium,
        reason: "returns NULL on failure and may free original pointer; check return value",
    },
    // Use-after-free (CWE-416) — free can lead to UAF if pointer reused
    DangerousEntry {
        name: "free",
        category: DangerCategory::UseAfterFree,
        severity: Severity::High,
        reason: "accessing freed memory causes use-after-free; nullify pointer after free",
    },
    // Resource leak (CWE-401/772/775) — resource-acquiring APIs
    DangerousEntry {
        name: "fopen",
        category: DangerCategory::ResourceLeak,
        severity: Severity::Medium,
        reason: "opened file must be closed with fclose; check for leaks on error paths",
    },
    DangerousEntry {
        name: "fdopen",
        category: DangerCategory::ResourceLeak,
        severity: Severity::Medium,
        reason: "opened stream must be closed with fclose; check for leaks on error paths",
    },
    DangerousEntry {
        name: "open",
        category: DangerCategory::ResourceLeak,
        severity: Severity::Medium,
        reason: "opened file descriptor must be closed; check for leaks on error paths",
    },
    DangerousEntry {
        name: "socket",
        category: DangerCategory::ResourceLeak,
        severity: Severity::Medium,
        reason: "opened socket must be closed; check for leaks on error paths",
    },
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
