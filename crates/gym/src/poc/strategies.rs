//! CWE-specific proof strategies with verifiable predicates.
//!
//! Each strategy defines:
//! - What disproof checks to run (find sanitizers, guards, bounds checks)
//! - What proof predicates to verify (taint paths, patterns, reachability)
//! - What tools to use for evidence gathering
//! - How to generate an exploit sketch (labeled UNTESTED HYPOTHESIS)

use super::Evidence;

// ---------------------------------------------------------------------------
// Strategy trait + registry
// ---------------------------------------------------------------------------

/// Context available for proof attempts.
#[derive(Debug, Clone)]
pub struct ProofContext {
    pub case_id: String,
    pub suite: String,
    pub cwe: u32,
    pub detected_cwes: Vec<u32>,
    pub finding_id: String,
}

/// A CWE-specific proof strategy.
pub trait ProofStrategy: Send + Sync {
    /// Human-readable strategy name.
    fn name(&self) -> &str;

    /// CWE IDs this strategy handles.
    fn applicable_cwes(&self) -> &[u32];

    /// Tools needed for this strategy.
    fn required_tools(&self) -> &[&str];

    /// Execute the strategy: returns (disproof_evidence, proof_evidence, reasoning).
    ///
    /// The strategy should:
    /// 1. First search for disproof (mitigations, guards, sanitizers)
    /// 2. Only if no disproof found, search for proof evidence
    fn execute(
        &self,
        context: &ProofContext,
    ) -> anyhow::Result<(Vec<Evidence>, Vec<Evidence>, String)>;

    /// Generate an untested exploit sketch (hypothesis only).
    fn generate_exploit_sketch(
        &self,
        context: &ProofContext,
        proof_evidence: &[Evidence],
    ) -> Option<String>;
}

/// Select the appropriate proof strategy for a CWE.
pub fn select_strategy(cwe: u32) -> Box<dyn ProofStrategy> {
    match cwe_family(cwe) {
        CweFamily::Injection => Box::new(InjectionProofStrategy),
        CweFamily::PathTraversal => Box::new(PathTraversalProofStrategy),
        CweFamily::Memory => Box::new(MemoryProofStrategy),
        CweFamily::Config => Box::new(ConfigProofStrategy),
        CweFamily::Unknown => Box::new(GenericProofStrategy),
    }
}

/// CWE family classification for strategy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CweFamily {
    Injection,
    PathTraversal,
    Memory,
    Config,
    Unknown,
}

fn cwe_family(cwe: u32) -> CweFamily {
    match cwe {
        // SQL injection, XSS, OS command injection, code injection, LDAP injection
        89 | 79 | 78 | 94 | 90 | 77 | 917 => CweFamily::Injection,
        // Path traversal
        22 | 23 | 36 => CweFamily::PathTraversal,
        // Buffer overflow, integer overflow/underflow, use-after-free, double-free
        121 | 122 | 119 | 120 | 124 | 125 | 126 | 127 | 190 | 191 | 416 | 415 => CweFamily::Memory,
        // Missing secure flag, broken crypto, hardcoded creds, sensitive data exposure
        614 | 327 | 328 | 259 | 798 | 200 | 311 | 319 => CweFamily::Config,
        _ => CweFamily::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Injection proof strategy (CWE-89, 79, 78, etc.)
// ---------------------------------------------------------------------------

/// Proves injection vulnerabilities via taint analysis.
///
/// Disproof checks:
/// - Parameterized query / prepared statement usage
/// - ORM usage (no raw SQL)
/// - Input validation / sanitization on taint path
/// - Template auto-escape enabled
/// - Content Security Policy headers
///
/// Proof predicates:
/// - Source→sink taint path exists
/// - No sanitizer/escape on the path
/// - Sink is string-concat into dangerous context (SQL/HTML/shell)
/// - Source is attacker-controlled (HTTP param, user input, etc.)
struct InjectionProofStrategy;

impl ProofStrategy for InjectionProofStrategy {
    fn name(&self) -> &str {
        "injection_proof"
    }

    fn applicable_cwes(&self) -> &[u32] {
        &[89, 79, 78, 94, 90, 77, 917]
    }

    fn required_tools(&self) -> &[&str] {
        &[
            "get_taint_paths",
            "read_function",
            "get_callers",
            "get_cross_file_calls",
            "get_data_sources",
            "lookup_cwe",
        ]
    }

    fn execute(
        &self,
        context: &ProofContext,
    ) -> anyhow::Result<(Vec<Evidence>, Vec<Evidence>, String)> {
        // This is the deterministic strategy template.
        // When integrated with AgentRunner, the LLM will use tools to populate these.
        // For now, return the strategy structure that the agent will fill in.
        let reasoning = format!(
            "Injection proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Search for parameterized queries, ORM usage, \
             input validation, template auto-escape, CSP headers.\n\
             Phase 2 (Proof): Trace taint from attacker-controlled source to \
             dangerous sink. Verify no sanitization on path. Confirm string \
             concatenation into {context_type}.\n\
             Status: Awaiting agent execution with tool access.",
            cwe = context.cwe,
            case = context.case_id,
            context_type = injection_context_type(context.cwe),
        );

        Ok((vec![], vec![], reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        context: &ProofContext,
        _proof_evidence: &[Evidence],
    ) -> Option<String> {
        let sketch = match context.cwe {
            89 => "UNTESTED HYPOTHESIS: Input \"' OR 1=1 --\" through identified taint path may bypass SQL query logic",
            79 => "UNTESTED HYPOTHESIS: Input \"<script>alert(1)</script>\" through identified taint path may execute in browser context",
            78 => "UNTESTED HYPOTHESIS: Input \"; cat /etc/passwd\" through identified taint path may execute as OS command",
            _ => return None,
        };
        Some(sketch.to_string())
    }
}

fn injection_context_type(cwe: u32) -> &'static str {
    match cwe {
        89 => "SQL query",
        79 => "HTML/JavaScript output",
        78 | 77 => "OS command",
        94 => "code evaluation",
        90 => "LDAP query",
        917 => "expression language",
        _ => "dangerous context",
    }
}

// ---------------------------------------------------------------------------
// Path traversal proof strategy (CWE-22)
// ---------------------------------------------------------------------------

struct PathTraversalProofStrategy;

impl ProofStrategy for PathTraversalProofStrategy {
    fn name(&self) -> &str {
        "path_traversal_proof"
    }

    fn applicable_cwes(&self) -> &[u32] {
        &[22, 23, 36]
    }

    fn required_tools(&self) -> &[&str] {
        &[
            "get_taint_paths",
            "read_function",
            "get_callers",
            "get_data_sources",
            "lookup_cwe",
        ]
    }

    fn execute(
        &self,
        context: &ProofContext,
    ) -> anyhow::Result<(Vec<Evidence>, Vec<Evidence>, String)> {
        let reasoning = format!(
            "Path traversal proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Search for path canonicalization, chroot/jail, \
             allowlist validation, realpath() usage, prefix checks.\n\
             Phase 2 (Proof): Trace input to file operation. Verify no path \
             normalization. Confirm no prefix/allowlist check.\n\
             Status: Awaiting agent execution with tool access.",
            cwe = context.cwe,
            case = context.case_id,
        );
        Ok((vec![], vec![], reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        _context: &ProofContext,
        _proof_evidence: &[Evidence],
    ) -> Option<String> {
        Some(
            "UNTESTED HYPOTHESIS: Input \"../../../etc/passwd\" through identified path may escape intended directory"
                .to_string(),
        )
    }
}

// ---------------------------------------------------------------------------
// Memory proof strategy (CWE-121, 191, etc.)
// ---------------------------------------------------------------------------

struct MemoryProofStrategy;

impl ProofStrategy for MemoryProofStrategy {
    fn name(&self) -> &str {
        "memory_reachability_proof"
    }

    fn applicable_cwes(&self) -> &[u32] {
        &[121, 122, 119, 120, 124, 125, 126, 127, 190, 191, 416, 415]
    }

    fn required_tools(&self) -> &[&str] {
        &[
            "read_function",
            "get_callers",
            "get_callees",
            "get_taint_paths",
            "lookup_cwe",
            "query_graph",
        ]
    }

    fn execute(
        &self,
        context: &ProofContext,
    ) -> anyhow::Result<(Vec<Evidence>, Vec<Evidence>, String)> {
        let reasoning = format!(
            "Memory safety proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Search for bounds checks, safe API wrappers, \
             compiler protections (stack canaries, ASAN annotations), \
             size validation before write operations.\n\
             Phase 2 (Proof): Identify buffer allocation and write operation. \
             Show buffer size < max possible input. Verify no bounds check \
             between allocation and write. Provide concrete trigger values.\n\
             NOTE: Static reachability is weaker than dynamic proof. \
             Verdicts for memory CWEs should be treated with extra scrutiny.\n\
             Status: Awaiting agent execution with tool access.",
            cwe = context.cwe,
            case = context.case_id,
        );
        Ok((vec![], vec![], reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        context: &ProofContext,
        _proof_evidence: &[Evidence],
    ) -> Option<String> {
        let desc = match context.cwe {
            119..=122 => {
                "UNTESTED HYPOTHESIS: Input exceeding buffer allocation at identified location may cause stack/heap corruption"
            }
            190 | 191 => {
                "UNTESTED HYPOTHESIS: Arithmetic on attacker-controlled value at identified location may overflow/underflow"
            }
            416 => {
                "UNTESTED HYPOTHESIS: Use of freed memory at identified location may be triggerable via identified path"
            }
            _ => return None,
        };
        Some(desc.to_string())
    }
}

// ---------------------------------------------------------------------------
// Config/crypto proof strategy (CWE-614, 327, etc.)
// ---------------------------------------------------------------------------

struct ConfigProofStrategy;

impl ProofStrategy for ConfigProofStrategy {
    fn name(&self) -> &str {
        "config_pattern_proof"
    }

    fn applicable_cwes(&self) -> &[u32] {
        &[614, 327, 328, 259, 798, 200, 311, 319]
    }

    fn required_tools(&self) -> &[&str] {
        &["read_function", "query_graph", "lookup_cwe", "get_callers"]
    }

    fn execute(
        &self,
        context: &ProofContext,
    ) -> anyhow::Result<(Vec<Evidence>, Vec<Evidence>, String)> {
        let reasoning = format!(
            "Configuration/crypto proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Search for override configuration, global \
             secure-by-default settings, wrapper functions, migration path \
             to secure algorithms.\n\
             Phase 2 (Proof): Confirm insecure pattern in production code path. \
             Verify no global override. Cite standards violation.\n\
             Status: Awaiting agent execution with tool access.",
            cwe = context.cwe,
            case = context.case_id,
        );
        Ok((vec![], vec![], reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        _context: &ProofContext,
        _proof_evidence: &[Evidence],
    ) -> Option<String> {
        // Config/crypto issues don't have traditional exploit sketches
        None
    }
}

// ---------------------------------------------------------------------------
// Generic fallback strategy
// ---------------------------------------------------------------------------

struct GenericProofStrategy;

impl ProofStrategy for GenericProofStrategy {
    fn name(&self) -> &str {
        "generic_proof"
    }

    fn applicable_cwes(&self) -> &[u32] {
        &[]
    }

    fn required_tools(&self) -> &[&str] {
        &[
            "read_function",
            "get_taint_paths",
            "get_callers",
            "lookup_cwe",
            "query_graph",
        ]
    }

    fn execute(
        &self,
        context: &ProofContext,
    ) -> anyhow::Result<(Vec<Evidence>, Vec<Evidence>, String)> {
        let reasoning = format!(
            "Generic proof strategy for CWE-{cwe} on case {case}:\n\
             No specialized strategy available for this CWE. Using generic \
             taint analysis and pattern matching.\n\
             Phase 1 (Disproof): Search for guards, validation, safe wrappers.\n\
             Phase 2 (Proof): Trace data flow, identify dangerous patterns.\n\
             Status: Awaiting agent execution with tool access.",
            cwe = context.cwe,
            case = context.case_id,
        );
        Ok((vec![], vec![], reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        _context: &ProofContext,
        _proof_evidence: &[Evidence],
    ) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwe_family_classification() {
        assert_eq!(cwe_family(89), CweFamily::Injection);
        assert_eq!(cwe_family(79), CweFamily::Injection);
        assert_eq!(cwe_family(78), CweFamily::Injection);
        assert_eq!(cwe_family(22), CweFamily::PathTraversal);
        assert_eq!(cwe_family(121), CweFamily::Memory);
        assert_eq!(cwe_family(191), CweFamily::Memory);
        assert_eq!(cwe_family(614), CweFamily::Config);
        assert_eq!(cwe_family(327), CweFamily::Config);
        assert_eq!(cwe_family(999), CweFamily::Unknown);
    }

    #[test]
    fn test_strategy_selection() {
        assert_eq!(select_strategy(89).name(), "injection_proof");
        assert_eq!(select_strategy(79).name(), "injection_proof");
        assert_eq!(select_strategy(22).name(), "path_traversal_proof");
        assert_eq!(select_strategy(121).name(), "memory_reachability_proof");
        assert_eq!(select_strategy(614).name(), "config_pattern_proof");
        assert_eq!(select_strategy(999).name(), "generic_proof");
    }

    #[test]
    fn test_injection_exploit_sketch() {
        let strategy = InjectionProofStrategy;
        let ctx = ProofContext {
            case_id: "test".into(),
            suite: "fixtures".into(),
            cwe: 89,
            detected_cwes: vec![89],
            finding_id: "f1".into(),
        };
        let sketch = strategy.generate_exploit_sketch(&ctx, &[]);
        assert!(sketch.is_some());
        assert!(sketch.unwrap().starts_with("UNTESTED HYPOTHESIS"));
    }

    #[test]
    fn test_config_no_exploit_sketch() {
        let strategy = ConfigProofStrategy;
        let ctx = ProofContext {
            case_id: "test".into(),
            suite: "fixtures".into(),
            cwe: 614,
            detected_cwes: vec![614],
            finding_id: "f1".into(),
        };
        assert!(strategy.generate_exploit_sketch(&ctx, &[]).is_none());
    }

    #[test]
    fn test_strategy_required_tools() {
        let s = select_strategy(89);
        assert!(s.required_tools().contains(&"get_taint_paths"));

        let s = select_strategy(121);
        assert!(s.required_tools().contains(&"read_function"));
    }
}
