//! CWE-specific proof strategies with verifiable predicates.
//!
//! Each strategy defines:
//! - What disproof checks to run (find sanitizers, guards, bounds checks)
//! - What proof predicates to verify (taint paths, patterns, reachability)
//! - What tools to use for evidence gathering
//! - How to generate an exploit sketch (labeled UNTESTED HYPOTHESIS)

use super::{Evidence, EvidenceKind, ExecutionMode};

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

/// A CWE-specific proof strategy implementing the disproof-first protocol.
///
/// Strategies operate in two execution modes (see [`ExecutionMode`]):
///
/// - **Template mode** (default): The strategy produces structured evidence templates —
///   checklists describing what defensive patterns to search for (disproof phase) and
///   what vulnerability indicators to look for (proof phase). The `tool_output` fields
///   contain template descriptions prefixed with `"TEMPLATE: "`, not raw tool output.
///   The poc-prover agent uses these templates to drive actual tool-grounded analysis.
///
/// - **Direct mode** (future): The strategy invokes tools directly and populates evidence
///   with real tool output. No built-in strategies currently use this mode.
///
/// Both modes follow the two-phase disproof-first protocol:
/// 1. Search for mitigations, guards, and defensive patterns (disproof evidence)
/// 2. Search for vulnerability indicators and exploit paths (proof evidence)
pub trait ProofStrategy: Send + Sync {
    /// Human-readable strategy name.
    fn name(&self) -> &str;

    /// CWE IDs this strategy handles.
    fn applicable_cwes(&self) -> &[u32];

    /// Tools needed for this strategy.
    fn required_tools(&self) -> &[&str];

    /// Returns the execution mode for this strategy.
    ///
    /// Template-mode strategies produce structured checklists; direct-mode strategies
    /// perform actual tool-grounded analysis. Default is [`ExecutionMode::Template`].
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Template
    }

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
/// **Template-mode strategy**: Produces structured evidence templates for the poc-prover
/// agent. The `tool_output` fields contain template descriptions (prefixed with
/// `"TEMPLATE: "`), not raw tool output.
///
/// Disproof checks (Phase 1 — search for mitigations):
/// - Parameterized query / prepared statement usage
/// - ORM usage (no raw SQL)
/// - Input validation / sanitization on taint path
/// - Template auto-escape enabled
/// - Content Security Policy headers
///
/// Proof predicates (Phase 2 — search for exploitability):
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
        let ctx_type = injection_context_type(context.cwe);
        let (source_desc, sink_desc, pattern_desc) = injection_evidence_details(context.cwe);

        // Phase 1: Disproof — checklist of defensive patterns to search for
        let disproof_evidence = vec![
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for parameterized queries or prepared statements protecting {} sink (CWE-{})",
                    ctx_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: Search for parameterized query bindings, prepared statement APIs, \
                     or ORM query builders on the path to {} sink. Tools: get_taint_paths, read_function.",
                    ctx_type,
                ),
            },
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for input validation or output encoding on taint path for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: Search for input validation (allowlist, regex, type checks), \
                     output encoding (htmlspecialchars, encodeURIComponent), or template \
                     auto-escape on the data flow path to {} sink. Tools: get_taint_paths, read_function.",
                    ctx_type,
                ),
            },
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for ORM usage or Content Security Policy headers for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: Search for ORM framework usage (no raw SQL), CSP headers, \
                     or framework-level auto-escaping that would mitigate {} vulnerabilities. \
                     Tools: read_function, query_graph.",
                    ctx_type,
                ),
            },
        ];

        // Phase 2: Proof — vulnerability indicators to search for
        let proof_evidence = vec![
            Evidence {
                kind: EvidenceKind::TaintPath,
                description: format!(
                    "Taint path from attacker-controlled input to {} sink in case {}",
                    ctx_type, context.case_id,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"source\": \"user_input\", \"sink\": \"{}\", \"cwe\": {}, \"sanitizers\": []}}",
                    ctx_type, context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::DataFlowSource,
                description: source_desc.to_string(),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"source_type\": \"attacker_controlled\", \"context\": \"{}\", \"cwe\": {}}}",
                    ctx_type, context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::PatternMatch,
                description: pattern_desc.to_string(),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: {{\"pattern\": \"{}\", \"sink_type\": \"{}\", \"cwe\": {}}}",
                    sink_desc, ctx_type, context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::CallChain,
                description: format!(
                    "Reachable call chain from entry point to {} sink for CWE-{}",
                    ctx_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"chain\": [\"entry_point\", \"handler\", \"{}_sink\"], \"reachable\": true}}",
                    ctx_type.replace('/', "_"),
                ),
            },
        ];

        let reasoning = format!(
            "Injection proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Generated checklist for parameterized queries, ORM usage, \
             input validation, template auto-escape, CSP headers.\n\
             Phase 2 (Proof): Generated templates for taint path from attacker-controlled \
             source to {context_type} sink, pattern match, and call chain reachability.\n\
             Evidence: 3 disproof templates + TaintPath + DataFlowSource + PatternMatch + CallChain.",
            cwe = context.cwe,
            case = context.case_id,
            context_type = ctx_type,
        );

        Ok((disproof_evidence, proof_evidence, reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        context: &ProofContext,
        proof_evidence: &[Evidence],
    ) -> Option<String> {
        let payload = match context.cwe {
            89 => "' OR 1=1 --",
            79 => "<script>alert(1)</script>",
            78 => "; cat /etc/passwd",
            94 => "eval(malicious_code)",
            90 => "*)(uid=*))(|(uid=*",
            77 => "; malicious_command",
            917 => "${T(java.lang.Runtime).getRuntime().exec('cmd')}",
            _ => return None,
        };
        // M3: Reference actual proof evidence locations instead of generic text
        let evidence_refs: Vec<String> = proof_evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::TaintPath || e.kind == EvidenceKind::DataFlowSource)
            .map(|e| format!("{} ({})", e.location, e.description))
            .collect();
        let ref_text = if evidence_refs.is_empty() {
            "no taint path identified".to_string()
        } else {
            evidence_refs.join("; ")
        };
        Some(format!(
            "UNTESTED HYPOTHESIS: Input \"{payload}\" through [{ref_text}] may exploit CWE-{cwe} {ctx}",
            payload = payload,
            ref_text = ref_text,
            cwe = context.cwe,
            ctx = injection_context_type(context.cwe),
        ))
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

/// Returns (source_description, sink_description, pattern_description) for a given injection CWE.
fn injection_evidence_details(cwe: u32) -> (&'static str, &'static str, &'static str) {
    match cwe {
        89 => (
            "Attacker-controlled input (HTTP parameter/form field) flows to SQL query without parameterization",
            "string_concat_sql",
            "String concatenation directly into SQL query without prepared statement or parameterized binding",
        ),
        79 => (
            "Attacker-controlled input (HTTP parameter/form field) rendered in HTML output without encoding",
            "unescaped_html_output",
            "User input reflected in HTML/JavaScript context without output encoding or template auto-escape",
        ),
        78 => (
            "Attacker-controlled input passed to OS command execution function (exec/system/popen)",
            "os_command_exec",
            "User input concatenated into OS command string without shell escaping or allowlist validation",
        ),
        94 => (
            "Attacker-controlled input passed to code evaluation function (eval/exec/Function constructor)",
            "code_eval",
            "User input flows to dynamic code evaluation without sandboxing or input restriction",
        ),
        90 => (
            "Attacker-controlled input concatenated into LDAP search filter without escaping",
            "ldap_filter_concat",
            "User input injected into LDAP filter string without LDAP-specific character escaping",
        ),
        77 => (
            "Attacker-controlled input passed indirectly to OS command via library or wrapper function",
            "indirect_command_exec",
            "User input reaches command execution through indirect invocation without argument sanitization",
        ),
        917 => (
            "Attacker-controlled input evaluated in expression language context (EL/SpEL/OGNL/MVEL)",
            "expression_language_eval",
            "User input interpreted as expression language without sandbox or expression type restriction",
        ),
        _ => (
            "Attacker-controlled input reaches dangerous sink without validation",
            "generic_injection_sink",
            "User input flows to potentially dangerous operation without proper sanitization",
        ),
    }
}

// ---------------------------------------------------------------------------
// Path traversal proof strategy (CWE-22)
// ---------------------------------------------------------------------------

/// Proves path traversal vulnerabilities via file path taint analysis.
///
/// **Template-mode strategy**: Produces structured evidence templates for the poc-prover
/// agent.
///
/// Disproof checks (Phase 1): path canonicalization, allowlist validation, chroot/jail usage.
/// Proof predicates (Phase 2): user-controlled path to file operation, no normalization.
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
        let traversal_type = match context.cwe {
            22 => "relative path traversal (../ sequences)",
            23 => "relative path traversal with directory escape",
            36 => "absolute path traversal",
            _ => "path traversal",
        };

        // Phase 1: Disproof — checklist of defensive patterns to search for
        let disproof_evidence = vec![
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for path canonicalization (realpath/canonical) before file operation (CWE-{})",
                    context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: "TEMPLATE: Search for realpath(), canonicalize(), or path normalization \
                     calls before the file system operation. Verify the canonical path is \
                     checked against an allowed prefix. Tools: read_function, get_taint_paths.".to_string(),
            },
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for allowlist validation or chroot/jail for {} (CWE-{})",
                    traversal_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: Search for path allowlist checks (starts_with, prefix validation), \
                     chroot/jail confinement, or sandbox restrictions that prevent {} from \
                     accessing files outside the intended directory. Tools: read_function, get_callers.",
                    traversal_type,
                ),
            },
        ];

        // Phase 2: Proof — vulnerability indicators
        let proof_evidence = vec![
            Evidence {
                kind: EvidenceKind::TaintPath,
                description: format!(
                    "Taint path from user-controlled filename/path input to file system operation in case {}",
                    context.case_id,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"source\": \"user_path_input\", \"sink\": \"file_operation\", \"cwe\": {}, \"type\": \"{}\"}}",
                    context.cwe, traversal_type,
                ),
            },
            Evidence {
                kind: EvidenceKind::DataFlowSource,
                description: format!(
                    "User-controlled file path input (HTTP parameter, API argument, or form field) used in {} for CWE-{}",
                    traversal_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"source_type\": \"user_controlled_path\", \"cwe\": {}, \"traversal_type\": \"{}\"}}",
                    context.cwe, traversal_type,
                ),
            },
            Evidence {
                kind: EvidenceKind::PatternMatch,
                description: format!(
                    "File system access using user input without path canonicalization, chroot, or allowlist check ({})",
                    traversal_type,
                ),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: {{\"pattern\": \"unvalidated_file_access\", \"missing_controls\": [\"realpath\", \"chroot\", \"allowlist\"], \"cwe\": {}}}",
                    context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::CallChain,
                description: format!(
                    "Reachable call chain from entry point to file system operation for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"chain\": [\"entry_point\", \"path_handler\", \"file_operation\"], \"reachable\": true, \"cwe\": {}}}",
                    context.cwe,
                ),
            },
        ];

        let reasoning = format!(
            "Path traversal proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Generated checklist for path canonicalization, chroot/jail, \
             allowlist validation, realpath() usage, prefix checks.\n\
             Phase 2 (Proof): Generated templates for user-controlled path to file operation, \
             missing path normalization, traversal type: {traversal_type}.\n\
             Evidence: 2 disproof templates + TaintPath + DataFlowSource + PatternMatch + CallChain.",
            cwe = context.cwe,
            case = context.case_id,
            traversal_type = traversal_type,
        );

        Ok((disproof_evidence, proof_evidence, reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        context: &ProofContext,
        proof_evidence: &[Evidence],
    ) -> Option<String> {
        let payload = match context.cwe {
            22 => "../../../etc/passwd",
            23 => "..\\..\\..\\etc\\passwd",
            36 => "/etc/passwd",
            _ => "../../../etc/passwd",
        };
        // M3: Reference actual proof evidence locations
        let evidence_refs: Vec<String> = proof_evidence
            .iter()
            .filter(|e| e.kind == EvidenceKind::TaintPath || e.kind == EvidenceKind::DataFlowSource)
            .map(|e| format!("{} ({})", e.location, e.description))
            .collect();
        let ref_text = if evidence_refs.is_empty() {
            "no taint path identified".to_string()
        } else {
            evidence_refs.join("; ")
        };
        Some(format!(
            "UNTESTED HYPOTHESIS: Input \"{payload}\" through [{ref_text}] may exploit CWE-{cwe} path traversal",
            payload = payload,
            ref_text = ref_text,
            cwe = context.cwe,
        ))
    }
}

// ---------------------------------------------------------------------------
// Memory proof strategy (CWE-121, 191, etc.)
// ---------------------------------------------------------------------------

/// Proves memory safety vulnerabilities via reachability and pattern analysis.
///
/// **Template-mode strategy**: Produces structured evidence templates for the poc-prover
/// agent.
///
/// Disproof checks (Phase 1): bounds checking, safe APIs, ASLR/DEP, stack canaries.
/// Proof predicates (Phase 2): attacker-influenced value to vulnerable operation.
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
        let (vuln_type, pattern_desc) = memory_evidence_details(context.cwe);

        // Phase 1: Disproof — checklist of defensive patterns to search for
        let disproof_evidence = vec![
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for bounds checking or size validation before {} operation (CWE-{})",
                    vuln_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: Search for bounds checks (length validation, size comparisons), \
                     safe API wrappers (strncpy vs strcpy, snprintf vs sprintf), or \
                     range-checked arithmetic before the {} operation. Tools: read_function, get_taint_paths.",
                    vuln_type,
                ),
            },
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for compiler protections (ASLR/DEP/stack canaries) for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: Check for compiler-level protections: stack canaries (-fstack-protector), \
                     ASLR, DEP/NX, AddressSanitizer annotations, or safe language wrappers \
                     that mitigate {} vulnerabilities. Tools: read_function, query_graph.",
                    vuln_type,
                ),
            },
        ];

        // Phase 2: Proof — vulnerability indicators
        let proof_evidence = vec![
            Evidence {
                kind: EvidenceKind::PatternMatch,
                description: format!(
                    "Memory safety pattern: {} in case {} (CWE-{})",
                    pattern_desc, context.case_id, context.cwe,
                ),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: {{\"pattern\": \"{}\", \"vuln_type\": \"{}\", \"cwe\": {}}}",
                    pattern_desc, vuln_type, context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::DataFlowSource,
                description: format!(
                    "Attacker-influenced value (size, index, or pointer) reaches {} operation for CWE-{}",
                    vuln_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"source_type\": \"attacker_influenced_value\", \"operation\": \"{}\", \"cwe\": {}}}",
                    vuln_type, context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::CallChain,
                description: format!(
                    "Reachable path from entry point to vulnerable {} operation for CWE-{}",
                    vuln_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: {{\"chain\": [\"entry_point\", \"data_handler\", \"{}_operation\"], \"reachable\": true}}",
                    vuln_type,
                ),
            },
        ];

        let reasoning = format!(
            "Memory safety proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Generated checklist for bounds checks, safe API wrappers, \
             compiler protections (stack canaries, ASAN annotations), \
             size validation before write operations.\n\
             Phase 2 (Proof): Generated templates for {vuln_type} pattern, attacker-influenced \
             value reaching vulnerable operation.\n\
             NOTE: Static reachability is weaker than dynamic proof. \
             Verdicts for memory CWEs should be treated with extra scrutiny.\n\
             Evidence: 2 disproof templates + PatternMatch + DataFlowSource + CallChain.",
            cwe = context.cwe,
            case = context.case_id,
            vuln_type = vuln_type,
        );

        Ok((disproof_evidence, proof_evidence, reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        context: &ProofContext,
        proof_evidence: &[Evidence],
    ) -> Option<String> {
        let desc = match context.cwe {
            119..=122 => "buffer corruption via oversized input",
            190 | 191 => "integer overflow/underflow on attacker-controlled value",
            416 => "use-after-free via identified allocation path",
            _ => return None,
        };
        // M3: Reference actual proof evidence locations
        let evidence_refs: Vec<String> = proof_evidence
            .iter()
            .map(|e| format!("{} ({})", e.location, e.description))
            .collect();
        let ref_text = if evidence_refs.is_empty() {
            "no evidence path identified".to_string()
        } else {
            evidence_refs.join("; ")
        };
        Some(format!(
            "UNTESTED HYPOTHESIS: {desc} at [{ref_text}] may be exploitable (CWE-{cwe})",
            desc = desc,
            ref_text = ref_text,
            cwe = context.cwe,
        ))
    }
}

// ---------------------------------------------------------------------------
// Config/crypto proof strategy (CWE-614, 327, etc.)
// ---------------------------------------------------------------------------

/// Proves configuration and cryptographic weaknesses via pattern analysis.
///
/// **Template-mode strategy**: Produces structured evidence templates for the poc-prover
/// agent.
///
/// Disproof checks (Phase 1): secure defaults, config validation, least privilege.
/// Proof predicates (Phase 2): insecure configuration pattern in production path.
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
        let (config_type, pattern_desc) = config_evidence_details(context.cwe);

        // Phase 1: Disproof — checklist of defensive patterns to search for
        let disproof_evidence = vec![
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for secure defaults or override configuration for {} (CWE-{})",
                    config_type, context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: Search for global secure-by-default settings, environment-specific \
                     overrides, or wrapper functions that enforce secure {} configuration. \
                     Check for migration path to secure alternatives. Tools: read_function, query_graph.",
                    config_type,
                ),
            },
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for config validation or least privilege enforcement for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: Search for configuration validation logic, principle of least \
                     privilege enforcement, or deployment-time security controls that mitigate \
                     {} vulnerabilities. Tools: read_function, get_callers.",
                    config_type,
                ),
            },
        ];

        // Phase 2: Proof — vulnerability indicators
        let proof_evidence = vec![Evidence {
            kind: EvidenceKind::PatternMatch,
            description: format!(
                "Insecure configuration pattern: {} in case {} (CWE-{})",
                pattern_desc, context.case_id, context.cwe,
            ),
            location: format!("{}:case:{}", context.suite, context.case_id),
            tool_output: format!(
                "TEMPLATE: {{\"pattern\": \"{}\", \"config_type\": \"{}\", \"cwe\": {}}}",
                pattern_desc, config_type, context.cwe,
            ),
        }];

        let reasoning = format!(
            "Configuration/crypto proof strategy for CWE-{cwe} on case {case}:\n\
             Phase 1 (Disproof): Generated checklist for override configuration, global \
             secure-by-default settings, wrapper functions, migration path \
             to secure algorithms.\n\
             Phase 2 (Proof): Generated template for {config_type} pattern in production \
             code path.\n\
             Evidence: 2 disproof templates + PatternMatch (score=1, Insufficient — config \
             issues require manual verification of deployment context).",
            cwe = context.cwe,
            case = context.case_id,
            config_type = config_type,
        );

        Ok((disproof_evidence, proof_evidence, reasoning))
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
// Generic strategy
// ---------------------------------------------------------------------------

/// Generic strategy for CWEs without a specialized proof strategy.
///
/// **Template-mode strategy**: Produces structured evidence templates for the poc-prover
/// agent.
///
/// Disproof checks (Phase 1): input validation, error handling, defensive patterns.
/// Proof predicates (Phase 2): generic vulnerability pattern via taint analysis.
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
        // Phase 1: Disproof — checklist of defensive patterns to search for
        let disproof_evidence = vec![
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for input validation or sanitization for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:finding:{}", context.suite, context.finding_id),
                tool_output: format!(
                    "TEMPLATE: Search for input validation (type checks, allowlists, regex), \
                     sanitization functions, or encoding applied to user-controlled data \
                     before it reaches the vulnerable operation for CWE-{}. \
                     Tools: get_taint_paths, read_function.",
                    context.cwe,
                ),
            },
            Evidence {
                kind: EvidenceKind::MitigationFound,
                description: format!(
                    "Check for error handling or defensive patterns for CWE-{}",
                    context.cwe,
                ),
                location: format!("{}:case:{}", context.suite, context.case_id),
                tool_output: format!(
                    "TEMPLATE: Search for error handling, guard clauses, safe wrappers, \
                     or other defensive coding patterns that mitigate CWE-{}. \
                     Tools: read_function, get_callers, query_graph.",
                    context.cwe,
                ),
            },
        ];

        // Phase 2: Proof — vulnerability indicators
        let proof_evidence = vec![Evidence {
            kind: EvidenceKind::PatternMatch,
            description: format!(
                "Potential vulnerability pattern for CWE-{} detected in case {} \
                     via generic analysis (no specialized strategy available)",
                context.cwe, context.case_id,
            ),
            location: format!("{}:case:{}", context.suite, context.case_id),
            tool_output: format!(
                "TEMPLATE: {{\"pattern\": \"generic_vuln_pattern\", \"cwe\": {}, \"detected_cwes\": {:?}}}",
                context.cwe, context.detected_cwes,
            ),
        }];

        let reasoning = format!(
            "Generic proof strategy for CWE-{cwe} on case {case}:\n\
             No specialized strategy available for this CWE. Using generic \
             taint analysis and pattern matching.\n\
             Phase 1 (Disproof): Generated checklist for guards, validation, safe wrappers.\n\
             Phase 2 (Proof): Generated template for potential vulnerability pattern via \
             generic analysis.\n\
             Evidence: 2 disproof templates + PatternMatch (score=1, Insufficient — generic \
             analysis cannot provide strong evidence without CWE-specific strategy).",
            cwe = context.cwe,
            case = context.case_id,
        );

        Ok((disproof_evidence, proof_evidence, reasoning))
    }

    fn generate_exploit_sketch(
        &self,
        _context: &ProofContext,
        _proof_evidence: &[Evidence],
    ) -> Option<String> {
        None
    }
}

/// Returns (vulnerability_type, pattern_description) for memory CWEs.
fn memory_evidence_details(cwe: u32) -> (&'static str, &'static str) {
    match cwe {
        119 => (
            "buffer_overflow",
            "Improper restriction of operations within the bounds of a memory buffer",
        ),
        120 => (
            "buffer_copy",
            "Buffer copy without checking size of input (classic buffer overflow)",
        ),
        121 => (
            "stack_buffer_overflow",
            "Stack-based buffer overflow — write exceeds stack buffer allocation",
        ),
        122 => (
            "heap_buffer_overflow",
            "Heap-based buffer overflow — write exceeds heap buffer allocation",
        ),
        124 => (
            "buffer_underwrite",
            "Buffer underwrite — write before beginning of buffer",
        ),
        125 => ("oob_read", "Out-of-bounds read — read past end of buffer"),
        126 => (
            "buffer_over_read",
            "Buffer over-read — read past intended buffer boundary",
        ),
        127 => (
            "buffer_under_read",
            "Buffer under-read — read before beginning of buffer",
        ),
        190 => (
            "integer_overflow",
            "Integer overflow or wraparound — arithmetic exceeds max value",
        ),
        191 => (
            "integer_underflow",
            "Integer underflow or wraparound — arithmetic goes below min value",
        ),
        416 => (
            "use_after_free",
            "Use after free — memory accessed after deallocation",
        ),
        415 => ("double_free", "Double free — memory freed multiple times"),
        _ => ("memory_safety", "Generic memory safety issue"),
    }
}

/// Returns (config_type, pattern_description) for config/crypto CWEs.
fn config_evidence_details(cwe: u32) -> (&'static str, &'static str) {
    match cwe {
        614 => (
            "missing_secure_flag",
            "Cookie set without Secure flag, allowing transmission over unencrypted HTTP",
        ),
        327 => (
            "broken_crypto_algorithm",
            "Use of a broken or risky cryptographic algorithm (e.g., DES, RC4, MD5 for auth)",
        ),
        328 => (
            "weak_hash",
            "Use of weak hash function (e.g., MD5, SHA1) for security-sensitive operations",
        ),
        259 => (
            "hardcoded_password",
            "Hard-coded password used in source code",
        ),
        798 => (
            "hardcoded_credentials",
            "Hard-coded credentials (username/password/key) embedded in source",
        ),
        200 => (
            "info_exposure",
            "Exposure of sensitive information to unauthorized actors",
        ),
        311 => (
            "missing_encryption",
            "Missing encryption of sensitive data in transit or at rest",
        ),
        319 => (
            "cleartext_transmission",
            "Cleartext transmission of sensitive information",
        ),
        _ => (
            "insecure_config",
            "Insecure configuration or cryptographic practice",
        ),
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

    // --- New tests for non-empty evidence generation ---

    fn make_context(cwe: u32) -> ProofContext {
        ProofContext {
            case_id: format!("test-case-{}", cwe),
            suite: "test-suite".into(),
            cwe,
            detected_cwes: vec![cwe],
            finding_id: format!("f-{}", cwe),
        }
    }

    #[test]
    fn test_injection_execute_all_cwes() {
        let strategy = InjectionProofStrategy;
        for cwe in &[89, 79, 78, 94, 90, 77, 917] {
            let ctx = make_context(*cwe);
            let (disproof, proof, reasoning) = strategy.execute(&ctx).unwrap();
            assert!(
                !disproof.is_empty(),
                "CWE-{}: should have disproof evidence",
                cwe
            );
            assert!(!proof.is_empty(), "CWE-{}: should have proof evidence", cwe);
            assert!(
                proof.len() >= 3,
                "CWE-{}: need ≥3 proof items for Moderate",
                cwe
            );
            assert!(
                !reasoning.is_empty(),
                "CWE-{}: reasoning should not be empty",
                cwe
            );

            // Verify disproof evidence kinds are all MitigationFound
            for ev in &disproof {
                assert_eq!(
                    ev.kind,
                    EvidenceKind::MitigationFound,
                    "CWE-{}: disproof evidence should be MitigationFound",
                    cwe,
                );
            }

            // Verify proof evidence kinds present
            let kinds: Vec<_> = proof.iter().map(|e| &e.kind).collect();
            assert!(
                kinds.contains(&&EvidenceKind::TaintPath),
                "CWE-{}: missing TaintPath",
                cwe
            );
            assert!(
                kinds.contains(&&EvidenceKind::DataFlowSource),
                "CWE-{}: missing DataFlowSource",
                cwe
            );
            assert!(
                kinds.contains(&&EvidenceKind::PatternMatch),
                "CWE-{}: missing PatternMatch",
                cwe
            );
        }
    }

    #[test]
    fn test_injection_scores_disproven_with_templates() {
        use super::super::score_evidence;
        let strategy = InjectionProofStrategy;
        let ctx = make_context(89);
        let (disproof, proof, _) = strategy.execute(&ctx).unwrap();
        // With disproof templates present, score_evidence returns Disproven
        let (score, verdict) = score_evidence(&disproof, &proof);
        assert_eq!(score, super::super::EvidenceScore::Disproven);
        assert_eq!(verdict, super::super::PocVerdict::Disproven);
    }

    #[test]
    fn test_injection_exploit_sketch_all_cwes() {
        let strategy = InjectionProofStrategy;
        for cwe in &[89, 79, 78, 94, 90, 77, 917] {
            let ctx = make_context(*cwe);
            let sketch = strategy.generate_exploit_sketch(&ctx, &[]);
            assert!(sketch.is_some(), "CWE-{}: should have exploit sketch", cwe);
            assert!(
                sketch.as_ref().unwrap().starts_with("UNTESTED HYPOTHESIS"),
                "CWE-{}: sketch should start with 'UNTESTED HYPOTHESIS'",
                cwe,
            );
        }
    }

    #[test]
    fn test_path_traversal_execute_all_cwes() {
        let strategy = PathTraversalProofStrategy;
        for cwe in &[22, 23, 36] {
            let ctx = make_context(*cwe);
            let (disproof, proof, reasoning) = strategy.execute(&ctx).unwrap();
            assert!(
                !disproof.is_empty(),
                "CWE-{}: should have disproof evidence",
                cwe
            );
            assert!(!proof.is_empty(), "CWE-{}: should have proof evidence", cwe);
            assert!(proof.len() >= 3, "CWE-{}: need ≥3 proof items", cwe);
            assert!(!reasoning.is_empty());
        }
    }

    #[test]
    fn test_path_traversal_scores_disproven_with_templates() {
        use super::super::score_evidence;
        let strategy = PathTraversalProofStrategy;
        let ctx = make_context(22);
        let (disproof, proof, _) = strategy.execute(&ctx).unwrap();
        // With disproof templates present, score_evidence returns Disproven
        let (score, verdict) = score_evidence(&disproof, &proof);
        assert_eq!(score, super::super::EvidenceScore::Disproven);
        assert_eq!(verdict, super::super::PocVerdict::Disproven);
    }

    #[test]
    fn test_path_traversal_exploit_sketch_all_cwes() {
        let strategy = PathTraversalProofStrategy;
        for cwe in &[22, 23, 36] {
            let ctx = make_context(*cwe);
            let sketch = strategy.generate_exploit_sketch(&ctx, &[]);
            assert!(sketch.is_some(), "CWE-{}: should have exploit sketch", cwe);
            assert!(sketch.unwrap().starts_with("UNTESTED HYPOTHESIS"));
        }
    }

    #[test]
    fn test_memory_execute_produces_evidence() {
        let strategy = MemoryProofStrategy;
        for cwe in &[121, 191, 416] {
            let ctx = make_context(*cwe);
            let (disproof, proof, reasoning) = strategy.execute(&ctx).unwrap();
            assert!(
                !disproof.is_empty(),
                "CWE-{}: should have disproof evidence",
                cwe
            );
            assert!(!proof.is_empty(), "CWE-{}: should have proof evidence", cwe);
            assert!(!reasoning.is_empty());

            let has_pattern = proof.iter().any(|e| e.kind == EvidenceKind::PatternMatch);
            assert!(
                has_pattern,
                "CWE-{}: should have PatternMatch evidence",
                cwe
            );
        }
    }

    #[test]
    fn test_config_execute_produces_evidence() {
        let strategy = ConfigProofStrategy;
        for cwe in &[614, 327, 798] {
            let ctx = make_context(*cwe);
            let (disproof, proof, reasoning) = strategy.execute(&ctx).unwrap();
            assert!(
                !disproof.is_empty(),
                "CWE-{}: should have disproof evidence",
                cwe
            );
            assert!(!proof.is_empty(), "CWE-{}: should have proof evidence", cwe);
            assert!(!reasoning.is_empty());

            let has_pattern = proof.iter().any(|e| e.kind == EvidenceKind::PatternMatch);
            assert!(
                has_pattern,
                "CWE-{}: should have PatternMatch evidence",
                cwe
            );
        }
    }

    #[test]
    fn test_generic_execute_produces_evidence() {
        let strategy = GenericProofStrategy;
        let ctx = make_context(999);
        let (disproof, proof, reasoning) = strategy.execute(&ctx).unwrap();
        assert!(
            !disproof.is_empty(),
            "Generic should have disproof evidence"
        );
        assert!(!proof.is_empty(), "Generic should have proof evidence");
        assert!(!reasoning.is_empty());

        let has_pattern = proof.iter().any(|e| e.kind == EvidenceKind::PatternMatch);
        assert!(has_pattern, "Generic should have PatternMatch evidence");
    }

    #[test]
    fn test_no_strategy_returns_empty_evidence() {
        // Verify the H1 fix: no strategy returns empty evidence vectors
        let test_cwes: &[u32] = &[
            89, 79, 78, 94, 90, 77, 917, 22, 23, 36, 121, 191, 614, 327, 999,
        ];
        for cwe in test_cwes {
            let strategy = select_strategy(*cwe);
            let ctx = make_context(*cwe);
            let (_, proof, _) = strategy.execute(&ctx).unwrap();
            assert!(
                !proof.is_empty(),
                "CWE-{} ({}) must produce non-empty evidence",
                cwe,
                strategy.name(),
            );
        }
    }
}
