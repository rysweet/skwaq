//! Analysis modules: taint tracking, pattern detection, hardening,
//! attack surface, variant analysis, severity scoring, Semgrep,
//! multi-cycle orchestration, findings model, and perspectives.

pub mod findings;
pub mod hardening;
pub mod orchestrator;
pub mod patterns;
pub mod patterns_binary;
pub mod patterns_source;
pub mod perspective_context;
pub mod perspective_dataflow;
pub mod perspective_pattern;
pub mod semantic_classifier;
pub mod semgrep;
pub mod severity;
pub mod surface;
pub mod surface_binary;
pub mod surface_source;
pub mod taint;
pub mod variant;

pub use findings::{Finding, FindingLocation, FindingStatus, FindingUpdate};
pub use hardening::format_hardening;
pub use orchestrator::{AnalysisCycle, AnalysisOrchestrator};
pub use patterns::{DangerCategory, DangerousApiHit, Severity};
pub use patterns_binary::DangerousApiDetector;
pub use perspective_context::context_perspective;
pub use perspective_dataflow::dataflow_perspective;
pub use perspective_pattern::pattern_perspective;
pub use semantic_classifier::{
    extract_function_from_title, extract_line_from_title, SemanticPatternClass,
    SemanticPatternClassifier,
};
pub use semgrep::SemgrepRunner;
pub use severity::compute_severity;
pub use surface::{
    identify_attack_surface, identify_source_sinks, identify_source_sinks_in_content,
    AttackSurface, AttackSurfaceAnalyzer, SourceSinkHit, SourceSinkKind,
};
pub use taint::{TaintAnalyzer, TaintPath};
pub use variant::VariantAnalyzer;
