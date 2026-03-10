//! Analysis modules: taint tracking, pattern detection, hardening,
//! attack surface, variant analysis, severity scoring, Semgrep,
//! multi-cycle orchestration, findings model, and perspectives.

pub mod findings;
pub mod hardening;
pub mod orchestrator;
pub mod patterns;
pub mod perspectives;
pub mod semgrep;
pub mod severity;
pub mod surface;
pub mod taint;
pub mod variant;

pub use findings::{Finding, FindingLocation, FindingStatus, FindingUpdate};
pub use hardening::format_hardening;
pub use orchestrator::{AnalysisCycle, AnalysisOrchestrator};
pub use patterns::{DangerousApiDetector, DangerousApiHit, DangerCategory, Severity};
pub use semgrep::SemgrepRunner;
pub use severity::compute_severity;
pub use surface::{
    identify_attack_surface, identify_source_sinks, identify_source_sinks_in_content,
    AttackSurface, AttackSurfaceAnalyzer, SourceSinkHit, SourceSinkKind,
};
pub use taint::{TaintAnalyzer, TaintPath};
pub use variant::VariantAnalyzer;
