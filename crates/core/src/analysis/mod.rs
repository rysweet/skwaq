//! Analysis modules: taint tracking, pattern detection, hardening,
//! attack surface, variant analysis, severity scoring, and Semgrep.

pub mod hardening;
pub mod patterns;
pub mod semgrep;
pub mod severity;
pub mod surface;
pub mod taint;
pub mod variant;

pub use hardening::format_hardening;
pub use patterns::{DangerousApiDetector, DangerousApiHit, DangerCategory, Severity};
pub use semgrep::SemgrepRunner;
pub use severity::compute_severity;
pub use surface::{identify_attack_surface, AttackSurface, AttackSurfaceAnalyzer};
pub use taint::{TaintAnalyzer, TaintPath};
pub use variant::VariantAnalyzer;
