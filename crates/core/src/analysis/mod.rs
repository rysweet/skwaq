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
pub use patterns::DangerousApiDetector;
pub use semgrep::SemgrepRunner;
pub use severity::compute_severity;
pub use surface::AttackSurfaceAnalyzer;
pub use taint::TaintAnalyzer;
pub use variant::VariantAnalyzer;
