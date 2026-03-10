//! Investigation lifecycle: creation, annotation, and hypothesis tracking.

pub mod annotations;
pub mod hypotheses;
pub mod manager;

pub use annotations::AnnotationManager;
pub use hypotheses::HypothesisManager;
pub use manager::InvestigationManager;
