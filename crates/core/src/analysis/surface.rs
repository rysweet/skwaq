//! Attack surface analysis.
//!
//! Re-exports from submodules:
//! - `surface_binary`: binary-level import categorization
//! - `surface_source`: source-level source/sink identification

pub use super::surface_binary::{
    identify_attack_surface, AttackSurface, AttackSurfaceAnalyzer, SurfaceEntry, SINK_PATTERNS,
    SOURCE_PATTERNS,
};
pub use super::surface_source::{
    identify_source_sinks, identify_source_sinks_in_content, SourceSinkHit, SourceSinkKind,
};
