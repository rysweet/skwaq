//! Durable agent memory: cross-run learning for vulnerability analysis agents.
//!
//! Backed by LadybugDB for native graph storage. Agents store experiences
//! (successes, failures, patterns, insights) and recall relevant memories
//! to improve across benchmark runs.

pub mod experience;
pub mod pattern;
pub mod store;

pub use experience::{Experience, ExperienceType};
pub use pattern::PatternDetector;
pub use store::{MemoryStats, MemoryStore};
