//! Durable agent memory: cross-run learning for vulnerability analysis agents.
//!
//! Adapted from amplihack-memory-lib's cognitive memory model. Agents store
//! experiences (successes, failures, patterns, insights) and recall relevant
//! memories to improve across benchmark runs without overfitting to specific
//! targets.
//!
//! # Architecture
//!
//! - **MemoryStore**: SQLite-backed persistent storage (separate from the
//!   investigation graph DB so memories span all investigations).
//! - **Experience**: The core unit of memory — what happened, what the agent
//!   learned, and how confident it is.
//! - **PatternDetector**: Recognizes recurring patterns from experiences and
//!   promotes them to high-confidence generalized knowledge.
//! - **Anti-overfitting**: Confidence decay, generalization scoring, and
//!   investigation-tag filtering prevent agents from memorizing benchmark
//!   specifics.

pub mod experience;
pub mod pattern;
pub mod store;

pub use experience::{Experience, ExperienceType};
pub use pattern::PatternDetector;
pub use store::MemoryStore;
