//! skwaq-agents: AI agent implementations for the vulnerability
//! assessment copilot.
//!
//! This crate re-exports the dynamic agent system from `skwaq-core::agents`
//! and provides backward-compatible wrappers for the original hardcoded agents.

pub mod budget;
pub mod critic;
pub mod prompts;
pub mod tool_executor;
pub mod tools;
pub mod vuln_hunter;

// Re-export the dynamic agent system from core.
pub use skwaq_core::agents as dynamic;
