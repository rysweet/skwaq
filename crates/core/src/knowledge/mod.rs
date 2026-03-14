//! Knowledge bases: CWE definitions and vulnerability pattern catalogues.

pub mod cwe;
pub mod patterns;
pub mod search;

pub use cwe::CweDatabase;
pub use patterns::VulnerabilityPatterns;
pub use search::{
    find_knowledge_dir, initialize_cwe_catalog, search_knowledge, InitSummary, KnowledgeHit,
};
