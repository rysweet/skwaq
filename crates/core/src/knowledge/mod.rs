//! Knowledge bases: CWE definitions and vulnerability pattern catalogues.

pub mod cwe;
pub mod patterns;

pub use cwe::CweDatabase;
pub use patterns::VulnerabilityPatterns;
