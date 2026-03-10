//! Report generation in multiple formats: SARIF, Markdown, and JSON.

pub mod json;
pub mod markdown;
pub mod sarif;

pub use json::generate_json;
pub use markdown::generate_markdown;
pub use sarif::generate_sarif;
