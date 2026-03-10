//! Report generation in multiple formats: SARIF, Markdown, and JSON.

pub mod json;
pub mod markdown;
pub mod sarif;

pub use json::{generate_json, generate_report_for_investigation};
pub use markdown::{generate_markdown, generate_markdown_for_investigation};
pub use sarif::{generate_sarif, generate_sarif_for_investigation};
