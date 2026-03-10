//! Source code ingestion and parsing.

pub mod parser;

pub use parser::{detect_language, parse_file, ParsedFile, ParsedFunction};
