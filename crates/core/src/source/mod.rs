//! Source code ingestion and parsing.

pub mod parser;
pub mod tree_sitter_flow;

pub use parser::{
    detect_language, is_source_file, parse_file, parse_source, ExtractedCall, ExtractedFunction,
    ExtractedString, ParsedFile, ParsedFunction, ParsedSource, SOURCE_EXTENSIONS,
};
