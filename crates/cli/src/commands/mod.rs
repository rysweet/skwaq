//! CLI command definitions using clap derive.

pub mod analyze;
pub mod checksec_cmd;
pub mod doctor;
pub mod ingest;
pub mod investigate;
pub mod report;
pub mod strings_cmd;
pub mod symbols_cmd;
pub mod version_cmd;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "skwaq",
    about = "Vulnerability assessment copilot",
    version,
    propagate_version = true
)]
pub struct Cli {
    /// Increase log verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Ingest a binary, source tree, or SARIF report
    Ingest {
        #[command(subcommand)]
        sub: IngestSub,
    },

    /// Decompile a binary using Ghidra
    Decompile {
        /// Path to the binary
        binary: PathBuf,
    },

    /// Disassemble a binary
    Disassemble {
        /// Path to the binary
        binary: PathBuf,
    },

    /// Extract printable strings from a binary
    Strings {
        /// Path to the binary
        binary: PathBuf,

        /// Minimum string length
        #[arg(short = 'n', long, default_value = "4")]
        min_length: usize,
    },

    /// List symbols from a binary
    Symbols {
        /// Path to the binary
        binary: PathBuf,
    },

    /// Show binary hardening status (checksec)
    Checksec {
        /// Path to the binary
        binary: PathBuf,
    },

    /// Find cross-references to/from a function
    Xrefs {
        /// Function name or address
        function: String,
    },

    /// Map the attack surface
    Surface,

    /// Run AI-driven vulnerability analysis
    Analyze {
        /// Investigation ID to analyze (uses most recent if omitted)
        #[arg(long)]
        investigation: Option<String>,

        /// Quick scan (reduced depth)
        #[arg(long)]
        quick: bool,

        /// Token budget for LLM calls
        #[arg(long)]
        budget: Option<u64>,
    },

    /// Trace taint flows between sources and sinks
    Taint {
        /// Taint source function
        #[arg(long)]
        source: Option<String>,

        /// Taint sink function
        #[arg(long)]
        sink: Option<String>,
    },

    /// Find functions similar to a given function
    FindSimilar {
        /// Function name to compare
        #[arg(long)]
        function: String,
    },

    /// Manage investigations
    Investigate {
        #[command(subcommand)]
        sub: InvestigateSub,
    },

    /// Annotate a function or finding
    Annotate {
        /// Target (function name, finding ID, etc.)
        target: String,

        /// Annotation text
        text: String,
    },

    /// Generate hypotheses about potential vulnerabilities
    Hypothesize {
        /// Optional focus area
        focus: Option<String>,
    },

    /// Generate reports
    Report {
        /// Investigation ID (uses most recent if omitted)
        investigation_id: Option<String>,

        /// Output SARIF format
        #[arg(long)]
        sarif: bool,

        /// Output JSON format
        #[arg(long)]
        json: bool,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Visualize analysis results
    Viz {
        #[command(subcommand)]
        sub: VizSub,
    },

    /// Knowledge base operations
    Kb {
        #[command(subcommand)]
        sub: KbSub,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        sub: ConfigSub,
    },

    /// Check system dependencies and connectivity
    Doctor,

    /// Show version information
    Version,
}

#[derive(Subcommand)]
pub enum IngestSub {
    /// Ingest a binary file
    Binary {
        /// Path to the binary
        path: PathBuf,
    },
    /// Ingest a source code directory
    Source {
        /// Path to the source tree
        path: PathBuf,
    },
    /// Import a SARIF report
    Sarif {
        /// Path to the SARIF file
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum InvestigateSub {
    /// Create a new investigation
    New {
        /// Investigation name
        name: String,
    },
    /// Resume an existing investigation
    Resume {
        /// Investigation ID
        id: String,
    },
    /// List all investigations
    List,
    /// Export investigation results
    Export {
        /// Investigation ID
        id: String,
        /// Output path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum VizSub {
    /// Show call graph
    Callgraph {
        /// Root function
        function: Option<String>,
    },
    /// Show taint flow diagram
    Taint,
    /// Show decompiled code
    Decompile {
        /// Function name
        function: String,
    },
    /// Show findings summary
    Findings,
}

#[derive(Subcommand)]
pub enum KbSub {
    /// Initialize the knowledge base with CWE data
    Init,
    /// Search the knowledge base
    Search {
        /// Search query
        query: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigSub {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
}
