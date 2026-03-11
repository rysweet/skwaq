//! CLI dispatch for `skwaq gym *` subcommands.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GymSub {
    /// Download and prepare all benchmark data
    Setup,

    /// Run benchmarks
    Run {
        /// Suite name (fixtures). Omit for all.
        suite: Option<String>,

        /// Filter to specific CWE (e.g., CWE-119)
        #[arg(long)]
        cwe: Option<String>,

        /// Maximum test cases per suite (for quick validation)
        #[arg(long)]
        max_cases: Option<usize>,

        /// Use full analysis (default is quick mode)
        #[arg(long)]
        full: bool,

        /// Output JSON report to file
        #[arg(long)]
        json: Option<PathBuf>,

        /// Output Markdown report to file
        #[arg(long)]
        markdown: Option<PathBuf>,
    },

    /// Show latest benchmark results
    Report {
        /// Output format (terminal, json, markdown)
        #[arg(long, default_value = "terminal")]
        format: String,
    },

    /// Compare last two runs
    Compare,

    /// Show benchmark history
    History {
        /// Number of runs to show
        #[arg(long, default_value = "10")]
        limit: u32,
    },
}

pub async fn run(sub: &GymSub) -> anyhow::Result<()> {
    let skwaq_root = find_skwaq_root()?;
    let mut gym = skwaq_gym::Gym::new(skwaq_root)?;

    match sub {
        GymSub::Setup => {
            gym.setup().await?;
            println!("All benchmarks set up.");
        }
        GymSub::Run {
            suite,
            cwe,
            max_cases,
            full,
            json,
            markdown,
        } => {
            let cwe_filter = cwe.as_ref().map(|c| {
                let num: u32 = c
                    .trim_start_matches("CWE-")
                    .trim_start_matches("cwe-")
                    .parse()
                    .expect("Invalid CWE number");
                vec![num]
            });
            gym.run(suite.as_deref(), cwe_filter, *max_cases, *full)
                .await?;

            if let Some(path) = json {
                let report = gym.report(skwaq_gym::ReportFormat::Json)?;
                std::fs::write(path, report)?;
            }
            if let Some(path) = markdown {
                let report = gym.report(skwaq_gym::ReportFormat::Markdown)?;
                std::fs::write(path, report)?;
            }
        }
        GymSub::Report { format } => {
            let fmt = match format.as_str() {
                "json" => skwaq_gym::ReportFormat::Json,
                "markdown" | "md" => skwaq_gym::ReportFormat::Markdown,
                _ => skwaq_gym::ReportFormat::Terminal,
            };
            let output = gym.report(fmt)?;
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        GymSub::Compare => {
            gym.compare()?;
        }
        GymSub::History { limit } => {
            gym.history(*limit)?;
        }
    }

    Ok(())
}

/// Find the workspace root by looking for Cargo.toml with [workspace].
fn find_skwaq_root() -> anyhow::Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            anyhow::bail!("Could not find skwaq workspace root (Cargo.toml with [workspace])");
        }
    }
}
