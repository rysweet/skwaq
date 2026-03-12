//! CLI dispatch for `skwaq gym *` subcommands.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GymSub {
    /// Download and prepare all benchmark data
    Setup,

    /// Run benchmarks
    Run {
        /// Suite name (fixtures, juliet, cgc, cyberseceval, owasp). Omit for all.
        suite: Option<String>,

        /// Filter to specific CWE (e.g., CWE-119)
        #[arg(long)]
        cwe: Option<String>,

        /// Maximum test cases per suite (for quick validation)
        #[arg(long)]
        max_cases: Option<usize>,

        /// Use quick pattern-only mode (default is full analysis with AI agents)
        #[arg(long)]
        quick: bool,

        /// Skip the first N cases (for multi-process parallelism)
        #[arg(long, default_value = "0")]
        skip: usize,

        /// Number of cases to analyze concurrently (in-process async parallelism).
        /// Default 4 for hybrid mode, 1 for quick mode.
        #[arg(long, short = 'j')]
        concurrency: Option<usize>,

        /// Analyze source code only, skip binary analysis (binary is the default for C cases)
        #[arg(long)]
        source_only: bool,

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

    /// Run self-improvement loop: analyze failures and propose fixes
    Improve {
        /// Suite to improve (fixtures, juliet, cgc, owasp, cyberseceval)
        suite: String,

        /// Maximum cases to analyze
        #[arg(long, default_value = "20")]
        max_cases: usize,
    },

    /// Generate dashboard: mermaid charts + scores table from run history
    Dashboard,
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
            quick,
            skip,
            concurrency,
            source_only,
            json,
            markdown,
        } => {
            let cwe_filter = cwe
                .as_ref()
                .map(|c| parse_cwe_number(c).map(|n| vec![n]))
                .transpose()?;
            let binary_mode = !*source_only;
            // Default concurrency: 4 for hybrid mode, 1 for quick mode
            let conc = concurrency.unwrap_or(if *quick { 1 } else { 4 });
            gym.run(
                suite.as_deref(),
                cwe_filter,
                *max_cases,
                *quick,
                binary_mode,
                *skip,
                conc,
            )
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
        GymSub::Improve { suite, max_cases } => {
            let config = skwaq_gym::adapters::BenchmarkConfig {
                cache_dir: dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("skwaq/gym/cache"),
                cwe_filter: None,
                max_cases: Some(*max_cases),
                quick_mode: true,
                binary_mode: false,
                parallelism: 4,
                skip: 0,
                concurrency: 1,
                timeout_secs: 30,
            };

            // Find the matching adapter
            let adapters = gym.get_adapters();
            let adapter = adapters
                .iter()
                .find(|a| a.name() == suite.as_str())
                .ok_or_else(|| anyhow::anyhow!("Unknown suite: {}", suite))?;

            let data_dir = adapter.setup(&config).await?;
            let cycle =
                skwaq_gym::improve::run_improvement_cycle(adapter.as_ref(), &config, &data_dir)
                    .await?;
            skwaq_gym::improve::print_proposals(&cycle);
        }
        GymSub::Dashboard => {
            println!(
                "{}",
                skwaq_gym::dashboard::generate_charts(&gym.history_db)?
            );
            println!(
                "{}",
                skwaq_gym::dashboard::generate_scores_table(&gym.history_db)?
            );
        }
    }

    Ok(())
}

/// Parse a CWE filter string like "CWE-119", "cwe-119", or "119" into a number.
fn parse_cwe_number(s: &str) -> anyhow::Result<u32> {
    s.trim_start_matches("CWE-")
        .trim_start_matches("cwe-")
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid CWE number: '{}'. Use format: CWE-119 or 119", s))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cwe_number_plain() {
        assert_eq!(parse_cwe_number("119").unwrap(), 119);
    }

    #[test]
    fn test_parse_cwe_number_prefixed() {
        assert_eq!(parse_cwe_number("CWE-121").unwrap(), 121);
        assert_eq!(parse_cwe_number("cwe-78").unwrap(), 78);
    }

    #[test]
    fn test_parse_cwe_number_invalid() {
        let err = parse_cwe_number("not-a-number").unwrap_err();
        assert!(err.to_string().contains("Invalid CWE number"));
        assert!(err.to_string().contains("not-a-number"));
    }

    #[test]
    fn test_parse_cwe_number_empty() {
        assert!(parse_cwe_number("").is_err());
    }
}
