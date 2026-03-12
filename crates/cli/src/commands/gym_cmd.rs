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

    /// Full evaluation: run all benchmarks in parallel, collect, and report.
    /// Combines --skip, --concurrency, and multi-process execution into one command.
    Eval {
        /// Comma-separated suite list (default: all)
        #[arg(long, default_value = "fixtures,juliet,owasp,cyberseceval,cgc")]
        suites: String,

        /// Processes per suite for multi-process parallelism (1-50)
        #[arg(long, default_value = "5")]
        procs: usize,

        /// In-process async concurrency per process
        #[arg(long, short = 'j', default_value = "2")]
        concurrency: usize,

        /// Use quick pattern-only mode
        #[arg(long)]
        quick: bool,

        /// Output directory for results
        #[arg(long)]
        output: Option<PathBuf>,
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
        GymSub::Eval {
            suites,
            procs,
            concurrency,
            quick,
            output,
        } => {
            let eval_dir = output.clone().unwrap_or_else(|| {
                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                PathBuf::from(format!("/tmp/gym-eval-{}", ts))
            });
            std::fs::create_dir_all(&eval_dir)?;

            let exe = std::env::current_exe()?;
            let suite_cases: std::collections::HashMap<&str, usize> = [
                ("fixtures", 7),
                ("juliet", 5000),
                ("owasp", 2740),
                ("cyberseceval", 578),
                ("cgc", 204),
            ]
            .into_iter()
            .collect();

            let mode = if *quick { "pattern-only" } else { "hybrid" };
            println!("=== Skwaq Gym Evaluation ({mode}) ===");
            println!("  Suites:      {suites}");
            println!("  Procs/suite: {procs}");
            println!("  Concurrency: {concurrency}");
            println!("  Output:      {}", eval_dir.display());
            println!();

            let valid_suites: std::collections::HashSet<&str> = [
                "fixtures",
                "juliet",
                "owasp",
                "cyberseceval",
                "cgc",
                "binpool",
                "binmetric",
            ]
            .into_iter()
            .collect();
            let suite_list: Vec<&str> = suites.split(',').map(|s| s.trim()).collect();
            for s in &suite_list {
                if !valid_suites.contains(s) {
                    anyhow::bail!("Unknown suite '{}'. Valid: {:?}", s, valid_suites);
                }
            }
            let mut all_children: Vec<(String, Vec<std::process::Child>)> = Vec::new();

            for suite in &suite_list {
                let total = suite_cases.get(suite).copied().unwrap_or(100);
                let n_procs = if *suite == "fixtures" {
                    1
                } else {
                    (*procs).clamp(1, 50)
                };
                let cases_per = total.div_ceil(n_procs);
                let suite_dir = eval_dir.join(suite);
                std::fs::create_dir_all(&suite_dir)?;

                println!("[{suite}] Launching {n_procs} processes ({total} cases)...");

                let mut children = Vec::new();
                for i in 0..n_procs {
                    let skip = i * cases_per;
                    let log_path = suite_dir.join(format!("shard-{i}.log"));
                    let log_file = std::fs::File::create(&log_path)?;

                    let mut cmd = std::process::Command::new(&exe);
                    cmd.args(["gym", "run", suite])
                        .args(["--skip", &skip.to_string()])
                        .args(["--max-cases", &cases_per.to_string()])
                        .args(["-j", &concurrency.to_string()])
                        .args([
                            "--json",
                            &suite_dir.join(format!("shard-{i}.json")).to_string_lossy(),
                        ])
                        .stdout(log_file.try_clone()?)
                        .stderr(log_file);

                    if *quick {
                        cmd.arg("--quick");
                    }

                    children.push(cmd.spawn()?);
                }
                all_children.push((suite.to_string(), children));
            }

            // Monitor loop
            println!();
            println!("=== Monitoring ===");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));

                let mut all_done = true;
                println!();
                for (suite, children) in &mut all_children {
                    let mut running = 0;
                    for child in children.iter_mut() {
                        if let Ok(None) = child.try_wait() {
                            running += 1;
                            all_done = false;
                        }
                    }

                    // Count cases from logs
                    let suite_dir = eval_dir.join(suite.as_str());
                    let mut total_cases = 0;
                    let mut total_retries = 0;
                    for i in 0..children.len() {
                        let log = suite_dir.join(format!("shard-{i}.log"));
                        if let Ok(content) = std::fs::read_to_string(&log) {
                            total_cases += content.matches("Agent").count().saturating_sub(1) / 5;
                            total_retries += content.matches("Retrying").count();
                        }
                    }
                    let target = suite_cases.get(suite.as_str()).copied().unwrap_or(0);
                    let pct = if target > 0 {
                        total_cases * 100 / target
                    } else {
                        0
                    };
                    println!(
                        "  {suite}: ~{total_cases}/{target} ({pct}%) | {running} procs | {total_retries} retries"
                    );
                }

                if all_done {
                    break;
                }
            }

            // Collect and report
            println!();
            println!("=== Results ===");
            println!(
                "{:<15} {:>8} {:>8} {:>8} {:>6} {:>6} {:>6}",
                "Suite", "F1%", "Prec%", "Rec%", "TP", "FP", "FN"
            );
            println!("{}", "-".repeat(70));

            for suite in &suite_list {
                let suite_dir = eval_dir.join(suite);
                let mut tp = 0u32;
                let mut fp = 0u32;
                let mut fn_ = 0u32;

                // Parse TP/FP/FN from each shard log
                let n = if *suite == "fixtures" { 1 } else { *procs };
                for i in 0..n {
                    let log = suite_dir.join(format!("shard-{i}.log"));
                    if let Ok(content) = std::fs::read_to_string(&log) {
                        let extract_from_line = |line: &str, prefix: &str| -> u32 {
                            line.find(prefix)
                                .and_then(|i| {
                                    line[i + prefix.len()..]
                                        .split_whitespace()
                                        .next()
                                        .and_then(|s| s.parse().ok())
                                })
                                .unwrap_or(0)
                        };
                        for line in content.lines() {
                            if line.contains("TP:") && line.contains("FP:") {
                                tp += extract_from_line(line, "TP: ");
                                fp += extract_from_line(line, "FP: ");
                                fn_ += extract_from_line(line, "FN: ");
                                break;
                            }
                        }
                    }
                }

                let prec = if tp + fp > 0 {
                    tp as f64 / (tp + fp) as f64 * 100.0
                } else {
                    0.0
                };
                let rec = if tp + fn_ > 0 {
                    tp as f64 / (tp + fn_) as f64 * 100.0
                } else {
                    0.0
                };
                let f1 = if prec + rec > 0.0 {
                    2.0 * prec * rec / (prec + rec)
                } else {
                    0.0
                };

                println!(
                    "{:<15} {:>7.1} {:>7.1} {:>7.1} {:>6} {:>6} {:>6}",
                    suite, f1, prec, rec, tp, fp, fn_
                );
            }
            println!();
            println!("Results saved to: {}", eval_dir.display());
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
