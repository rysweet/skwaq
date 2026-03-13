//! CLI dispatch for `skwaq gym *` subcommands.

use anyhow::Context;
use clap::Subcommand;
use serde::Serialize;
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
        #[arg(long, alias = "pattern-only", conflicts_with = "llm_only")]
        quick: bool,

        /// Use LLM-only mode (no pattern detection, agents only).
        /// Measures what agents actually understand vs what patterns match.
        #[arg(long, conflicts_with = "quick")]
        llm_only: bool,

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

        /// Enable adaptive rate throttling (AIMD congestion control for API calls).
        /// Automatically scales concurrency up/down based on rate-limit responses.
        #[arg(long)]
        adaptive: bool,

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
        #[arg(long, alias = "pattern-only", conflicts_with = "llm_only")]
        quick: bool,

        /// Use LLM-only mode (no pattern detection, agents only)
        #[arg(long, conflicts_with = "quick")]
        llm_only: bool,

        /// Enable adaptive rate throttling (AIMD congestion control for API calls)
        #[arg(long)]
        adaptive: bool,

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

#[derive(Debug, Clone, Serialize, PartialEq)]
struct EvalSuiteSummary {
    suite: String,
    skwaq_commit: String,
    precision: f64,
    recall: f64,
    f1: f64,
    true_positives: u32,
    false_positives: u32,
    false_negatives: u32,
    true_negatives: u32,
    shard_reports: u32,
    target_cases: u32,
}

#[derive(Debug, Serialize, PartialEq)]
struct EvalSummaryReport {
    generated_at: String,
    mode: String,
    suites: Vec<EvalSuiteSummary>,
}

#[derive(Debug, Default)]
struct AggregatedCwe {
    total_cases: u32,
    true_positives: u32,
    false_positives: u32,
    false_negatives: u32,
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
            llm_only,
            skip,
            concurrency,
            source_only,
            adaptive,
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
            if !quick {
                ensure_hybrid_benchmark_ready().await?;
            }
            gym.run(
                suite.as_deref(),
                cwe_filter,
                *max_cases,
                *quick,
                *llm_only,
                binary_mode,
                *skip,
                conc,
                *adaptive,
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
            llm_only,
            adaptive,
            output,
        } => {
            let eval_dir = output.clone().unwrap_or_else(|| {
                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                PathBuf::from(format!("/tmp/gym-eval-{}", ts))
            });
            std::fs::create_dir_all(&eval_dir)?;

            if !quick {
                ensure_hybrid_benchmark_ready().await?;
            }

            let exe = std::env::current_exe()?;
            let suite_cases = load_suite_case_counts(&gym)?;

            let mode = if *quick {
                "pattern-only"
            } else if *llm_only {
                "llm-only"
            } else {
                "hybrid"
            };
            println!("=== Skwaq Gym Evaluation ({mode}) ===");
            println!("  Suites:      {suites}");
            println!("  Procs/suite: {procs}");
            println!("  Concurrency: {concurrency}");
            println!("  Adaptive:    {adaptive}");
            println!("  Output:      {}", eval_dir.display());
            println!();

            let valid_suites: std::collections::HashSet<&str> =
                suite_cases.keys().map(String::as_str).collect();
            let suite_list: Vec<&str> = suites
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            for s in &suite_list {
                if !valid_suites.contains(s) {
                    anyhow::bail!("Unknown suite '{}'. Valid: {:?}", s, valid_suites);
                }
            }
            let mut all_children: Vec<(String, Vec<std::process::Child>)> = Vec::new();
            let mut suite_shards: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for suite in &suite_list {
                let total = suite_cases
                    .get(*suite)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("Missing case count for suite '{}'", suite))?;
                let n_procs = if *suite == "fixtures" {
                    1
                } else {
                    (*procs).clamp(1, total.max(1))
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
                    } else if *llm_only {
                        cmd.arg("--llm-only");
                    }
                    if *adaptive {
                        cmd.arg("--adaptive");
                    }

                    children.push(cmd.spawn()?);
                }
                suite_shards.insert((*suite).to_string(), n_procs);
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
                "{:<15} {:>8} {:>8} {:>8} {:>6} {:>6} {:>6} {:>6}",
                "Suite", "F1%", "Prec%", "Rec%", "TP", "FP", "FN", "TN"
            );
            println!("{}", "-".repeat(70));

            let mut summaries = Vec::new();
            for suite in &suite_list {
                let suite_dir = eval_dir.join(suite);
                let shard_count = suite_shards.get(*suite).copied().unwrap_or(1);
                let (summary, cwe_results) = summarize_eval_suite(
                    suite,
                    &suite_dir,
                    shard_count,
                    suite_cases
                        .get(*suite)
                        .copied()
                        .expect("suite validated before spawning shards")
                        as u32,
                )?;
                let run_id = gym
                    .history_db
                    .start_run(&summary.suite, &summary.skwaq_commit)?;
                gym.history_db
                    .finish_run(&skwaq_gym::history::BenchmarkRun {
                        id: run_id.clone(),
                        started_at: chrono::Utc::now(),
                        finished_at: Some(chrono::Utc::now()),
                        suite: summary.suite.clone(),
                        skwaq_commit: summary.skwaq_commit.clone(),
                        precision: summary.precision,
                        recall: summary.recall,
                        f1: summary.f1,
                        true_positives: summary.true_positives,
                        false_positives: summary.false_positives,
                        false_negatives: summary.false_negatives,
                        true_negatives: summary.true_negatives,
                    })?;
                for cwe_result in cwe_results {
                    gym.history_db
                        .insert_cwe_result(&skwaq_gym::history::CweResult {
                            run_id: run_id.clone(),
                            ..cwe_result
                        })?;
                }

                println!(
                    "{:<15} {:>7.1} {:>7.1} {:>7.1} {:>6} {:>6} {:>6} {:>6}",
                    summary.suite,
                    summary.f1 * 100.0,
                    summary.precision * 100.0,
                    summary.recall * 100.0,
                    summary.true_positives,
                    summary.false_positives,
                    summary.false_negatives,
                    summary.true_negatives
                );
                summaries.push(summary);
            }
            println!();
            write_eval_artifacts(&eval_dir, mode, &summaries, &gym.history_db)?;
            println!("Results saved to: {}", eval_dir.display());
            println!("Summary: {}", eval_dir.join("summary.md").display());
            println!("Dashboard: {}", eval_dir.join("dashboard.md").display());
        }
        GymSub::Improve { suite, max_cases } => {
            let config = skwaq_gym::adapters::BenchmarkConfig {
                cache_dir: dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("skwaq/gym/cache"),
                cwe_filter: None,
                max_cases: Some(*max_cases),
                quick_mode: true,
                llm_only: false,
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

async fn ensure_hybrid_benchmark_ready() -> anyhow::Result<()> {
    let config = skwaq_core::config::Config::load()?;
    skwaq_core::llm::ensure_benchmark_llm_ready(&config.llm)
        .await
        .context(
            "Hybrid benchmark runs require a working LLM (ANTHROPIC_API_KEY or Copilot auth). \
             Use `skwaq gym run --quick` for pattern-only smoke tests.",
        )
}

fn load_suite_case_counts(
    gym: &skwaq_gym::Gym,
) -> anyhow::Result<std::collections::HashMap<String, usize>> {
    let mut counts = std::collections::HashMap::new();
    for adapter in gym.get_adapters() {
        let gt = adapter.ground_truth().with_context(|| {
            format!("Failed to load ground truth for suite '{}'", adapter.name())
        })?;
        counts.insert(adapter.name().to_string(), gt.cases.len());
    }
    Ok(counts)
}

fn summarize_eval_suite(
    suite: &str,
    suite_dir: &std::path::Path,
    shard_count: usize,
    target_cases: u32,
) -> anyhow::Result<(EvalSuiteSummary, Vec<skwaq_gym::history::CweResult>)> {
    let reports = load_shard_reports(suite, suite_dir, shard_count)?;
    let commit = reports
        .first()
        .map(|report| report.skwaq_commit.clone())
        .unwrap_or_default();

    let mut true_positives = 0u32;
    let mut false_positives = 0u32;
    let mut false_negatives = 0u32;
    let mut true_negatives = 0u32;
    let mut per_cwe: std::collections::BTreeMap<u32, AggregatedCwe> =
        std::collections::BTreeMap::new();

    for report in reports {
        true_positives += report.true_positives;
        false_positives += report.false_positives;
        false_negatives += report.false_negatives;
        true_negatives += report.true_negatives;

        for cwe in report.per_cwe {
            let entry = per_cwe.entry(cwe.cwe_id).or_default();
            entry.total_cases += cwe.total_cases;
            entry.true_positives += cwe.true_positives;
            entry.false_positives += cwe.false_positives;
            entry.false_negatives += cwe.false_negatives;
        }
    }

    let precision = ratio(true_positives, true_positives + false_positives);
    let recall = ratio(true_positives, true_positives + false_negatives);
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    let cwe_results = per_cwe
        .into_iter()
        .map(|(cwe_id, agg)| skwaq_gym::history::CweResult {
            run_id: String::new(),
            cwe_id,
            total_cases: agg.total_cases,
            true_positives: agg.true_positives,
            false_positives: agg.false_positives,
            false_negatives: agg.false_negatives,
            detection_rate: ratio(agg.true_positives, agg.total_cases),
            precision: ratio(agg.true_positives, agg.true_positives + agg.false_positives),
        })
        .collect();

    Ok((
        EvalSuiteSummary {
            suite: suite.to_string(),
            skwaq_commit: commit,
            precision,
            recall,
            f1,
            true_positives,
            false_positives,
            false_negatives,
            true_negatives,
            shard_reports: shard_count as u32,
            target_cases,
        },
        cwe_results,
    ))
}

fn load_shard_reports(
    suite: &str,
    suite_dir: &std::path::Path,
    shard_count: usize,
) -> anyhow::Result<Vec<skwaq_gym::reporting::json_report::JsonReport>> {
    let mut reports = Vec::new();

    for shard in 0..shard_count {
        let shard_path = suite_dir.join(format!("shard-{shard}.json"));
        if !shard_path.exists() {
            continue;
        }

        let text = std::fs::read_to_string(&shard_path)?;
        if text.trim().is_empty() {
            continue;
        }

        let report = serde_json::from_str(&text).map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse shard report '{}' for suite '{}': {}",
                shard_path.display(),
                suite,
                err
            )
        })?;
        reports.push(report);
    }

    if reports.is_empty() {
        anyhow::bail!(
            "No shard reports found for suite '{}' in '{}'",
            suite,
            suite_dir.display()
        );
    }

    Ok(reports)
}

fn write_eval_artifacts(
    eval_dir: &std::path::Path,
    mode: &str,
    summaries: &[EvalSuiteSummary],
    history_db: &skwaq_gym::history::HistoryDb,
) -> anyhow::Result<()> {
    let summary_report = EvalSummaryReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        mode: mode.to_string(),
        suites: summaries.to_vec(),
    };
    std::fs::write(
        eval_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary_report)?,
    )?;
    std::fs::write(
        eval_dir.join("summary.md"),
        render_eval_summary_markdown(mode, summaries),
    )?;

    let mut dashboard = skwaq_gym::dashboard::generate_charts(history_db)?;
    dashboard.push('\n');
    dashboard.push_str(&skwaq_gym::dashboard::generate_scores_table(history_db)?);
    std::fs::write(eval_dir.join("dashboard.md"), dashboard)?;
    std::fs::write(
        eval_dir.join("eval.json"),
        skwaq_gym::dashboard::generate_eval_json(history_db)?,
    )?;

    Ok(())
}

fn render_eval_summary_markdown(mode: &str, summaries: &[EvalSuiteSummary]) -> String {
    let mut output = String::new();
    output.push_str("# Skwaq Gym Evaluation Summary\n\n");
    output.push_str(&format!(
        "- Generated: {}\n- Mode: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        mode
    ));
    output.push_str(
        "| Suite | F1 | Precision | Recall | TP | FP | FN | TN | Shards | Target cases |\n",
    );
    output.push_str(
        "|-------|----|-----------|--------|----|----|----|----|--------|--------------|\n",
    );

    for summary in summaries {
        output.push_str(&format!(
            "| {} | {:.1}% | {:.1}% | {:.1}% | {} | {} | {} | {} | {} | {} |\n",
            summary.suite,
            summary.f1 * 100.0,
            summary.precision * 100.0,
            summary.recall * 100.0,
            summary.true_positives,
            summary.false_positives,
            summary.false_negatives,
            summary.true_negatives,
            summary.shard_reports,
            summary.target_cases
        ));
    }

    output
}

fn ratio(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
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
    use skwaq_gym::reporting::json_report::{JsonCweResult, JsonReport};
    use tempfile::tempdir;

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

    #[test]
    fn test_summarize_eval_suite_from_shards() {
        let dir = tempdir().unwrap();
        let suite_dir = dir.path();
        let shard0 = JsonReport {
            suite: "fixtures".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            skwaq_commit: "abc123".to_string(),
            precision: 0.0,
            recall: 0.0,
            f1: 0.0,
            true_positives: 2,
            false_positives: 1,
            false_negatives: 1,
            true_negatives: 3,
            per_cwe: vec![JsonCweResult {
                cwe_id: 121,
                total_cases: 3,
                true_positives: 2,
                false_positives: 1,
                false_negatives: 1,
                detection_rate: 0.0,
                precision: 0.0,
            }],
        };
        let shard1 = JsonReport {
            suite: "fixtures".to_string(),
            timestamp: "2026-01-01T00:00:01Z".to_string(),
            skwaq_commit: "abc123".to_string(),
            precision: 0.0,
            recall: 0.0,
            f1: 0.0,
            true_positives: 1,
            false_positives: 0,
            false_negatives: 2,
            true_negatives: 4,
            per_cwe: vec![JsonCweResult {
                cwe_id: 121,
                total_cases: 3,
                true_positives: 1,
                false_positives: 0,
                false_negatives: 2,
                detection_rate: 0.0,
                precision: 0.0,
            }],
        };

        std::fs::write(
            suite_dir.join("shard-0.json"),
            serde_json::to_string_pretty(&shard0).unwrap(),
        )
        .unwrap();
        std::fs::write(
            suite_dir.join("shard-1.json"),
            serde_json::to_string_pretty(&shard1).unwrap(),
        )
        .unwrap();

        let (summary, cwe_results) = summarize_eval_suite("fixtures", suite_dir, 2, 7).unwrap();
        assert_eq!(summary.suite, "fixtures");
        assert_eq!(summary.skwaq_commit, "abc123");
        assert_eq!(summary.true_positives, 3);
        assert_eq!(summary.false_positives, 1);
        assert_eq!(summary.false_negatives, 3);
        assert_eq!(summary.true_negatives, 7);
        assert!((summary.precision - 0.75).abs() < f64::EPSILON);
        assert!((summary.recall - 0.5).abs() < f64::EPSILON);
        assert!((summary.f1 - 0.6).abs() < 1e-9);
        assert_eq!(cwe_results.len(), 1);
        assert_eq!(cwe_results[0].cwe_id, 121);
        assert_eq!(cwe_results[0].total_cases, 6);
        assert_eq!(cwe_results[0].true_positives, 3);
    }

    #[test]
    fn test_render_eval_summary_markdown() {
        let markdown = render_eval_summary_markdown(
            "pattern-only",
            &[EvalSuiteSummary {
                suite: "fixtures".to_string(),
                skwaq_commit: "abc123".to_string(),
                precision: 0.75,
                recall: 0.5,
                f1: 0.6,
                true_positives: 3,
                false_positives: 1,
                false_negatives: 3,
                true_negatives: 7,
                shard_reports: 2,
                target_cases: 7,
            }],
        );

        assert!(markdown.contains("# Skwaq Gym Evaluation Summary"));
        assert!(markdown.contains("pattern-only"));
        assert!(markdown.contains("| fixtures | 60.0% | 75.0% | 50.0% | 3 | 1 | 3 | 7 | 2 | 7 |"));
    }
}
