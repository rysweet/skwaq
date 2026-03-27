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
        /// Suite name (e.g. fixtures, realworld, juliet, cgc, cyberseceval, owasp, binpool). Omit for all registered suites.
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

        /// Total cases for stratified sampling across shards (internal, set by eval command)
        #[arg(long, hide = true)]
        shard_total: Option<usize>,

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

    /// Compare the latest two finished runs for the most recently run suite
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

        /// Maximum cases per suite (0 = all cases)
        #[arg(long, default_value = "0")]
        max_cases: usize,

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

        /// Create a git tag and GitHub release with the eval results.
        /// Tag format: eval-YYYY-MM-DD[-vN] (auto-increments if date already exists).
        #[arg(long)]
        tag: bool,
    },

    /// Run self-improvement loop: analyze failures and propose fixes
    Improve {
        /// Suite to improve (fixtures, juliet, cgc, owasp, cyberseceval, binpool)
        suite: String,

        /// Maximum cases to analyze
        #[arg(long, default_value = "20")]
        max_cases: usize,

        /// Filter to specific CWE (e.g., CWE-121). Only analyze cases matching this CWE.
        #[arg(long)]
        cwe: Option<String>,

        /// Fraction of cases to hold out for validation (0.0-0.5, default 0.2)
        #[arg(long, default_value = "0.2")]
        holdout_fraction: f64,

        /// Maximum improvement proposals to accept per cycle (1-10, default 5)
        #[arg(long, default_value = "5")]
        max_improvements: usize,

        /// Timeout in seconds per case analysis (5-600, default 30)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Compare per-case outcomes between the latest two finished runs for a suite
    CaseDiff {
        /// Suite to diff (defaults to the suite from the most recent finished run)
        #[arg(long)]
        suite: Option<String>,
    },

    /// Generate dashboard: mermaid charts + scores table from run history.
    /// Use --live for a real-time ratatui TUI, or --tui for a static snapshot.
    Dashboard {
        /// Launch live interactive TUI dashboard (ratatui)
        #[arg(long, conflicts_with = "tui")]
        live: bool,

        /// Show static TUI snapshot of latest run (ratatui)
        #[arg(long, conflicts_with = "live")]
        tui: bool,
    },

    /// Query and manage OpenTelemetry span telemetry
    Telemetry {
        #[command(subcommand)]
        action: TelemetrySub,
    },

    /// Preflight check: verify Copilot backend, auth, model, and no-fallback readiness.
    /// Run this before hybrid benchmark runs to ensure the LLM pipeline will work.
    Preflight,
}

#[derive(Subcommand)]
pub enum TelemetrySub {
    /// Query recorded spans and print a summary
    Query {
        /// Filter spans by name (substring match)
        #[arg(long)]
        name: Option<String>,

        /// Filter spans by attribute key=value (e.g. "suite=juliet")
        #[arg(long)]
        attr: Option<String>,

        /// Maximum number of spans to return
        #[arg(long, default_value = "500")]
        limit: usize,
    },

    /// Rotate the spans JSONL file (archive when over size limit)
    Rotate {
        /// Maximum file size in bytes before rotation (default 50 MB)
        #[arg(long, default_value = "52428800")]
        max_bytes: u64,
    },
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

#[derive(Debug, Clone, Serialize, PartialEq)]
struct EvalRunMetadata {
    started_at: String,
    git_commit: String,
    git_dirty: bool,
    mode: String,
    suites: String,
    procs_per_suite: usize,
    concurrency: usize,
    llm_backend: String,
    llm_model: String,
    binary_mode: bool,
    skwaq_version: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct EvalSummaryReport {
    generated_at: String,
    mode: String,
    metadata: EvalRunMetadata,
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
    let mut gym = skwaq_gym::Gym::new(skwaq_root.clone())?;

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
            shard_total,
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
                *shard_total,
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
        GymSub::CaseDiff { suite } => {
            let suite = if let Some(suite) = suite {
                suite.clone()
            } else {
                gym.history_db
                    .recent_finished_runs(1)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        anyhow::anyhow!("No finished runs yet. Run `skwaq gym run` first.")
                    })?
                    .suite
            };
            let runs = gym.history_db.recent_finished_runs_for_suite(&suite, 2)?;
            if runs.len() < 2 {
                anyhow::bail!(
                    "Need at least 2 finished runs for suite `{}` to diff. Run `skwaq gym run {}` twice.",
                    suite,
                    suite
                );
            }

            let deltas = gym
                .history_db
                .compare_case_outcomes(&runs[1].id, &runs[0].id)?;
            if deltas.is_empty() {
                println!("No per-case changes between the last two runs.");
                println!(
                    "(Hint: per-case outcomes are recorded during `gym run`; identical runs simply produce no deltas.)"
                );
            } else {
                println!(
                    "\nPer-case diff for suite `{}`: {} -> {}",
                    suite,
                    &runs[1].skwaq_commit[..6.min(runs[1].skwaq_commit.len())],
                    &runs[0].skwaq_commit[..6.min(runs[0].skwaq_commit.len())]
                );
                println!("{}", "-".repeat(60));
                for delta in &deltas {
                    match delta {
                        skwaq_gym::history::CaseDelta::Improved { case_id, cwe } => {
                            println!("  [+] IMPROVED  {} (CWE-{}): FN -> TP", case_id, cwe);
                        }
                        skwaq_gym::history::CaseDelta::Regressed { case_id, cwe } => {
                            println!("  [-] REGRESSED {} (CWE-{}): TP -> FN", case_id, cwe);
                        }
                        skwaq_gym::history::CaseDelta::NewFalsePositive { case_id, cwe } => {
                            println!("  [!] NEW FP    {} (CWE-{})", case_id, cwe);
                        }
                        skwaq_gym::history::CaseDelta::FixedFalsePositive { case_id, cwe } => {
                            println!("  [*] FIXED FP  {} (CWE-{})", case_id, cwe);
                        }
                    }
                }

                let improved = deltas
                    .iter()
                    .filter(|delta| matches!(delta, skwaq_gym::history::CaseDelta::Improved { .. }))
                    .count();
                let regressed = deltas
                    .iter()
                    .filter(|delta| {
                        matches!(delta, skwaq_gym::history::CaseDelta::Regressed { .. })
                    })
                    .count();
                println!();
                println!(
                    "  Summary: {} improved, {} regressed, {} total changes",
                    improved,
                    regressed,
                    deltas.len()
                );
            }
        }
        GymSub::Eval {
            suites,
            max_cases,
            procs,
            concurrency,
            quick,
            llm_only,
            adaptive,
            output,
            tag,
        } => {
            let mode = if *quick {
                "pattern-only"
            } else if *llm_only {
                "llm-only"
            } else {
                "hybrid"
            };
            let config = skwaq_core::config::Config::load()?;
            if !quick {
                ensure_hybrid_benchmark_ready_with_llm(&config.llm).await?;
            }

            let eval_dir = output.clone().unwrap_or_else(|| {
                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                PathBuf::from(format!("/tmp/gym-eval-{}", ts))
            });
            std::fs::create_dir_all(&eval_dir)?;

            let eval_metadata = EvalRunMetadata {
                started_at: chrono::Utc::now().to_rfc3339(),
                git_commit: git_commit_full(&skwaq_root)?,
                git_dirty: git_is_dirty(&skwaq_root)?,
                mode: mode.to_string(),
                suites: suites.clone(),
                procs_per_suite: *procs,
                concurrency: *concurrency,
                llm_backend: config.llm.reasoning.clone(),
                llm_model: config.llm.copilot.model.clone(),
                binary_mode: true,
                skwaq_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            std::fs::write(
                eval_dir.join("metadata.json"),
                serde_json::to_string_pretty(&eval_metadata)?,
            )?;

            let exe = std::env::current_exe()?;
            let mut suite_cases = load_suite_case_counts(&gym)?;
            if *max_cases > 0 {
                for count in suite_cases.values_mut() {
                    *count = (*count).min(*max_cases);
                }
            }
            println!("=== Skwaq Gym Evaluation ({mode}) ===");
            println!("  Suites:      {suites}");
            println!("  Procs/suite: {procs}");
            println!("  Concurrency: {concurrency}");
            println!("  Adaptive:    {adaptive}");
            println!("  Output:      {}", eval_dir.display());
            println!();

            let valid_suites = gym.available_suite_names();
            let valid_suite_set: std::collections::HashSet<&str> =
                valid_suites.iter().map(String::as_str).collect();
            let suite_list: Vec<&str> = suites
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            for s in &suite_list {
                if !valid_suite_set.contains(s) {
                    anyhow::bail!(
                        "Unknown suite '{}'. Available: {}",
                        s,
                        valid_suites.join(", ")
                    );
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
                        .args(["--shard-total", &total.to_string()])
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
                let run_metadata = skwaq_gym::history::RunMetadata {
                    llm_backend: eval_metadata.llm_backend.clone(),
                    llm_model: eval_metadata.llm_model.clone(),
                    run_mode: mode.to_string(),
                    binary_mode: eval_metadata.binary_mode,
                    git_dirty: eval_metadata.git_dirty,
                    concurrency: *concurrency,
                    skip: 0,
                    max_cases: Some(summary.target_cases as usize),
                };
                let run_id = gym.history_db.start_run(
                    &summary.suite,
                    &summary.skwaq_commit,
                    &run_metadata,
                )?;
                gym.history_db
                    .finish_run(&skwaq_gym::history::BenchmarkRun {
                        id: run_id.clone(),
                        started_at: chrono::Utc::now(),
                        finished_at: Some(chrono::Utc::now()),
                        suite: summary.suite.clone(),
                        skwaq_commit: summary.skwaq_commit.clone(),
                        metadata: run_metadata,
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

            // Results Skeptic: validate coverage and flag suspicious results
            for summary in &summaries {
                let evaluated = summary.true_positives
                    + summary.false_positives
                    + summary.false_negatives
                    + summary.true_negatives;
                let target = summary.target_cases;
                let coverage_pct = if target > 0 {
                    evaluated as f64 / target as f64 * 100.0
                } else {
                    0.0
                };

                if coverage_pct < 80.0 {
                    eprintln!(
                        "WARNING [results-skeptic]: {} — only {}/{} cases evaluated ({:.0}% coverage). Results are UNRELIABLE.",
                        summary.suite, evaluated, target, coverage_pct
                    );
                }
                if summary.f1 > 0.95 && evaluated > 50 {
                    eprintln!(
                        "WARNING [results-skeptic]: {} — F1={:.1}% with {} cases evaluated. Verify no silent case skipping.",
                        summary.suite,
                        summary.f1 * 100.0,
                        evaluated
                    );
                }
                if summary.precision >= 1.0 && summary.true_negatives == 0 && target > 100 {
                    eprintln!(
                        "WARNING [results-skeptic]: {} — 100% precision but 0 TN. Are negative cases being evaluated?",
                        summary.suite
                    );
                }
            }

            write_eval_artifacts(&eval_dir, &eval_metadata, &summaries, &gym.history_db)?;
            println!("Results saved to: {}", eval_dir.display());
            println!("Metadata: {}", eval_dir.join("metadata.json").display());
            println!("Summary: {}", eval_dir.join("summary.md").display());
            println!("Dashboard: {}", eval_dir.join("dashboard.md").display());

            if *tag {
                println!();
                println!("=== Tagging ===");
                let tag_name = skwaq_gym::tagging::next_tag_name(&skwaq_root)?;

                // Collect per-CWE results across all suites for the tag payload
                let mut all_cwe_tag_results = Vec::new();
                for suite_name in &suite_list {
                    let suite_dir = eval_dir.join(suite_name);
                    let shard_count = suite_shards.get(*suite_name).copied().unwrap_or(1);
                    if let Ok(reports) = load_shard_reports(suite_name, &suite_dir, shard_count) {
                        for report in &reports {
                            for cwe in &report.per_cwe {
                                all_cwe_tag_results.push(skwaq_gym::tagging::CweTagResult {
                                    suite: suite_name.to_string(),
                                    cwe_id: cwe.cwe_id,
                                    total_cases: cwe.total_cases,
                                    true_positives: cwe.true_positives,
                                    false_positives: cwe.false_positives,
                                    false_negatives: cwe.false_negatives,
                                    detection_rate: cwe.detection_rate,
                                    precision: cwe.precision,
                                });
                            }
                        }
                    }
                }

                let payload = skwaq_gym::tagging::EvalTagPayload {
                    tag_name: tag_name.clone(),
                    commit: eval_metadata.git_commit.clone(),
                    timestamp: eval_metadata.started_at.clone(),
                    mode: eval_metadata.mode.clone(),
                    suites: eval_metadata.suites.clone(),
                    procs_per_suite: eval_metadata.procs_per_suite,
                    concurrency: eval_metadata.concurrency,
                    llm_backend: eval_metadata.llm_backend.clone(),
                    llm_model: eval_metadata.llm_model.clone(),
                    binary_mode: eval_metadata.binary_mode,
                    skwaq_version: eval_metadata.skwaq_version.clone(),
                    git_dirty: eval_metadata.git_dirty,
                    suite_results: summaries
                        .iter()
                        .map(|s| skwaq_gym::tagging::SuiteTagResult {
                            suite: s.suite.clone(),
                            f1: s.f1,
                            precision: s.precision,
                            recall: s.recall,
                            true_positives: s.true_positives,
                            false_positives: s.false_positives,
                            false_negatives: s.false_negatives,
                            true_negatives: s.true_negatives,
                        })
                        .collect(),
                    per_cwe: all_cwe_tag_results,
                    reproducible_command: skwaq_gym::tagging::build_reproducible_command(
                        suites,
                        *max_cases,
                        *procs,
                        *concurrency,
                        *quick,
                        *llm_only,
                        *adaptive,
                    ),
                };

                let results_json = eval_dir.join("summary.json");
                match skwaq_gym::tagging::tag_eval_results(&skwaq_root, &payload, &results_json) {
                    Ok(created_tag) => {
                        println!("  Tag created: {}", created_tag);
                    }
                    Err(e) => {
                        eprintln!("WARNING: Tagging failed: {}", e);
                        eprintln!("  Results are still saved in: {}", eval_dir.display());
                    }
                }
            }
        }
        GymSub::Improve {
            suite,
            max_cases,
            cwe,
            holdout_fraction,
            max_improvements,
            timeout,
        } => {
            // Validate CLI arg ranges
            anyhow::ensure!(
                *holdout_fraction > 0.0 && *holdout_fraction <= 0.5,
                "holdout_fraction must be in (0.0, 0.5], got {}",
                holdout_fraction
            );
            anyhow::ensure!(
                *max_improvements >= 1 && *max_improvements <= 10,
                "max_improvements must be in [1, 10], got {}",
                max_improvements
            );
            anyhow::ensure!(
                *timeout >= 5 && *timeout <= 600,
                "timeout must be in [5, 600] seconds, got {}",
                timeout
            );

            let cwe_filter = cwe.as_ref().and_then(|c| {
                let num_str = c.trim_start_matches("CWE-").trim_start_matches("cwe-");
                num_str.parse::<u32>().ok().map(|n| vec![n])
            });
            let config = skwaq_gym::adapters::BenchmarkConfig {
                cache_dir: dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("skwaq/gym/cache"),
                cwe_filter,
                max_cases: Some(*max_cases),
                quick_mode: true,
                llm_only: false,
                binary_mode: false,
                parallelism: 4,
                skip: 0,
                concurrency: 1,
                timeout_secs: *timeout,
                holdout_fraction: *holdout_fraction,
                max_improvements_per_cycle: *max_improvements,
            };

            // Find the matching adapter
            let adapters = gym.get_adapters();
            let adapter = adapters
                .iter()
                .find(|a| a.name() == suite.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unknown suite '{}'. Available: {}",
                        suite,
                        gym.available_suite_names().join(", ")
                    )
                })?;

            let data_dir = adapter.setup(&config).await?;
            let cycle =
                skwaq_gym::improve::run_improvement_cycle(adapter.as_ref(), &config, &data_dir)
                    .await?;
            skwaq_gym::improve::store_improvement_lessons(&cycle)?;
            skwaq_gym::improve::append_learned_patterns(&cycle);

            // Apply accepted NewPattern proposals to the codebase
            let applied = skwaq_gym::improve::apply_accepted_proposals(&cycle, None)?;
            if applied > 0 {
                println!(
                    "\n  {} proposal(s) applied to source code. Run `cargo test` to validate.",
                    applied
                );
            }

            skwaq_gym::improve::print_proposals(&cycle);
        }
        GymSub::Dashboard { live, tui } => {
            if *live {
                let telemetry_dir = default_telemetry_dir();
                skwaq_gym::tui::run_live(&gym.history_db, &telemetry_dir)?;
            } else if *tui {
                let telemetry_dir = default_telemetry_dir();
                skwaq_gym::tui::run_static(&gym.history_db, &telemetry_dir)?;
            } else {
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
        GymSub::Telemetry { action } => {
            let telemetry_dir = default_telemetry_dir();
            match action {
                TelemetrySub::Query { name, attr, limit } => {
                    let attr_filter = attr.as_ref().map(|a| {
                        let mut parts = a.splitn(2, '=');
                        let key = parts.next().unwrap_or("").to_string();
                        let val = parts.next().unwrap_or("").to_string();
                        (key, val)
                    });
                    let spans = skwaq_gym::telemetry::query_spans(
                        &telemetry_dir,
                        name.as_deref(),
                        attr_filter.as_ref().map(|(k, v)| (k.as_str(), v.as_str())),
                        *limit,
                    )?;
                    if spans.is_empty() {
                        println!("No spans found.");
                    } else {
                        skwaq_gym::telemetry::print_span_summary(&spans);
                    }
                }
                TelemetrySub::Rotate { max_bytes } => {
                    skwaq_gym::telemetry::rotate_spans_file(&telemetry_dir, *max_bytes)?;
                    println!("Telemetry spans file rotated.");
                }
            }
        }
        GymSub::Preflight => {
            run_preflight().await?;
        }
    }

    Ok(())
}

fn default_telemetry_dir() -> String {
    dirs::home_dir()
        .map(|h| h.join(".skwaq/telemetry").to_string_lossy().into_owned())
        .unwrap_or_else(|| "~/.skwaq/telemetry".to_string())
}

async fn ensure_hybrid_benchmark_ready() -> anyhow::Result<()> {
    let config = skwaq_core::config::Config::load()?;
    ensure_hybrid_benchmark_ready_with_llm(&config.llm).await
}

async fn ensure_hybrid_benchmark_ready_with_llm(
    llm: &skwaq_core::config::LlmConfig,
) -> anyhow::Result<()> {
    skwaq_core::llm::ensure_benchmark_copilot_ready(llm)
        .await
        .context(
            "Hybrid benchmark runs require explicit Copilot configuration and auth. \
             Use `skwaq gym run --quick` for pattern-only smoke tests.",
        )
}

async fn run_preflight() -> anyhow::Result<()> {
    println!("skwaq gym preflight - verifying Copilot benchmark readiness\n");

    let mut all_ok = true;

    print!("  Config .............. ");
    let config = match skwaq_core::config::Config::load() {
        Ok(config) => {
            println!("OK");
            config
        }
        Err(err) => {
            println!("FAIL ({err})");
            anyhow::bail!(
                "Preflight failed. Fix the issues above before running hybrid benchmarks."
            );
        }
    };

    print!("  LLM backend ......... ");
    match skwaq_core::llm::validate_benchmark_copilot_config(&config.llm) {
        Ok(_) => println!("OK ({})", config.llm.reasoning),
        Err(err) => {
            println!("FAIL ({err})");
            all_ok = false;
        }
    }

    print!("  No-fallback check ... ");
    if config.llm.reasoning == "copilot" && config.llm.decompilation == "copilot" {
        println!(
            "OK (reasoning={}, decompilation={})",
            config.llm.reasoning, config.llm.decompilation
        );
    } else {
        println!(
            "FAIL (reasoning={}, decompilation={})",
            config.llm.reasoning, config.llm.decompilation
        );
        all_ok = false;
    }

    print!("  Model ............... ");
    let model = config.llm.copilot.model.trim();
    if model.is_empty() {
        println!("FAIL (missing)");
        println!("    Set [llm.copilot] model = \"claude-opus-4.6\" in skwaq.toml");
        all_ok = false;
    } else {
        println!("OK ({model})");
    }

    print!("  GitHub account ...... ");
    match resolve_github_identity() {
        Some(login) => println!("OK ({login})"),
        None => println!("UNKNOWN (no gh auth identity available)"),
    }

    print!("  Copilot client ...... ");
    match skwaq_core::llm::ensure_benchmark_copilot_ready(&config.llm).await {
        Ok(_) => println!("OK (client created)"),
        Err(err) => {
            println!("FAIL ({err})");
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        println!("All preflight checks passed. Ready for hybrid benchmark.");
        Ok(())
    } else {
        anyhow::bail!("Preflight failed. Fix the issues above before running hybrid benchmarks.");
    }
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
    metadata: &EvalRunMetadata,
    summaries: &[EvalSuiteSummary],
    history_db: &skwaq_gym::history::HistoryDb,
) -> anyhow::Result<()> {
    let summary_report = EvalSummaryReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        mode: metadata.mode.clone(),
        metadata: metadata.clone(),
        suites: summaries.to_vec(),
    };
    std::fs::write(
        eval_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary_report)?,
    )?;
    std::fs::write(
        eval_dir.join("summary.md"),
        render_eval_summary_markdown(metadata, summaries),
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

fn render_eval_summary_markdown(
    metadata: &EvalRunMetadata,
    summaries: &[EvalSuiteSummary],
) -> String {
    let mut output = String::new();
    output.push_str("# Skwaq Gym Evaluation Summary\n\n");
    output.push_str(&format!(
        "- Generated: {}\n- Mode: {}\n- Commit: {}\n- Git dirty: {}\n- LLM backend: {}\n- LLM model: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        metadata.mode,
        metadata.git_commit,
        metadata.git_dirty,
        metadata.llm_backend,
        metadata.llm_model,
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

fn git_commit_full(repo: &std::path::Path) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_is_dirty(repo: &std::path::Path) -> anyhow::Result<bool> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git status --porcelain failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(!output.stdout.is_empty())
}

fn resolve_github_identity() -> Option<String> {
    let output = std::process::Command::new("gh")
        .args(["api", "user", "--jq", ".login"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let login = String::from_utf8(output.stdout).ok()?;
    let login = login.trim();
    if login.is_empty() {
        None
    } else {
        Some(login.to_string())
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
    use skwaq_gym::{
        history::RunMetadata,
        reporting::json_report::{JsonCweResult, JsonReport},
    };
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
            metadata: RunMetadata::default(),
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
            per_original_cwe: vec![],
            per_semantic: vec![],
        };
        let shard1 = JsonReport {
            suite: "fixtures".to_string(),
            timestamp: "2026-01-01T00:00:01Z".to_string(),
            skwaq_commit: "abc123".to_string(),
            metadata: RunMetadata::default(),
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
            per_original_cwe: vec![],
            per_semantic: vec![],
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
            &EvalRunMetadata {
                started_at: "2026-01-01T00:00:00Z".to_string(),
                git_commit: "abc123def456".to_string(),
                git_dirty: false,
                mode: "pattern-only".to_string(),
                suites: "fixtures".to_string(),
                procs_per_suite: 1,
                concurrency: 1,
                llm_backend: "copilot".to_string(),
                llm_model: "claude-opus-4.6".to_string(),
                binary_mode: true,
                skwaq_version: "0.1.0".to_string(),
            },
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
        assert!(markdown.contains("claude-opus-4.6"));
        assert!(markdown.contains("| fixtures | 60.0% | 75.0% | 50.0% | 3 | 1 | 3 | 7 | 2 | 7 |"));
    }
}
