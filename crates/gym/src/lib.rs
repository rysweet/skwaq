//! Skwaq Gym: Benchmark harness for measuring vulnerability detection accuracy.
//!
//! Measures skwaq against known ground truth datasets, tracks improvement over time,
//! and drives a self-improvement loop.

pub mod adapters;
pub mod agentic;
pub mod dashboard;
pub mod download;
pub mod ground_truth;
pub mod history;
pub mod improve;
pub mod reporting;
pub mod scoring;
pub mod throttle;

use futures::stream::{FuturesUnordered, StreamExt};
use std::pin::Pin;

use adapters::{BenchmarkAdapter, BenchmarkConfig};
use history::HistoryDb;
use std::path::PathBuf;

/// Top-level gym runner that coordinates all suites.
pub struct Gym {
    pub history_db: HistoryDb,
    adapters: Vec<Box<dyn BenchmarkAdapter>>,
    config: BenchmarkConfig,
    skwaq_root: PathBuf,
}

impl Gym {
    pub fn new(skwaq_root: PathBuf) -> anyhow::Result<Self> {
        let gym_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("skwaq")
            .join("gym");

        let history_db = HistoryDb::open(&gym_dir.join("results.db"))?;

        let gt_dir = skwaq_root.join("data/gym/ground_truth");
        let cache_dir = gym_dir.join("cache");

        let mut adapter_list: Vec<Box<dyn BenchmarkAdapter>> =
            vec![Box::new(adapters::fixtures::FixturesAdapter::new(
                gt_dir.join("fixtures.toml"),
                skwaq_root.join("tests/fixtures"),
            ))];

        // Add industry benchmark adapters if their manifests exist
        for (name, constructor) in [
            (
                "juliet",
                Box::new(|p: PathBuf| -> Box<dyn BenchmarkAdapter> {
                    Box::new(adapters::juliet::JulietAdapter::new(p))
                }) as Box<dyn Fn(PathBuf) -> Box<dyn BenchmarkAdapter>>,
            ),
            (
                "cgc",
                Box::new(|p: PathBuf| -> Box<dyn BenchmarkAdapter> {
                    Box::new(adapters::cgc::CgcAdapter::new(p))
                }) as Box<dyn Fn(PathBuf) -> Box<dyn BenchmarkAdapter>>,
            ),
            (
                "cyberseceval",
                Box::new(|p: PathBuf| -> Box<dyn BenchmarkAdapter> {
                    Box::new(adapters::cyberseceval::CyberSecEvalAdapter::new(p))
                }) as Box<dyn Fn(PathBuf) -> Box<dyn BenchmarkAdapter>>,
            ),
            (
                "owasp",
                Box::new(|p: PathBuf| -> Box<dyn BenchmarkAdapter> {
                    Box::new(adapters::owasp::OwaspBenchmarkAdapter::new(p))
                }) as Box<dyn Fn(PathBuf) -> Box<dyn BenchmarkAdapter>>,
            ),
            (
                "binpool",
                Box::new(|p: PathBuf| -> Box<dyn BenchmarkAdapter> {
                    Box::new(adapters::binpool::BinPoolAdapter::new(p))
                }) as Box<dyn Fn(PathBuf) -> Box<dyn BenchmarkAdapter>>,
            ),
            (
                "binmetric",
                Box::new(|p: PathBuf| -> Box<dyn BenchmarkAdapter> {
                    Box::new(adapters::binmetric::BinMetricAdapter::new(p))
                }) as Box<dyn Fn(PathBuf) -> Box<dyn BenchmarkAdapter>>,
            ),
        ] {
            let manifest = gt_dir.join(format!("{}.toml", name));
            if manifest.exists() {
                adapter_list.push(constructor(manifest));
            }
        }

        let adapters = adapter_list;

        let config = BenchmarkConfig {
            cache_dir,
            cwe_filter: None,
            max_cases: None,
            quick_mode: false,
            llm_only: false,
            binary_mode: true, // Binary analysis is the default for cases with binary_path
            parallelism: 4,
            skip: 0,
            concurrency: 1,
            timeout_secs: 1800,
        };

        Ok(Self {
            history_db,
            adapters,
            config,
            skwaq_root,
        })
    }

    /// Setup all benchmark data.
    pub async fn setup(&self) -> anyhow::Result<()> {
        for adapter in &self.adapters {
            if !adapter.is_ready(&self.config) {
                tracing::info!("Setting up {}...", adapter.name());
                let data_dir = adapter.setup(&self.config).await?;
                adapter.compile(&data_dir, &self.config).await?;
            } else {
                tracing::info!("{} already set up.", adapter.name());
            }
        }
        Ok(())
    }

    /// Run a specific suite or all suites.
    ///
    /// By default, runs full analysis (pattern detection + AI agents).
    /// Pass `quick_only=true` to use pattern-only mode (faster, no LLM).
    /// Pass `llm_only=true` to use LLM-only mode (no patterns, agents only).
    /// Pass `binary_mode=true` to analyze compiled binaries instead of source.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &mut self,
        suite: Option<&str>,
        cwe_filter: Option<Vec<u32>>,
        max_cases: Option<usize>,
        quick_only: bool,
        llm_only: bool,
        binary_mode: bool,
        skip: usize,
        concurrency: usize,
        adaptive: bool,
    ) -> anyhow::Result<()> {
        let commit = get_git_commit(&self.skwaq_root)?;

        let adapters: Vec<&Box<dyn BenchmarkAdapter>> = match suite {
            Some(name) => self.adapters.iter().filter(|a| a.name() == name).collect(),
            None => self.adapters.iter().collect(),
        };

        if adapters.is_empty() {
            anyhow::bail!("Unknown suite. Available: fixtures");
        }

        let mut config = self.config.clone();
        config.cwe_filter = cwe_filter;
        if let Some(max) = max_cases {
            config.max_cases = Some(max);
        }
        if quick_only {
            config.quick_mode = true;
            config.llm_only = false;
            config.timeout_secs = 30;
        } else if llm_only {
            config.quick_mode = false;
            config.llm_only = true;
            config.timeout_secs = 1800;
        } else {
            config.quick_mode = false;
            config.llm_only = false;
            // Agentic analysis with 5 LLM agents can take 10+ minutes per case.
            // 30 minutes is generous but prevents infinite hangs.
            config.timeout_secs = 1800;
        }
        config.binary_mode = binary_mode;
        config.skip = skip;
        config.concurrency = concurrency.max(1);

        for adapter in adapters {
            let suite_name = adapter.name().to_string();
            tracing::info!("Running {} benchmark...", suite_name);

            let run_metadata = build_run_metadata(&self.skwaq_root, &config);
            let run_id = self
                .history_db
                .start_run(&suite_name, &commit, &run_metadata)?;
            let gt = adapter.ground_truth()?;
            let data_dir = adapter.setup(&config).await?;

            let cases: Vec<&ground_truth::TestCase> = gt
                .cases
                .iter()
                .filter(|c| {
                    config.cwe_filter.as_ref().is_none_or(|f| {
                        c.expected_cwes.iter().any(|cwe| f.contains(cwe))
                            || c.expected_cwes.is_empty()
                    })
                })
                .skip(config.skip)
                .take(config.max_cases.unwrap_or(usize::MAX))
                .collect();

            let total = cases.len();
            let concurrency = config.concurrency;

            let rate_controller = if adaptive {
                Some(throttle::RateController::with_defaults(concurrency as u32))
            } else {
                None
            };

            tracing::info!(
                "{}: {} cases (skip={}, concurrency={}, adaptive={})",
                suite_name,
                total,
                config.skip,
                concurrency,
                adaptive
            );

            // Skip empty shards (can happen when skip >= total cases in multi-process mode)
            if cases.is_empty() {
                tracing::warn!(
                    "{}: no cases after skip={}, skipping",
                    suite_name,
                    config.skip
                );
                reporting::terminal::print_summary(
                    &scoring::AggregateScore::default(),
                    &suite_name,
                );
                continue;
            }

            // Run cases with in-process async concurrency.
            // Each case creates its own in-memory GraphDb, so no shared state.
            // Concurrency > 1 lets multiple LLM API calls overlap (network I/O).
            let mut outcomes = Vec::with_capacity(total);
            let timeout_secs = config.timeout_secs;

            if concurrency <= 1 {
                // Sequential mode (original behavior)
                for (i, case) in cases.iter().enumerate() {
                    if i % 10 == 0 && i > 0 {
                        tracing::info!("[{}/{}] Processing {}", i, total, case.id);
                    }
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(timeout_secs),
                        adapter.run_case(case, &data_dir, &config),
                    )
                    .await
                    {
                        Ok(Ok(findings)) => {
                            let mut outcome = scoring::score_case(case, &findings, &|f| {
                                adapter.map_finding_to_cwes(f)
                            });
                            outcome.suite = suite_name.clone();
                            outcomes.push(outcome);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Case {} failed: {}", case.id, e);
                        }
                        Err(_) => {
                            tracing::warn!("Case {} timed out after {}s", case.id, timeout_secs);
                        }
                    }
                }
            } else {
                // Concurrent mode: run N cases at once using FuturesUnordered.
                // On a single-threaded runtime, this interleaves at await points
                // (network I/O), giving true concurrency on LLM API calls.
                // Each case gets its own in-memory GraphDb, so no shared state.
                type CaseResult<'a> = (
                    usize,
                    &'a ground_truth::TestCase,
                    String,
                    Result<
                        anyhow::Result<Vec<adapters::DetectedFinding>>,
                        tokio::time::error::Elapsed,
                    >,
                );

                let data_dir = &data_dir;
                let config = &config;

                let mut pending: FuturesUnordered<
                    Pin<Box<dyn std::future::Future<Output = CaseResult<'_>>>>,
                > = FuturesUnordered::new();
                let mut case_iter = cases.iter().enumerate();
                let mut completed = 0usize;

                // Seed the initial batch
                for _ in 0..concurrency {
                    if let Some((i, &case)) = case_iter.next() {
                        let suite = suite_name.clone();
                        pending.push(Box::pin(async move {
                            let result = tokio::time::timeout(
                                std::time::Duration::from_secs(timeout_secs),
                                adapter.run_case(case, data_dir, config),
                            )
                            .await;
                            (i, case, suite, result)
                        }));
                    }
                }

                // Process completions and feed new cases
                while let Some((i, case, suite, result)) = pending.next().await {
                    completed += 1;
                    if completed.is_multiple_of(10) {
                        tracing::info!("[{}/{}] Completed {}", completed, total, case.id);
                    }

                    // Determine call outcome for adaptive throttling.
                    let call_outcome = match &result {
                        Ok(Ok(_)) => throttle::CallOutcome::Success,
                        Ok(Err(e)) => {
                            let msg = e.to_string();
                            if msg.contains("429")
                                || msg.contains("rate")
                                || msg.contains("Rate")
                                || msg.contains("throttl")
                            {
                                throttle::CallOutcome::RateLimited
                            } else {
                                throttle::CallOutcome::OtherError
                            }
                        }
                        Err(_) => throttle::CallOutcome::OtherError,
                    };

                    if let Some(ref rc) = rate_controller {
                        rc.record(call_outcome);
                    }

                    match result {
                        Ok(Ok(findings)) => {
                            let mut outcome = scoring::score_case(case, &findings, &|f| {
                                adapter.map_finding_to_cwes(f)
                            });
                            outcome.suite = suite;
                            outcomes.push(outcome);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("[{}/{}] Case {} failed: {}", i, total, case.id, e);
                        }
                        Err(_) => {
                            tracing::warn!(
                                "[{}/{}] Case {} timed out after {}s",
                                i,
                                total,
                                case.id,
                                timeout_secs
                            );
                        }
                    }

                    // Feed new cases into the pool.
                    // In adaptive mode, respect the rate controller's current concurrency.
                    let target = if let Some(ref rc) = rate_controller {
                        rc.concurrency() as usize
                    } else {
                        concurrency
                    };
                    while pending.len() < target {
                        if let Some((next_i, &next_case)) = case_iter.next() {
                            let suite = suite_name.clone();
                            pending.push(Box::pin(async move {
                                let result = tokio::time::timeout(
                                    std::time::Duration::from_secs(timeout_secs),
                                    adapter.run_case(next_case, data_dir, config),
                                )
                                .await;
                                (next_i, next_case, suite, result)
                            }));
                        } else {
                            break;
                        }
                    }
                }

                // Log final adaptive throttle stats
                if let Some(ref rc) = rate_controller {
                    let stats = rc.stats();
                    tracing::info!(
                        "Adaptive throttle final: {} concurrent, {:.1} cases/min, {} completed",
                        stats.concurrency,
                        stats.throughput_per_min,
                        stats.total_completed,
                    );
                }
            }

            let score = scoring::aggregate(&outcomes);

            let run = history::BenchmarkRun {
                id: run_id.clone(),
                started_at: chrono::Utc::now(),
                finished_at: Some(chrono::Utc::now()),
                suite: suite_name.clone(),
                skwaq_commit: commit.clone(),
                metadata: run_metadata.clone(),
                precision: score.precision,
                recall: score.recall,
                f1: score.f1,
                true_positives: score.true_positives,
                false_positives: score.false_positives,
                false_negatives: score.false_negatives,
                true_negatives: score.true_negatives,
            };
            self.history_db.finish_run(&run)?;

            for cwe_score in score.per_cwe.values() {
                self.history_db.insert_cwe_result(&history::CweResult {
                    run_id: run_id.clone(),
                    cwe_id: cwe_score.cwe_id,
                    total_cases: cwe_score.total_cases,
                    true_positives: cwe_score.true_positives,
                    false_positives: cwe_score.false_positives,
                    false_negatives: cwe_score.false_negatives,
                    detection_rate: cwe_score.detection_rate,
                    precision: cwe_score.precision,
                })?;
            }

            reporting::terminal::print_summary(&score, &suite_name);
        }

        // Report synthesis usage across the entire run
        agentic::synthesis_stats().report();

        Ok(())
    }

    /// Show the most recent report.
    pub fn report(&self, format: ReportFormat) -> anyhow::Result<String> {
        let runs = self.history_db.recent_runs(1)?;
        let run = runs
            .first()
            .ok_or_else(|| anyhow::anyhow!("No runs yet. Run `skwaq gym run` first."))?;

        let cwe_results = self.history_db.cwe_results_for_run(&run.id)?;
        let score = reconstruct_score(run, &cwe_results);

        match format {
            ReportFormat::Terminal => {
                reporting::terminal::print_summary(&score, &run.suite);
                Ok(String::new())
            }
            ReportFormat::Json => Ok(reporting::json_report::generate(
                &score,
                &run.suite,
                &run.skwaq_commit,
                &run.metadata,
            )),
            ReportFormat::Markdown => Ok(reporting::markdown_report::generate(
                &score,
                &run.suite,
                &run.skwaq_commit,
            )),
        }
    }

    /// Compare the two most recent runs.
    pub fn compare(&self) -> anyhow::Result<()> {
        let runs = self.history_db.recent_runs(2)?;
        if runs.len() < 2 {
            anyhow::bail!("Need at least 2 runs to compare. Run `skwaq gym run` twice.");
        }
        reporting::terminal::print_comparison(&runs[1], &runs[0]);
        Ok(())
    }

    /// Show run history.
    pub fn history(&self, limit: u32) -> anyhow::Result<()> {
        let runs = self.history_db.recent_runs(limit)?;
        println!(
            "\n{:>4} {:>19} {:>8} {:>8} {:>8} {:>8} {:>6}",
            "#", "Date", "Suite", "Prec%", "Rec%", "F1%", "Commit"
        );
        println!("{}", "-".repeat(80));
        for (i, run) in runs.iter().enumerate() {
            println!(
                "{:>4} {:>19} {:>8} {:>7.1}% {:>7.1}% {:>7.1}% {:>6}",
                i + 1,
                run.started_at.format("%Y-%m-%d %H:%M"),
                run.suite,
                run.precision * 100.0,
                run.recall * 100.0,
                run.f1 * 100.0,
                &run.skwaq_commit[..6.min(run.skwaq_commit.len())]
            );
        }
        println!();
        Ok(())
    }

    /// Get a reference to the registered adapters.
    pub fn get_adapters(&self) -> &[Box<dyn BenchmarkAdapter>] {
        &self.adapters
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Terminal,
    Json,
    Markdown,
}

fn get_git_commit(repo: &std::path::Path) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn get_git_dirty(repo: &std::path::Path) -> anyhow::Result<bool> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .output()?;
    Ok(!output.stdout.is_empty())
}

fn build_run_metadata(repo: &std::path::Path, config: &BenchmarkConfig) -> history::RunMetadata {
    let llm = skwaq_core::config::Config::load().unwrap_or_default().llm;
    history::RunMetadata {
        llm_backend: llm.reasoning.trim().to_string(),
        llm_model: llm.copilot.model,
        run_mode: if config.quick_mode {
            "pattern-only".to_string()
        } else if config.llm_only {
            "llm-only".to_string()
        } else {
            "hybrid".to_string()
        },
        binary_mode: config.binary_mode,
        git_dirty: get_git_dirty(repo).unwrap_or(false),
        concurrency: config.concurrency,
        skip: config.skip,
        max_cases: config.max_cases,
    }
}

fn reconstruct_score(
    run: &history::BenchmarkRun,
    cwe_results: &[history::CweResult],
) -> scoring::AggregateScore {
    let mut per_cwe = std::collections::HashMap::new();
    for cr in cwe_results {
        per_cwe.insert(
            cr.cwe_id,
            scoring::CweScore {
                cwe_id: cr.cwe_id,
                total_cases: cr.total_cases,
                true_positives: cr.true_positives,
                false_positives: cr.false_positives,
                false_negatives: cr.false_negatives,
                detection_rate: cr.detection_rate,
                precision: cr.precision,
            },
        );
    }
    scoring::AggregateScore {
        true_positives: run.true_positives,
        false_positives: run.false_positives,
        false_negatives: run.false_negatives,
        true_negatives: run.true_negatives,
        precision: run.precision,
        recall: run.recall,
        f1: run.f1,
        per_cwe,
    }
}
