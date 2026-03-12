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
            binary_mode: true, // Binary analysis is the default for cases with binary_path
            parallelism: 4,
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
    /// Pass `binary_mode=true` to analyze compiled binaries instead of source.
    pub async fn run(
        &mut self,
        suite: Option<&str>,
        cwe_filter: Option<Vec<u32>>,
        max_cases: Option<usize>,
        quick_only: bool,
        binary_mode: bool,
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
            config.timeout_secs = 30;
        } else {
            config.quick_mode = false;
            // Agentic analysis with 5 LLM agents can take 10+ minutes per case.
            // 30 minutes is generous but prevents infinite hangs.
            config.timeout_secs = 1800;
        }
        config.binary_mode = binary_mode;

        for adapter in adapters {
            let suite_name = adapter.name().to_string();
            tracing::info!("Running {} benchmark...", suite_name);

            let run_id = self.history_db.start_run(&suite_name, &commit)?;
            let gt = adapter.ground_truth()?;
            let data_dir = adapter.setup(&config).await?;

            let cases: Vec<_> = gt
                .cases
                .iter()
                .filter(|c| {
                    config.cwe_filter.as_ref().is_none_or(|f| {
                        c.expected_cwes.iter().any(|cwe| f.contains(cwe))
                            || c.expected_cwes.is_empty()
                    })
                })
                .take(config.max_cases.unwrap_or(usize::MAX))
                .collect();

            let mut outcomes = Vec::new();
            let total = cases.len();

            for (i, case) in cases.iter().enumerate() {
                if i % 100 == 0 && i > 0 {
                    tracing::info!("[{}/{}] Processing {}", i, total, case.id);
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(config.timeout_secs),
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
                        tracing::warn!("Case {} timed out after {}s", case.id, config.timeout_secs);
                    }
                }
            }

            let score = scoring::aggregate(&outcomes);

            let run = history::BenchmarkRun {
                id: run_id.clone(),
                started_at: chrono::Utc::now(),
                finished_at: Some(chrono::Utc::now()),
                suite: suite_name.clone(),
                skwaq_commit: commit.clone(),
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
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
