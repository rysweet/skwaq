//! Ratatui-based TUI dashboard for viewing gym run status, agent stats,
//! and benchmark history in the terminal.
//!
//! Launch with `skwaq gym dashboard --live` for real-time monitoring
//! or `skwaq gym dashboard` for a static snapshot of the last run.

use crate::history::HistoryDb;
use crate::telemetry::{query_spans_since, read_active_runs};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::io::stdout;
use std::time::{Duration, Instant};

/// Run the live TUI dashboard.
pub fn run_live(history_db: &HistoryDb, telemetry_dir: &str) -> anyhow::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_secs(2);
    let mut last_tick = Instant::now();

    loop {
        let elapsed_since_tick = last_tick.elapsed();
        let secs_until_refresh = tick_rate.saturating_sub(elapsed_since_tick).as_secs();
        let state = DashboardState::load(history_db, telemetry_dir)?;
        terminal.draw(|f| render(f, &state, Some(secs_until_refresh)))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

/// Run the static (non-interactive) dashboard — prints to stdout and exits.
pub fn run_static(history_db: &HistoryDb, telemetry_dir: &str) -> anyhow::Result<()> {
    let state = DashboardState::load(history_db, telemetry_dir)?;
    print_static(&state);
    Ok(())
}

// ── Dashboard state ────────────────────────────────────────────────

struct SuiteStats {
    name: String,
    model: String,
    f1_history: Vec<f64>,
    latest_f1: f64,
    latest_precision: f64,
    latest_recall: f64,
    cases: u32,
    tp: u32,
    fp: u32,
    r#fn: u32,
    cost_usd: f64,
}

struct AgentStats {
    name: String,
    call_count: u64,
    avg_tokens: f64,
    avg_duration_ms: f64,
}

struct ActiveJob {
    suite: String,
    completed: u64,
    total: u64,
    concurrency: u64,
    avg_case_ms: f64,
    eta_secs: Option<u64>,
}

struct ApiHealth {
    total_requests: u64,
    rate_limit_retries: u64,
    errors: u64,
    model: String,
    total_cost_usd: f64,
}

struct DashboardState {
    suites: Vec<SuiteStats>,
    agents: Vec<AgentStats>,
    active_jobs: Vec<ActiveJob>,
    api_health: ApiHealth,
    recent_span_count: usize,
}

impl DashboardState {
    fn load(db: &HistoryDb, telemetry_dir: &str) -> anyhow::Result<Self> {
        let mut suites = Vec::new();
        for suite_name in &[
            "fixtures",
            "juliet",
            "owasp",
            "cyberseceval",
            "cgc",
            "cybergym",
        ] {
            let runs = db.recent_finished_runs_for_suite(suite_name, 20)?;
            if runs.is_empty() {
                continue;
            }
            let latest = &runs[0];
            let model = if !latest.metadata.llm_model.is_empty() {
                latest.metadata.llm_model.clone()
            } else if !latest.metadata.llm_backend.is_empty() {
                latest.metadata.llm_backend.clone()
            } else {
                "unknown".to_string()
            };
            let f1_history: Vec<f64> = runs.iter().rev().map(|r| r.f1 * 100.0).collect();
            suites.push(SuiteStats {
                name: suite_name.to_string(),
                model,
                f1_history,
                latest_f1: latest.f1 * 100.0,
                latest_precision: latest.precision * 100.0,
                latest_recall: latest.recall * 100.0,
                cases: latest.true_positives
                    + latest.false_positives
                    + latest.false_negatives
                    + latest.true_negatives,
                tp: latest.true_positives,
                fp: latest.false_positives,
                r#fn: latest.false_negatives,
                cost_usd: latest.metadata.estimated_cost_usd,
            });
        }

        // Active jobs from sidecar file (written at run start, removed on finish)
        let active_runs = read_active_runs(telemetry_dir);

        // Compute time bound: earliest active run start, or fall back to 24h ago
        let fallback_since = {
            let day_ago = chrono::Utc::now() - chrono::Duration::hours(24);
            day_ago.to_rfc3339()
        };
        let since = active_runs
            .iter()
            .map(|r| r.started_at.as_str())
            .min()
            .unwrap_or(fallback_since.as_str());

        // Agent stats from recent telemetry spans (time-bounded)
        let agent_spans = query_spans_since(telemetry_dir, Some("gym.agent"), None, 100000, since)
            .unwrap_or_default();
        let mut agent_map: std::collections::HashMap<String, (u64, f64, f64)> =
            std::collections::HashMap::new();
        for span in &agent_spans {
            let name = span
                .attributes
                .get("agent_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let tokens: f64 = span
                .attributes
                .get("tokens_out")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            let entry = agent_map.entry(name).or_insert((0, 0.0, 0.0));
            entry.0 += 1;
            entry.1 += tokens;
            entry.2 += span.duration_ms;
        }
        let mut agents: Vec<AgentStats> = agent_map
            .into_iter()
            .map(|(name, (count, total_tokens, total_ms))| AgentStats {
                name,
                call_count: count,
                avg_tokens: if count > 0 {
                    total_tokens / count as f64
                } else {
                    0.0
                },
                avg_duration_ms: if count > 0 {
                    total_ms / count as f64
                } else {
                    0.0
                },
            })
            .collect();
        agents.sort_by_key(|b| std::cmp::Reverse(b.call_count));

        let case_spans = query_spans_since(telemetry_dir, Some("gym.case"), None, 500000, since)
            .unwrap_or_default();

        // Count completed cases per suite and compute avg duration
        let mut case_counts: std::collections::HashMap<String, (u64, f64)> =
            std::collections::HashMap::new();
        for span in &case_spans {
            let suite = span
                .attributes
                .get("suite")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !suite.is_empty() {
                let entry = case_counts.entry(suite).or_insert((0, 0.0));
                entry.0 += 1;
                entry.1 += span.duration_ms;
            }
        }

        let mut active_jobs = Vec::new();
        for run in &active_runs {
            let (completed, total_case_ms) =
                case_counts.get(&run.suite).copied().unwrap_or((0, 0.0));

            let avg_case_ms = if completed > 0 {
                total_case_ms / completed as f64
            } else {
                0.0
            };
            let remaining = run.total_cases.saturating_sub(completed);
            let eta_secs = if completed > 0 && remaining > 0 {
                let effective_concurrency = run.concurrency.max(1) as f64;
                Some(((remaining as f64 * avg_case_ms) / (effective_concurrency * 1000.0)) as u64)
            } else {
                None
            };

            active_jobs.push(ActiveJob {
                suite: run.suite.clone(),
                completed,
                total: run.total_cases,
                concurrency: run.concurrency,
                avg_case_ms,
                eta_secs,
            });
        }

        // API health from LLM request spans (time-bounded)
        let llm_spans = query_spans_since(telemetry_dir, Some("llm.request"), None, 100000, since)
            .unwrap_or_default();
        let total_requests = llm_spans.len() as u64;
        let rate_limit_retries = llm_spans
            .iter()
            .filter(|s| s.attributes.get("retry").is_some())
            .count() as u64;
        let errors = llm_spans
            .iter()
            .filter(|s| s.status.contains("Error"))
            .count() as u64;
        // Extract model from most recent LLM span
        let model = llm_spans
            .last()
            .and_then(|s| s.attributes.get("model"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let total_cost_usd: f64 = suites.iter().map(|s| s.cost_usd).sum();

        Ok(DashboardState {
            suites,
            agents,
            active_jobs,
            api_health: ApiHealth {
                total_requests,
                rate_limit_retries,
                errors,
                model,
                total_cost_usd,
            },
            recent_span_count: agent_spans.len() + llm_spans.len(),
        })
    }
}

// ── TUI rendering ──────────────────────────────────────────────────

fn render(f: &mut Frame, state: &DashboardState, refresh_countdown: Option<u64>) {
    let has_active_jobs = !state.active_jobs.is_empty();

    let constraints = if has_active_jobs {
        vec![
            Constraint::Length(3),                                      // Title
            Constraint::Length(2 + state.active_jobs.len() as u16 + 1), // Active jobs
            Constraint::Min(8),                                         // Main content
            Constraint::Length(4),                                      // API Health
        ]
    } else {
        vec![
            Constraint::Length(3), // Title
            Constraint::Min(10),   // Main content
            Constraint::Length(4), // API Health
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    // Title bar
    let refresh_text = match refresh_countdown {
        Some(s) => format!("  refresh {s}s  [q] quit"),
        None => "  [q] quit".to_string(),
    };
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " SKWAQ GYM DASHBOARD ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  {} spans  │  model: {}  │  cost: {}{}",
            state.recent_span_count,
            state.api_health.model,
            crate::cost::format_cost(state.api_health.total_cost_usd),
            refresh_text
        )),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    if has_active_jobs {
        render_active_jobs(f, chunks[1], state);
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(chunks[2]);
        render_suites(f, main_chunks[0], state);
        render_agents(f, main_chunks[1], state);
        render_api_health(f, chunks[3], state);
    } else {
        let main_idx = 1;
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(chunks[main_idx]);
        render_suites(f, main_chunks[0], state);
        render_agents(f, main_chunks[1], state);
        render_api_health(f, chunks[2], state);
    }
}

fn render_active_jobs(f: &mut Frame, area: Rect, state: &DashboardState) {
    let header = Row::new(vec!["Suite", "Progress", "Concurrency", "Avg/case", "ETA"]).style(
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = state
        .active_jobs
        .iter()
        .map(|j| {
            let pct = if j.total > 0 {
                j.completed as f64 / j.total as f64 * 100.0
            } else {
                0.0
            };
            let progress_bar = format!("{}/{} ({:.0}%)", j.completed, j.total, pct);
            let avg_case = if j.avg_case_ms > 0.0 {
                format_duration_ms(j.avg_case_ms)
            } else {
                "—".to_string()
            };
            let eta = match j.eta_secs {
                Some(s) => format_duration_secs(s),
                None => "calculating…".to_string(),
            };
            let eta_color = match j.eta_secs {
                Some(s) if s < 300 => Color::Green,
                Some(s) if s < 3600 => Color::Yellow,
                _ => Color::White,
            };
            Row::new(vec![
                Cell::from(j.suite.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(progress_bar),
                Cell::from(format!("j{}", j.concurrency)),
                Cell::from(avg_case),
                Cell::from(eta).style(Style::default().fg(eta_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Length(13),
            Constraint::Length(12),
            Constraint::Length(14),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" ▶ Active Jobs ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    f.render_widget(table, area);
}

fn render_suites(f: &mut Frame, area: Rect, state: &DashboardState) {
    let header = Row::new(vec![
        "Suite", "Model", "Cases", "F1%", "Prec%", "Rec%", "TP", "FP", "FN", "Cost", "Trend",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = state
        .suites
        .iter()
        .map(|s| {
            let f1_color = if s.latest_f1 >= 90.0 {
                Color::Green
            } else if s.latest_f1 >= 80.0 {
                Color::Yellow
            } else {
                Color::Red
            };
            let trend = sparkline_ascii(&s.f1_history, 8);
            // Shorten model name for display
            let model_short = shorten_model(&s.model);
            let cost_str = crate::cost::format_cost(s.cost_usd);
            Row::new(vec![
                Cell::from(s.name.clone()),
                Cell::from(model_short).style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{}", s.cases)),
                Cell::from(format!("{:.1}", s.latest_f1)).style(Style::default().fg(f1_color)),
                Cell::from(format!("{:.1}", s.latest_precision)),
                Cell::from(format!("{:.1}", s.latest_recall)),
                Cell::from(format!("{}", s.tp)),
                Cell::from(format!("{}", s.fp)),
                Cell::from(format!("{}", s.r#fn)),
                Cell::from(cost_str).style(Style::default().fg(Color::Yellow)),
                Cell::from(trend),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Benchmark Results ")
            .borders(Borders::ALL),
    );
    f.render_widget(table, area);
}

fn render_agents(f: &mut Frame, area: Rect, state: &DashboardState) {
    let header = Row::new(vec!["Agent", "Calls", "Avg Tok", "Avg ms"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = state
        .agents
        .iter()
        .map(|a| {
            Row::new(vec![
                Cell::from(a.name.clone()),
                Cell::from(format!("{}", a.call_count)),
                Cell::from(format!("{:.0}", a.avg_tokens)),
                Cell::from(format!("{:.0}", a.avg_duration_ms)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Agent Stats ")
            .borders(Borders::ALL),
    );
    f.render_widget(table, area);
}

fn render_api_health(f: &mut Frame, area: Rect, state: &DashboardState) {
    let h = &state.api_health;
    let text = Line::from(vec![
        Span::styled(" API: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("{} requests", h.total_requests)),
        Span::raw("  │  "),
        Span::styled(
            format!("{} rate-limit retries", h.rate_limit_retries),
            Style::default().fg(if h.rate_limit_retries > 0 {
                Color::Yellow
            } else {
                Color::Green
            }),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("{} errors", h.errors),
            Style::default().fg(if h.errors > 0 {
                Color::Red
            } else {
                Color::Green
            }),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("cost: {}", crate::cost::format_cost(h.total_cost_usd)),
            Style::default().fg(Color::Yellow),
        ),
    ]);
    let widget =
        Paragraph::new(text).block(Block::default().title(" API Health ").borders(Borders::ALL));
    f.render_widget(widget, area);
}

/// Generate ASCII sparkline from values (▁▂▃▄▅▆▇█).
fn sparkline_ascii(values: &[f64], width: usize) -> String {
    if values.is_empty() {
        return String::new();
    }
    let blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (max - min).max(1.0);

    values
        .iter()
        .rev()
        .take(width)
        .rev()
        .map(|v| {
            let idx = ((v - min) / range * 7.0).round() as usize;
            blocks[idx.min(7)]
        })
        .collect()
}

fn format_duration_ms(ms: f64) -> String {
    let secs = ms / 1000.0;
    if secs < 60.0 {
        format!("{:.0}s", secs)
    } else {
        format!("{}m{:02}s", secs as u64 / 60, secs as u64 % 60)
    }
}

fn format_duration_secs(s: u64) -> String {
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

fn shorten_model(model: &str) -> String {
    match model {
        m if m.contains("opus") => "opus".to_string(),
        m if m.contains("sonnet") => "sonnet".to_string(),
        m if m.contains("gpt-5.4") || m.contains("gpt-54") => "gpt-5.4".to_string(),
        m if m.contains("gpt-5.1") || m.contains("gpt-51") => "gpt-5.1".to_string(),
        "azure" => "azure".to_string(),
        "copilot" => "copilot".to_string(),
        other => {
            if other.len() > 10 {
                format!("{}…", &other[..9])
            } else {
                other.to_string()
            }
        }
    }
}

// ── Static (non-TUI) output ────────────────────────────────────────

fn print_static(state: &DashboardState) {
    println!("\n  ╔══════════════════════════════════════════════════╗");
    println!("  ║         SKWAQ GYM DASHBOARD                     ║");
    println!("  ╚══════════════════════════════════════════════════╝\n");

    if state.suites.is_empty() {
        println!("  No benchmark runs found. Run `skwaq gym run <suite>` first.\n");
        return;
    }

    // Active jobs
    if !state.active_jobs.is_empty() {
        println!(
            "  {:<14} {:>18} {:>13} {:>12} {:>14}",
            "ACTIVE JOBS", "PROGRESS", "CONCURRENCY", "AVG/CASE", "ETA"
        );
        println!("  {}", "─".repeat(75));
        for j in &state.active_jobs {
            let pct = if j.total > 0 {
                j.completed as f64 / j.total as f64 * 100.0
            } else {
                0.0
            };
            let avg = if j.avg_case_ms > 0.0 {
                format_duration_ms(j.avg_case_ms)
            } else {
                "—".to_string()
            };
            let eta = match j.eta_secs {
                Some(s) => format_duration_secs(s),
                None => "calculating…".to_string(),
            };
            println!(
                "  {:<14} {:>3}/{:<3} ({:>4.0}%) {:>13} {:>12} {:>14}",
                j.suite,
                j.completed,
                j.total,
                pct,
                format!("j{}", j.concurrency),
                avg,
                eta
            );
        }
        println!();
    }

    println!(
        "  {:<12} {:<10} {:>6} {:>7} {:>7} {:>7} {:>5} {:>5} {:>5} {:>8}  TREND",
        "SUITE", "MODEL", "CASES", "F1%", "PREC%", "REC%", "TP", "FP", "FN", "COST"
    );
    println!("  {}", "─".repeat(95));

    for s in &state.suites {
        let trend = sparkline_ascii(&s.f1_history, 8);
        println!(
            "  {:<12} {:<10} {:>6} {:>6.1} {:>6.1} {:>6.1} {:>5} {:>5} {:>5} {:>8}  {}",
            s.name,
            shorten_model(&s.model),
            s.cases,
            s.latest_f1,
            s.latest_precision,
            s.latest_recall,
            s.tp,
            s.fp,
            s.r#fn,
            crate::cost::format_cost(s.cost_usd),
            trend
        );
    }

    if !state.agents.is_empty() {
        println!(
            "\n  {:<18} {:>7} {:>9} {:>9}",
            "AGENT", "CALLS", "AVG TOK", "AVG MS"
        );
        println!("  {}", "─".repeat(50));
        for a in &state.agents {
            println!(
                "  {:<18} {:>7} {:>9.0} {:>9.0}",
                a.name, a.call_count, a.avg_tokens, a.avg_duration_ms
            );
        }
    }

    let h = &state.api_health;
    println!(
        "\n  Model: {}  │  API: {} requests | {} rate-limit retries | {} errors | cost: {}\n",
        h.model,
        h.total_requests,
        h.rate_limit_retries,
        h.errors,
        crate::cost::format_cost(h.total_cost_usd)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparkline_ascii() {
        let s = sparkline_ascii(&[50.0, 60.0, 70.0, 80.0, 90.0], 5);
        assert_eq!(s.chars().count(), 5);
        assert!(s.contains('█'));
        assert!(s.contains('▁'));
    }

    #[test]
    fn test_sparkline_ascii_empty() {
        assert_eq!(sparkline_ascii(&[], 5), "");
    }

    #[test]
    fn test_sparkline_ascii_single() {
        let s = sparkline_ascii(&[90.0], 5);
        assert_eq!(s.chars().count(), 1);
    }

    #[test]
    fn test_format_duration_ms() {
        assert_eq!(format_duration_ms(5000.0), "5s");
        assert_eq!(format_duration_ms(90000.0), "1m30s");
        assert_eq!(format_duration_ms(500.0), "0s");
        assert_eq!(format_duration_ms(1500.0), "2s");
    }

    #[test]
    fn test_format_duration_secs() {
        assert_eq!(format_duration_secs(45), "45s");
        assert_eq!(format_duration_secs(90), "1m30s");
        assert_eq!(format_duration_secs(3661), "1h01m");
    }
}
