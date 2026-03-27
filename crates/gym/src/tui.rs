//! Ratatui-based TUI dashboard for viewing gym run status, agent stats,
//! and benchmark history in the terminal.
//!
//! Launch with `skwaq gym dashboard --live` for real-time monitoring
//! or `skwaq gym dashboard` for a static snapshot of the last run.

use crate::history::HistoryDb;
use crate::telemetry::query_spans;
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
        let state = DashboardState::load(history_db, telemetry_dir)?;
        terminal.draw(|f| render(f, &state))?;

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
    f1_history: Vec<f64>,
    latest_f1: f64,
    latest_precision: f64,
    latest_recall: f64,
    cases: u32,
    tp: u32,
    fp: u32,
    r#fn: u32,
}

struct AgentStats {
    name: String,
    call_count: u64,
    avg_tokens: f64,
    avg_duration_ms: f64,
}

struct ApiHealth {
    total_requests: u64,
    rate_limit_retries: u64,
    errors: u64,
}

struct DashboardState {
    suites: Vec<SuiteStats>,
    agents: Vec<AgentStats>,
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
            let f1_history: Vec<f64> = runs.iter().rev().map(|r| r.f1 * 100.0).collect();
            suites.push(SuiteStats {
                name: suite_name.to_string(),
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
            });
        }

        // Agent stats from recent telemetry spans
        let agent_spans =
            query_spans(telemetry_dir, Some("gym.agent"), None, 10000).unwrap_or_default();
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
        let agents: Vec<AgentStats> = agent_map
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

        // API health from LLM request spans
        let llm_spans =
            query_spans(telemetry_dir, Some("llm.request"), None, 10000).unwrap_or_default();
        let total_requests = llm_spans.len() as u64;
        let rate_limit_retries = llm_spans
            .iter()
            .filter(|s| s.attributes.get("retry").is_some())
            .count() as u64;
        let errors = llm_spans
            .iter()
            .filter(|s| s.status.contains("Error"))
            .count() as u64;

        Ok(DashboardState {
            suites,
            agents,
            api_health: ApiHealth {
                total_requests,
                rate_limit_retries,
                errors,
            },
            recent_span_count: agent_spans.len() + llm_spans.len(),
        })
    }
}

// ── TUI rendering ──────────────────────────────────────────────────

fn render(f: &mut Frame, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(10),   // Main content
            Constraint::Length(4), // API Health
        ])
        .split(f.area());

    // Title bar
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " SKWAQ GYM DASHBOARD ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  {} spans tracked  [q] quit",
            state.recent_span_count
        )),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(title, chunks[0]);

    // Main content: suites table + agent stats side-by-side
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    render_suites(f, main_chunks[0], state);
    render_agents(f, main_chunks[1], state);

    // API health bar
    render_api_health(f, chunks[2], state);
}

fn render_suites(f: &mut Frame, area: Rect, state: &DashboardState) {
    let header = Row::new(vec![
        "Suite", "Cases", "F1%", "Prec%", "Rec%", "TP", "FP", "FN", "Trend",
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
            Row::new(vec![
                Cell::from(s.name.clone()),
                Cell::from(format!("{}", s.cases)),
                Cell::from(format!("{:.1}", s.latest_f1)).style(Style::default().fg(f1_color)),
                Cell::from(format!("{:.1}", s.latest_precision)),
                Cell::from(format!("{:.1}", s.latest_recall)),
                Cell::from(format!("{}", s.tp)),
                Cell::from(format!("{}", s.fp)),
                Cell::from(format!("{}", s.r#fn)),
                Cell::from(trend),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
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

// ── Static (non-TUI) output ────────────────────────────────────────

fn print_static(state: &DashboardState) {
    println!("\n  ╔══════════════════════════════════════════════════╗");
    println!("  ║         SKWAQ GYM DASHBOARD                     ║");
    println!("  ╚══════════════════════════════════════════════════╝\n");

    if state.suites.is_empty() {
        println!("  No benchmark runs found. Run `skwaq gym run <suite>` first.\n");
        return;
    }

    println!(
        "  {:<12} {:>6} {:>7} {:>7} {:>7} {:>5} {:>5} {:>5}  TREND",
        "SUITE", "CASES", "F1%", "PREC%", "REC%", "TP", "FP", "FN"
    );
    println!("  {}", "─".repeat(75));

    for s in &state.suites {
        let trend = sparkline_ascii(&s.f1_history, 8);
        println!(
            "  {:<12} {:>6} {:>6.1} {:>6.1} {:>6.1} {:>5} {:>5} {:>5}  {}",
            s.name,
            s.cases,
            s.latest_f1,
            s.latest_precision,
            s.latest_recall,
            s.tp,
            s.fp,
            s.r#fn,
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
        "\n  API: {} requests | {} rate-limit retries | {} errors\n",
        h.total_requests, h.rate_limit_retries, h.errors
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
}
