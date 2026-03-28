//! OpenTelemetry telemetry: span pipeline, JSONL file exporter, and query helpers.
//!
//! Tier 1 (always on): file exporter writes spans to `~/.skwaq/telemetry/spans.jsonl`.
//! Tier 3 (opt-in, feature `otlp`): OTLP gRPC export when configured.

use futures_util::future::BoxFuture;
use opentelemetry::trace::TraceError;
use opentelemetry_sdk::{
    export::trace::{ExportResult, SpanData, SpanExporter},
    trace::TracerProvider,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Resolved telemetry directory (expanded from config).
fn resolve_telemetry_dir(configured: &str) -> PathBuf {
    if configured.starts_with("~/") || configured.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&configured[2..]);
        }
    }
    PathBuf::from(configured)
}

/// Default telemetry directory path.
pub fn default_telemetry_dir() -> String {
    dirs::home_dir()
        .map(|h| h.join(".skwaq/telemetry").to_string_lossy().into_owned())
        .unwrap_or_else(|| "~/.skwaq/telemetry".to_string())
}

/// Ensure the telemetry directory exists.
fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

// ── JSONL file exporter ────────────────────────────────────────────

/// A lightweight span record written to the JSONL file.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpanRecord {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_ms: f64,
    pub status: String,
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

/// Exporter that appends span records as JSONL to a file.
#[derive(Debug)]
struct JsonlFileExporter {
    path: PathBuf,
}

impl JsonlFileExporter {
    fn new(dir: &Path) -> anyhow::Result<Self> {
        ensure_dir(dir)?;
        Ok(Self {
            path: dir.join("spans.jsonl"),
        })
    }
}

impl SpanExporter for JsonlFileExporter {
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        let path = self.path.clone();
        Box::pin(async move {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| TraceError::Other(Box::new(e)))?;

            for span in &batch {
                let parent = {
                    let id = span.parent_span_id.to_string();
                    if id == "0000000000000000" {
                        None
                    } else {
                        Some(id)
                    }
                };

                let mut attrs = serde_json::Map::new();
                for kv in span.attributes.iter() {
                    attrs.insert(
                        kv.key.to_string(),
                        serde_json::Value::String(kv.value.to_string()),
                    );
                }

                let duration = span
                    .end_time
                    .duration_since(span.start_time)
                    .unwrap_or_default();

                let record = SpanRecord {
                    trace_id: span.span_context.trace_id().to_string(),
                    span_id: span.span_context.span_id().to_string(),
                    parent_span_id: parent,
                    name: span.name.to_string(),
                    start_time: humantime::format_rfc3339(span.start_time).to_string(),
                    end_time: humantime::format_rfc3339(span.end_time).to_string(),
                    duration_ms: duration.as_secs_f64() * 1000.0,
                    status: format!("{:?}", span.status),
                    attributes: attrs,
                };

                if let Ok(json) = serde_json::to_string(&record) {
                    let _ = writeln!(file, "{json}");
                }
            }
            Ok(())
        })
    }
}

// ── Provider setup ─────────────────────────────────────────────────

/// Initialise the OpenTelemetry [`TracerProvider`] with a JSONL file exporter
/// (always on) and optionally an OTLP exporter (feature-gated).
///
/// Returns the provider so callers can register a `tracing-opentelemetry` layer.
pub fn init_tracer_provider(
    telemetry_dir: &str,
    _otlp_endpoint: Option<&str>,
) -> anyhow::Result<TracerProvider> {
    let dir = resolve_telemetry_dir(telemetry_dir);
    let file_exporter = JsonlFileExporter::new(&dir)?;

    // Use simple exporter (synchronous, low overhead for file I/O)
    let builder = TracerProvider::builder().with_simple_exporter(file_exporter);

    // Tier 3: OTLP export (feature-gated)
    #[cfg(feature = "otlp")]
    let builder = {
        if let Some(endpoint) = _otlp_endpoint {
            use opentelemetry_otlp::WithExportConfig;
            let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            builder.with_simple_exporter(otlp_exporter)
        } else {
            builder
        }
    };

    let provider = builder.build();
    Ok(provider)
}

/// Rotate the spans file if it exceeds `max_bytes` (default 50 MB).
pub fn rotate_spans_file(telemetry_dir: &str, max_bytes: u64) -> anyhow::Result<()> {
    let dir = resolve_telemetry_dir(telemetry_dir);
    let path = dir.join("spans.jsonl");
    if !path.exists() {
        return Ok(());
    }
    let meta = fs::metadata(&path)?;
    if meta.len() > max_bytes {
        let rotated = dir.join("spans.jsonl.1");
        if rotated.exists() {
            fs::remove_file(&rotated)?;
        }
        fs::rename(&path, &rotated)?;
    }
    Ok(())
}

// ── Query helpers ──────────────────────────────────────────────────

/// Read and filter span records from the JSONL file.
pub fn query_spans(
    telemetry_dir: &str,
    name_filter: Option<&str>,
    attr_filter: Option<(&str, &str)>,
    limit: usize,
) -> anyhow::Result<Vec<SpanRecord>> {
    query_spans_impl(telemetry_dir, name_filter, attr_filter, limit, false, None)
}

/// Like `query_spans` but returns the *most recent* `limit` matching spans
/// instead of the first `limit`. This is important for dashboards that need
/// current data from long-running eval jobs where the spans.jsonl file grows
/// well beyond the limit.
pub fn query_spans_recent(
    telemetry_dir: &str,
    name_filter: Option<&str>,
    attr_filter: Option<(&str, &str)>,
    limit: usize,
) -> anyhow::Result<Vec<SpanRecord>> {
    query_spans_impl(telemetry_dir, name_filter, attr_filter, limit, true, None)
}

/// Like `query_spans_recent`, but only returns spans with `start_time >= since`.
/// `since` must be an RFC3339 timestamp string (lexicographic comparison).
pub fn query_spans_since(
    telemetry_dir: &str,
    name_filter: Option<&str>,
    attr_filter: Option<(&str, &str)>,
    limit: usize,
    since: &str,
) -> anyhow::Result<Vec<SpanRecord>> {
    query_spans_impl(
        telemetry_dir,
        name_filter,
        attr_filter,
        limit,
        true,
        Some(since),
    )
}

fn query_spans_impl(
    telemetry_dir: &str,
    name_filter: Option<&str>,
    attr_filter: Option<(&str, &str)>,
    limit: usize,
    recent: bool,
    since: Option<&str>,
) -> anyhow::Result<Vec<SpanRecord>> {
    let dir = resolve_telemetry_dir(telemetry_dir);
    let path = dir.join("spans.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = std::fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let mut results = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: SpanRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(name) = name_filter {
            if !record.name.contains(name) {
                continue;
            }
        }

        if let Some((key, value)) = attr_filter {
            match record.attributes.get(key) {
                Some(v) if v.as_str() == Some(value) => {}
                _ => continue,
            }
        }

        // Time-bound filter: skip spans older than `since` (RFC3339 lexicographic comparison)
        if let Some(since_ts) = since {
            if record.start_time.as_str() < since_ts {
                continue;
            }
        }

        results.push(record);

        if !recent && results.len() >= limit {
            break;
        }
    }

    // For recent mode, keep only the last `limit` entries
    if recent && results.len() > limit {
        results = results.split_off(results.len() - limit);
    }

    Ok(results)
}

/// Print a formatted summary of telemetry spans to stdout.
pub fn print_span_summary(spans: &[SpanRecord]) {
    if spans.is_empty() {
        println!("No spans found.");
        return;
    }

    println!(
        "{:<30} {:>10} {:>12} KEY ATTRIBUTES",
        "SPAN", "DURATION", "STATUS"
    );
    println!("{}", "-".repeat(80));

    for span in spans {
        let key_attrs: Vec<String> = span
            .attributes
            .iter()
            .filter(|(k, _)| {
                matches!(
                    k.as_str(),
                    "suite" | "case_id" | "agent_name" | "verdict" | "tokens_in" | "tokens_out"
                )
            })
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        println!(
            "{:<30} {:>8.1}ms {:>12} {}",
            truncate(&span.name, 30),
            span.duration_ms,
            &span.status,
            key_attrs.join(", ")
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

// ── Active run tracking ───────────────────────────────────────────

/// An active gym run (written to `active_runs.jsonl` on start, removed on finish).
#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveRun {
    pub suite: String,
    pub total_cases: u64,
    pub concurrency: u64,
    pub started_at: String,
    pub pid: u32,
}

/// Register an active run. Returns a guard that removes it on drop.
pub fn register_active_run(
    telemetry_dir: &str,
    suite: &str,
    total_cases: usize,
    concurrency: usize,
) -> ActiveRunGuard {
    let dir = resolve_telemetry_dir(telemetry_dir);
    let _ = ensure_dir(&dir);
    let run = ActiveRun {
        suite: suite.to_string(),
        total_cases: total_cases as u64,
        concurrency: concurrency as u64,
        started_at: chrono::Utc::now().to_rfc3339(),
        pid: std::process::id(),
    };
    let path = dir.join("active_runs.jsonl");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", serde_json::to_string(&run).unwrap_or_default());
    }
    ActiveRunGuard {
        dir,
        suite: suite.to_string(),
        pid: std::process::id(),
    }
}

/// Guard that removes the active run entry when dropped (suite finishes).
pub struct ActiveRunGuard {
    dir: PathBuf,
    suite: String,
    pid: u32,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        let path = self.dir.join("active_runs.jsonl");
        if !path.exists() {
            return;
        }
        // Rewrite the file without this run
        let Ok(content) = fs::read_to_string(&path) else {
            return;
        };
        let remaining: Vec<&str> = content
            .lines()
            .filter(|line| {
                let Ok(run) = serde_json::from_str::<ActiveRun>(line) else {
                    return false;
                };
                !(run.suite == self.suite && run.pid == self.pid)
            })
            .collect();
        let _ = fs::write(
            &path,
            remaining.join("\n") + if remaining.is_empty() { "" } else { "\n" },
        );
    }
}

/// Read currently active runs from the sidecar file.
pub fn read_active_runs(telemetry_dir: &str) -> Vec<ActiveRun> {
    let dir = resolve_telemetry_dir(telemetry_dir);
    let path = dir.join("active_runs.jsonl");
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<ActiveRun>(line).ok())
        .filter(|run| {
            // Only include runs whose process is still alive
            Path::new(&format!("/proc/{}", run.pid)).exists()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_telemetry_dir_tilde() {
        let dir = resolve_telemetry_dir("~/.skwaq/telemetry");
        assert!(dir.to_string_lossy().contains(".skwaq/telemetry"));
        assert!(!dir.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn test_resolve_telemetry_dir_absolute() {
        let dir = resolve_telemetry_dir("/tmp/telemetry");
        assert_eq!(dir, PathBuf::from("/tmp/telemetry"));
    }

    #[test]
    fn test_query_spans_empty() {
        let dir = tempfile::tempdir().unwrap();
        let results = query_spans(dir.path().to_str().unwrap(), None, None, 100).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_query_spans_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spans.jsonl");
        let record = SpanRecord {
            trace_id: "abc".into(),
            span_id: "def".into(),
            parent_span_id: None,
            name: "gym.case".into(),
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-01-01T00:00:01Z".into(),
            duration_ms: 1000.0,
            status: "Ok".into(),
            attributes: serde_json::Map::new(),
        };
        std::fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();

        let results = query_spans(dir.path().to_str().unwrap(), Some("gym"), None, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "gym.case");
    }

    #[test]
    fn test_query_spans_with_attr_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spans.jsonl");
        let mut attrs = serde_json::Map::new();
        attrs.insert("suite".into(), serde_json::Value::String("fixtures".into()));
        let record = SpanRecord {
            trace_id: "abc".into(),
            span_id: "def".into(),
            parent_span_id: None,
            name: "gym.case".into(),
            start_time: "2026-01-01T00:00:00Z".into(),
            end_time: "2026-01-01T00:00:01Z".into(),
            duration_ms: 1000.0,
            status: "Ok".into(),
            attributes: attrs,
        };
        std::fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();

        let results = query_spans(
            dir.path().to_str().unwrap(),
            None,
            Some(("suite", "fixtures")),
            100,
        )
        .unwrap();
        assert_eq!(results.len(), 1);

        let results = query_spans(
            dir.path().to_str().unwrap(),
            None,
            Some(("suite", "juliet")),
            100,
        )
        .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_rotate_spans_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spans.jsonl");
        std::fs::write(&path, "x".repeat(200)).unwrap();

        rotate_spans_file(dir.path().to_str().unwrap(), 100).unwrap();

        assert!(!path.exists());
        assert!(dir.path().join("spans.jsonl.1").exists());
    }
}
