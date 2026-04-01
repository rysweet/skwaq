//! Prometheus metrics endpoint for skwaq gym.
//!
//! When `--metrics-port` is passed to `skwaq gym eval`, this module serves
//! a `/metrics` HTTP endpoint that Prometheus can scrape.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Encoder, Gauge,
    HistogramVec, TextEncoder,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

lazy_static::lazy_static! {
    /// Cases processed, labeled by suite and status (completed / failed / timeout).
    pub static ref CASES_TOTAL: CounterVec = register_counter_vec!(
        "skwaq_gym_cases_total",
        "Cases processed",
        &["suite", "status"]
    ).unwrap();

    /// Agent invocations, labeled by agent name and suite.
    pub static ref AGENT_CALLS_TOTAL: CounterVec = register_counter_vec!(
        "skwaq_gym_agent_calls_total",
        "Agent calls",
        &["agent", "suite"]
    ).unwrap();

    /// Rate-limit retries, labeled by suite.
    pub static ref RETRIES_TOTAL: CounterVec = register_counter_vec!(
        "skwaq_gym_retries_total",
        "Rate limit retries",
        &["suite"]
    ).unwrap();

    /// Tokens consumed, labeled by agent name and direction (input / output).
    pub static ref TOKENS_TOTAL: CounterVec = register_counter_vec!(
        "skwaq_gym_tokens_total",
        "Tokens consumed",
        &["agent", "direction"]
    ).unwrap();

    /// Number of cases currently being processed.
    pub static ref CASES_IN_PROGRESS: Gauge = register_gauge!(
        "skwaq_gym_cases_in_progress",
        "Currently running cases"
    ).unwrap();

    /// Per-agent execution duration in seconds.
    pub static ref AGENT_DURATION: HistogramVec = register_histogram_vec!(
        "skwaq_gym_agent_duration_seconds",
        "Agent execution time",
        &["agent"],
        vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
    ).unwrap();

    /// Full case processing duration in seconds, labeled by suite.
    pub static ref CASE_DURATION: HistogramVec = register_histogram_vec!(
        "skwaq_gym_case_duration_seconds",
        "Full case processing time",
        &["suite"],
        vec![10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0]
    ).unwrap();
}

/// Handle a single HTTP request. Only `/metrics` returns data; everything else
/// gets a 404.
async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/metrics" {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buf = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buf) {
            tracing::error!("Failed to encode metrics: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(format!("encode error: {e}"))))
                .unwrap());
        }
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", encoder.format_type())
            .body(Full::new(Bytes::from(buf)))
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found\n")))
            .unwrap())
    }
}

/// Start the Prometheus metrics HTTP server on the given port.
///
/// This is meant to be called via `tokio::spawn(serve_metrics(port))` so it
/// runs as a background task alongside the eval pipeline.  It works on a
/// single-threaded tokio runtime because it only uses cooperative async I/O.
pub async fn serve_metrics(port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Prometheus metrics server listening on http://{}", addr);

    loop {
        let (stream, _remote) = listener.accept().await?;
        let io = TokioIo::new(stream);

        // Each connection is served inline (no tokio::spawn) so this works
        // on current_thread runtime.  HTTP/1.1 keep-alive means a single
        // Prometheus scrape is one connection with one request — very cheap.
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await
            {
                tracing::debug!("metrics connection error: {}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_register_without_panic() {
        // Accessing the lazy_static metrics forces registration.
        // If any metric name collides or is invalid, this panics.
        CASES_TOTAL.with_label_values(&["test", "completed"]).inc();
        AGENT_CALLS_TOTAL
            .with_label_values(&["attack-surface", "test"])
            .inc();
        RETRIES_TOTAL.with_label_values(&["test"]).inc();
        TOKENS_TOTAL
            .with_label_values(&["test-agent", "input"])
            .inc();
        CASES_IN_PROGRESS.set(0.0);
        AGENT_DURATION
            .with_label_values(&["attack-surface"])
            .observe(1.5);
        CASE_DURATION.with_label_values(&["test"]).observe(42.0);
    }

    #[test]
    fn metrics_encode_to_prometheus_text_format() {
        // Record something so the output is non-empty.
        CASES_TOTAL
            .with_label_values(&["encode", "completed"])
            .inc();

        let encoder = TextEncoder::new();
        let families = prometheus::gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();

        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("skwaq_gym_cases_total"),
            "expected metric name in output"
        );
        assert!(text.contains("# HELP"), "expected HELP comment in output");
        assert!(text.contains("# TYPE"), "expected TYPE comment in output");
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_format() {
        // Ensure at least one metric is recorded.
        CASES_TOTAL
            .with_label_values(&["endpoint-test", "completed"])
            .inc();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn the server loop.
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(io, service_fn(handle))
                        .await;
                });
            }
        });

        // Give the listener a moment to be ready.
        tokio::task::yield_now().await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/metrics"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let body = resp.text().await.unwrap();
        assert!(body.contains("skwaq_gym_cases_total"));
        assert!(body.contains("# TYPE"));
    }
}
