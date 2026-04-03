# Issue #456: Azure Retry Metrics — Codebase Analysis

**Date**: 2026-04-03
**Status**: Analysis complete, ready for design phase

## Problem Statement

Azure API retries (429 rate limit, 401 auth) happen inside RustyClawd's `with_retry()` but are invisible to monitoring. Need to surface retry count, wait time, and reason in OTEL spans and Prometheus counters.

## Relevant Existing Code

### RustyClawd (External Dependency, rev `43ebaa1`)

| File | Key Code | Notes |
|------|----------|-------|
| `crates/core/src/client/mod.rs:194-224` | `Client::with_retry()` — private method with `retries` counter, exponential backoff, `tracing::warn!` per retry | Returns only `ClientResult<T>`, discards retry metadata |
| `crates/core/src/client/retry.rs` | `RetryConfig { max_retries: 3, initial_delay: 1s, max_delay: 30s }` | Configurable but not exposed to callers |
| `crates/core/src/client/error.rs` | `is_retryable()` — matches `RateLimited`(429), `ServiceUnavailable`(503), `ServerError`(5xx), `Timeout`, `NetworkError`, `DnsError`, `ConnectionError` | **`Unauthorized`(401) is NOT retried** |
| `crates/core/src/client/tool_loop.rs:71-158` | `execute_with_tools()` calls `create_message()` in a loop per tool-use turn; each call retries independently via `with_retry()` | Retries accumulate across turns but are invisible |

### Skwaq LLM Layer

| File | Key Code | Notes |
|------|----------|-------|
| `crates/core/src/llm/traits.rs:90-96` | `llm.request` span with `model`, `tools_count`, `input_tokens`, `output_tokens` | Target for adding `retries` and `retry_wait_ms` fields |
| `crates/core/src/llm/traits.rs:112-122` | Calls `client.execute_with_tools()` — opaque to retry info | Must propagate metadata through here |
| `crates/core/src/agents/runner.rs:131-144` | Agent runner calls `execute_with_tools` with `gym.agent` span | Consumers of the wrapper |
| `crates/gym/src/agentic.rs:1716-1726` | `execute_synthesis_completion()` calls `execute_with_tools` | Another consumer |

### Gym Metrics & Telemetry

| File | Key Code | Notes |
|------|----------|-------|
| `crates/gym/src/metrics.rs:36-40` | `RETRIES_TOTAL` counter `["suite"]` — **case-level** retries only | Different from per-request API retries |
| `crates/gym/src/telemetry.rs` | OTEL TracerProvider with JSONL exporter + optional OTLP | Spans auto-exported |
| `crates/gym/src/tui.rs:263-265` | TUI reads `retry` span attribute | Will pick up new fields automatically |

## Files Requiring Modification

| # | File | Change | Complexity |
|---|------|--------|------------|
| 1 | RustyClawd `crates/core/src/client/mod.rs` | `with_retry()` returns `(T, RetryStats)` where `RetryStats { count: u32, total_wait_ms: u64 }` | HIGH (separate repo) |
| 2 | RustyClawd `crates/core/src/client/tool_loop.rs` | Accumulate `RetryStats` across tool-loop turns in `execute_with_tools()` | MEDIUM |
| 3 | `crates/core/src/llm/traits.rs` | Add `retries` (u32) and `retry_wait_ms` (u64) Empty fields to `llm.request` span; record after response | LOW |
| 4 | `crates/gym/src/metrics.rs` | Add `AZURE_RETRIES_TOTAL` CounterVec with `["reason"]` labels | LOW |
| 5 | `crates/gym/src/agentic.rs` | Record retry metrics after `run_llm_pipeline` | LOW-MEDIUM |

## Key Design Considerations

### 1. Cross-Repo Dependency
RustyClawd must be modified first, then its rev pin updated in skwaq's workspace `Cargo.toml` (line 15).

### 2. Aggregation Across Tool-Loop Turns
A single `execute_with_tools` call makes 1-N `create_message` calls (one per tool-use turn). Each can independently retry. Total retries = sum across all turns.

### 3. 401 Auth Retries Don't Exist Yet
`Unauthorized` is not in `is_retryable()`. If the goal includes tracking auth retries, RustyClawd's retry policy must also change. This should be clarified.

### 4. Retry Reason Classification
`ClientError` variants map to Prometheus label values:
- `RateLimited` → `"rate_limit"`
- `Timeout` → `"timeout"`
- `ServerError` → `"server_error"`
- `ServiceUnavailable` → `"service_unavailable"`
- `NetworkError`/`DnsError`/`ConnectionError` → `"network"`

### 5. Recommended Approach
Modify `with_retry()` to return `(T, RetryStats)`. Propagate through `create_message()` → `execute_with_tools()` → skwaq's `execute_with_tools` wrapper. Clean, traceable, minimal API surface change.

Alternative: Emit structured tracing spans inside `with_retry()` and capture via subscriber. Less invasive to RustyClawd API but harder to get exact counts into parent span fields.

## Consumers of Modified APIs

These files call `execute_with_tools` and will need updating if the return type changes:
- `crates/core/src/llm/traits.rs` (primary wrapper)
- `crates/core/src/agents/runner.rs` (agent pipeline)
- `crates/core/src/skills/mod.rs` (skill execution)
- `crates/gym/src/agentic.rs` (gym synthesis)
- `crates/gym/src/improve.rs` (self-improvement)
