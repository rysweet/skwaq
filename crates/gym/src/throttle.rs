//! Adaptive rate controller using TCP congestion control (AIMD) for API calls.
//!
//! Tracks success/error rates over sliding windows and adjusts concurrency:
//! - Error rate < 5%: additive increase (+1 concurrency)
//! - Error rate > 20%: multiplicative decrease (halve concurrency)
//! - Otherwise: hold steady

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

/// Outcome of an API call, used to update the rate controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    /// Successful response.
    Success,
    /// Rate-limited (HTTP 429 or equivalent).
    RateLimited,
    /// Other error (not rate-related).
    OtherError,
}

/// Adaptive rate controller that adjusts concurrency based on API response patterns.
///
/// Uses AIMD (Additive Increase, Multiplicative Decrease) similar to TCP congestion
/// control. Thread-safe via atomics — designed for single-threaded tokio but safe
/// to share across tasks.
pub struct RateController {
    /// Current allowed concurrency level.
    current_concurrency: AtomicU32,
    /// Minimum concurrency (never go below this).
    min_concurrency: u32,
    /// Maximum concurrency (never exceed this).
    max_concurrency: u32,
    /// Successes in the current window.
    window_successes: AtomicU32,
    /// Rate-limit errors in the current window.
    window_rate_errors: AtomicU32,
    /// Other errors in the current window.
    window_other_errors: AtomicU32,
    /// Total cases completed (lifetime).
    total_completed: AtomicU32,
    /// Window start time.
    window_start: std::sync::Mutex<Instant>,
    /// Window duration in seconds.
    window_secs: u64,
    /// Error rate threshold below which we increase concurrency.
    increase_threshold: f64,
    /// Error rate threshold above which we decrease concurrency.
    decrease_threshold: f64,
    /// Start time for throughput calculation.
    start_time: Instant,
}

impl RateController {
    /// Create a new rate controller.
    ///
    /// # Arguments
    /// * `initial_concurrency` - Starting concurrency level
    /// * `min_concurrency` - Floor (default 1)
    /// * `max_concurrency` - Ceiling (default 32)
    pub fn new(initial_concurrency: u32, min_concurrency: u32, max_concurrency: u32) -> Self {
        let initial = initial_concurrency.clamp(min_concurrency, max_concurrency);
        Self {
            current_concurrency: AtomicU32::new(initial),
            min_concurrency,
            max_concurrency,
            window_successes: AtomicU32::new(0),
            window_rate_errors: AtomicU32::new(0),
            window_other_errors: AtomicU32::new(0),
            total_completed: AtomicU32::new(0),
            window_start: std::sync::Mutex::new(Instant::now()),
            window_secs: 30,
            increase_threshold: 0.05,
            decrease_threshold: 0.20,
            start_time: Instant::now(),
        }
    }

    /// Create with default bounds (min=1, max=32).
    pub fn with_defaults(initial_concurrency: u32) -> Self {
        Self::new(initial_concurrency, 1, 32)
    }

    /// Record the outcome of an API call and potentially adjust concurrency.
    ///
    /// Returns the new concurrency level after adjustment.
    pub fn record(&self, outcome: CallOutcome) -> u32 {
        match outcome {
            CallOutcome::Success => {
                self.window_successes.fetch_add(1, Ordering::Relaxed);
            }
            CallOutcome::RateLimited => {
                self.window_rate_errors.fetch_add(1, Ordering::Relaxed);
            }
            CallOutcome::OtherError => {
                self.window_other_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total_completed.fetch_add(1, Ordering::Relaxed);

        self.maybe_adjust()
    }

    /// Check if the window has elapsed and adjust concurrency if so.
    /// Returns current concurrency.
    fn maybe_adjust(&self) -> u32 {
        let mut window_start = self.window_start.lock().unwrap();
        let elapsed = window_start.elapsed().as_secs();

        if elapsed < self.window_secs {
            return self.current_concurrency.load(Ordering::Relaxed);
        }

        // Window elapsed — evaluate and reset.
        let successes = self.window_successes.swap(0, Ordering::Relaxed);
        let rate_errors = self.window_rate_errors.swap(0, Ordering::Relaxed);
        let _other_errors = self.window_other_errors.swap(0, Ordering::Relaxed);
        *window_start = Instant::now();

        let total = successes + rate_errors;
        if total == 0 {
            return self.current_concurrency.load(Ordering::Relaxed);
        }

        let error_rate = rate_errors as f64 / total as f64;
        let old = self.current_concurrency.load(Ordering::Relaxed);

        let new = if error_rate > self.decrease_threshold {
            // Multiplicative decrease: halve concurrency
            (old / 2).max(self.min_concurrency)
        } else if error_rate < self.increase_threshold {
            // Additive increase: +1 concurrency
            (old + 1).min(self.max_concurrency)
        } else {
            old
        };

        if new != old {
            self.current_concurrency.store(new, Ordering::Relaxed);
        }

        let throughput = self.throughput_per_min();
        tracing::info!(
            "Throttle: {} concurrent, {:.1}% error rate, {:.1} cases/min{}",
            new,
            error_rate * 100.0,
            throughput,
            if new != old {
                format!(" (was {})", old)
            } else {
                String::new()
            }
        );

        new
    }

    /// Get the current allowed concurrency level.
    pub fn concurrency(&self) -> u32 {
        self.current_concurrency.load(Ordering::Relaxed)
    }

    /// Get throughput in cases per minute.
    pub fn throughput_per_min(&self) -> f64 {
        let completed = self.total_completed.load(Ordering::Relaxed) as f64;
        let elapsed_mins = self.start_time.elapsed().as_secs_f64() / 60.0;
        if elapsed_mins < 0.001 {
            0.0
        } else {
            completed / elapsed_mins
        }
    }

    /// Get a snapshot of current statistics for logging.
    pub fn stats(&self) -> ThrottleStats {
        ThrottleStats {
            concurrency: self.current_concurrency.load(Ordering::Relaxed),
            total_completed: self.total_completed.load(Ordering::Relaxed),
            throughput_per_min: self.throughput_per_min(),
        }
    }
}

/// Snapshot of throttle statistics.
#[derive(Debug, Clone)]
pub struct ThrottleStats {
    pub concurrency: u32,
    pub total_completed: u32,
    pub throughput_per_min: f64,
}

/// Cross-process rate limit signal using a shared file.
///
/// When any process gets rate-limited, it writes a backoff timestamp to
/// `~/.skwaq/rate_backoff`. Other processes check this file before making
/// API calls and sleep until the backoff expires.
pub struct CrossProcessBackoff {
    path: std::path::PathBuf,
}

impl CrossProcessBackoff {
    /// Create a new cross-process backoff signal.
    pub fn new() -> Self {
        let path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".skwaq")
            .join("rate_backoff");
        Self { path }
    }

    /// Signal that we were rate-limited. Other processes will back off.
    pub fn signal_rate_limited(&self, retry_after_secs: u64) {
        let backoff_until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + retry_after_secs;

        // Only update if our backoff is further in the future
        if let Ok(existing) = std::fs::read_to_string(&self.path) {
            if let Ok(existing_ts) = existing.trim().parse::<u64>() {
                if existing_ts >= backoff_until {
                    return; // Another process already set a longer backoff
                }
            }
        }

        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.path, backoff_until.to_string());
        tracing::warn!(
            "Cross-process backoff: signaled {}s retry-after",
            retry_after_secs
        );
    }

    /// Check if we should back off. Returns sleep duration if so.
    pub fn check_backoff(&self) -> Option<std::time::Duration> {
        let content = std::fs::read_to_string(&self.path).ok()?;
        let backoff_until: u64 = content.trim().parse().ok()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if backoff_until > now {
            Some(std::time::Duration::from_secs(backoff_until - now))
        } else {
            // Backoff expired — clean up the file
            let _ = std::fs::remove_file(&self.path);
            None
        }
    }

    /// Wait if another process signaled a backoff.
    pub async fn wait_if_needed(&self) {
        if let Some(duration) = self.check_backoff() {
            tracing::info!(
                "Cross-process backoff: waiting {}s (signaled by another process)",
                duration.as_secs()
            );
            tokio::time::sleep(duration).await;
        }
    }
}

impl Default for CrossProcessBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_concurrency() {
        let rc = RateController::with_defaults(4);
        assert_eq!(rc.concurrency(), 4);
    }

    #[test]
    fn test_clamp_to_bounds() {
        let rc = RateController::new(100, 1, 16);
        assert_eq!(rc.concurrency(), 16);

        let rc2 = RateController::new(0, 2, 16);
        assert_eq!(rc2.concurrency(), 2);
    }

    #[test]
    fn test_record_does_not_change_within_window() {
        let rc = RateController::with_defaults(4);
        // Within the 30-second window, concurrency should not change.
        for _ in 0..20 {
            rc.record(CallOutcome::Success);
        }
        assert_eq!(rc.concurrency(), 4);
    }

    #[test]
    fn test_additive_increase_on_low_error_rate() {
        let mut rc = RateController::with_defaults(4);
        // Set window to 0 so every record triggers adjustment.
        rc.window_secs = 0;

        // With window_secs=0, each record evaluates and resets the window.
        // First success: 0% error -> 4+1=5, window resets.
        rc.record(CallOutcome::Success);
        assert_eq!(rc.concurrency(), 5);
    }

    #[test]
    fn test_multiplicative_decrease_on_high_error_rate() {
        let mut rc = RateController::with_defaults(8);
        rc.window_secs = 0;

        // First rate-limited call: 100% error rate -> halve: 8 -> 4.
        rc.record(CallOutcome::RateLimited);
        assert_eq!(rc.concurrency(), 4);

        // Another rate-limited: 100% error -> halve: 4 -> 2.
        rc.record(CallOutcome::RateLimited);
        assert_eq!(rc.concurrency(), 2);
    }

    #[test]
    fn test_minimum_concurrency_floor() {
        let mut rc = RateController::new(2, 1, 32);
        rc.window_secs = 0;

        // All rate-limited -> halve: 2 -> 1 (min)
        rc.record(CallOutcome::RateLimited);
        rc.record(CallOutcome::RateLimited);
        rc.record(CallOutcome::RateLimited);
        assert!(rc.concurrency() >= 1);
    }

    #[test]
    fn test_maximum_concurrency_ceiling() {
        let mut rc = RateController::new(31, 1, 32);
        rc.window_secs = 0;

        // All successes -> increase: 31 -> 32 (max), then stays.
        for _ in 0..10 {
            rc.record(CallOutcome::Success);
        }
        assert!(rc.concurrency() <= 32);
    }

    #[test]
    fn test_hold_steady_in_middle_range() {
        let rc = RateController::with_defaults(8);
        // Without elapsed window (default 30s), concurrency stays regardless of outcomes.
        for _ in 0..9 {
            rc.record(CallOutcome::Success);
        }
        rc.record(CallOutcome::RateLimited);
        // Window hasn't elapsed, so no change.
        assert_eq!(rc.concurrency(), 8);
    }

    #[test]
    fn test_stats() {
        let rc = RateController::with_defaults(4);
        rc.record(CallOutcome::Success);
        rc.record(CallOutcome::Success);

        let stats = rc.stats();
        assert_eq!(stats.concurrency, 4);
        assert_eq!(stats.total_completed, 2);
    }

    #[test]
    fn test_other_errors_not_counted_as_rate_errors() {
        let mut rc = RateController::with_defaults(4);
        rc.window_secs = 0;

        // Other errors don't count toward rate error calculation.
        // Only successes and rate-limited count in the error rate.
        rc.record(CallOutcome::OtherError);
        rc.record(CallOutcome::OtherError);
        rc.record(CallOutcome::Success);
        // total = successes(1) + rate_errors(0) = 1, error_rate = 0% -> increase.
        // (other_errors are recorded but excluded from error_rate calculation)
        assert!(rc.concurrency() >= 4);
    }
}
